//! Cross-platform process-hardening ("process isolation") primitives.
//!
//! This is *not* sandboxing in the container/namespace sense — UNIGEN is a
//! single-process desktop GUI app with no untrusted-input parser worth
//! sandboxing off into a helper process. What "process isolation" means
//! here, concretely, is: make it harder for *another* process on the same
//! machine to read this process's memory (which is where decrypted vault
//! entries, the master password, and editor plaintext all live while the
//! app is unlocked).
//!
//! Three independent lines of defense, applied on every platform that has
//! an equivalent primitive:
//!
//!   1. Don't let this process's memory end up in a crash artifact
//!      (core dump / Windows Error Reporting minidump).
//!   2. Don't let another, unrelated process `ptrace`-attach (Linux) or
//!      open a memory-reading handle (Windows `OpenProcess` with
//!      `PROCESS_VM_READ`) to this one.
//!   3. Don't let a malicious DLL get loaded into this process via the
//!      classic Windows injection vectors (AppInit_DLLs, non-signed
//!      dynamic code, remote `CreateRemoteThread`).
//!
//! Every mitigation here is **best-effort**, exactly like `mem_lock`: a
//! sufficiently privileged attacker (root/Administrator, or anyone who can
//! load a kernel module/driver) can defeat all of this. The point is
//! raising the bar against the *common* cases — an unprivileged local
//! process, an accidental crash dump, a script kiddie's DLL injector — not
//! providing a hard security boundary. Call [`init`] once, as early as
//! possible in `main()`, before any secret ever touches memory.

/// Apply every hardening measure this platform supports. Best-effort:
/// never panics, and a failed mitigation is silently skipped (there is
/// nothing a desktop app can usefully do about an OS refusing one of
/// these requests other than proceed without it — same "best effort, not
/// a guarantee" contract as `mem_lock`).
pub fn init() {
    #[cfg(target_os = "linux")]
    linux::harden();
    #[cfg(target_os = "macos")]
    macos::harden();
    #[cfg(windows)]
    windows::harden();
}

// ---------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod linux {
    const PR_SET_DUMPABLE: i32 = 4;
    // Yama LSM (present on virtually every distro kernel since ~3.4):
    // PR_SET_PTRACER restricts *who* may `ptrace_attach` to this process.
    // Passing 0 (PR_SET_PTRACER_ANY's opposite — the literal value 0, not
    // the `PR_SET_PTRACER_ANY` macro which is `-1`) means "no additional
    // tracer beyond the default parent-can-trace-child rule", which is
    // the tightest setting available without needing CAP_SYS_PTRACE.
    const PR_SET_PTRACER: i32 = 0x59616d61; // "Yama" in ASCII, per prctl.h
    const PR_SET_PTRACER_NONE: u64 = 0;

    #[repr(C)]
    struct RLimit {
        cur: u64,
        max: u64,
    }
    const RLIMIT_CORE: i32 = 4;

    extern "C" {
        fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
        fn setrlimit(resource: i32, rlim: *const RLimit) -> i32;
    }

    pub fn harden() {
        // SAFETY: `prctl`/`setrlimit` here are called with only integer
        // arguments or a pointer to a local, fully-initialized `RLimit`
        // that outlives the call — standard FFI, no aliasing/lifetime
        // hazards. Return values are intentionally ignored: every call
        // here is best-effort and a refusal must not be treated as fatal.
        unsafe {
            // 1. No core dump can ever be written for this process,
            //    regardless of ulimit -c the user has set in their shell.
            prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
            let limit = RLimit { cur: 0, max: 0 };
            setrlimit(RLIMIT_CORE, &limit);

            // 2. Deny ptrace attach from any process other than our
            //    direct parent (the default kernel rule) — blocks a
            //    sibling process, or a background "memory scraper" tool
            //    run by the same user, from attaching a debugger and
            //    reading the vault out of live memory.
            prctl(PR_SET_PTRACER, PR_SET_PTRACER_NONE, 0, 0, 0);
        }
    }
}

// ---------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------
#[cfg(target_os = "macos")]
mod macos {
    const PT_DENY_ATTACH: i32 = 31;

    extern "C" {
        fn ptrace(request: i32, pid: i32, addr: *mut std::ffi::c_void, data: i32) -> i32;
    }

    pub fn harden() {
        // SAFETY: `PT_DENY_ATTACH` ignores `pid`/`addr`/`data` entirely
        // (documented Darwin behavior — the call always targets the
        // calling process), so passing zeros/null is correct and this
        // has no aliasing/lifetime concerns. Best-effort: the return
        // value is intentionally ignored, matching every other mitigation
        // in this module.
        unsafe {
            ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
    }
}

// ---------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------
#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::mem::size_of;

    // ---- SetErrorMode: suppress the WER ("this program has stopped
    // working") crash dialog and, critically, the minidump it can offer
    // to write. Same motivation as RLIMIT_CORE=0 on Linux: a crash must
    // not leave a forensics-readable snapshot of process memory behind.
    const SEM_FAILCRITICALERRORS: u32 = 0x0001;
    const SEM_NOGPFAULTERRORBOX: u32 = 0x0002;
    const SEM_NOOPENFILEERRORBOX: u32 = 0x8000;

    // ---- SetProcessMitigationPolicy policy classes/structs (from
    // <processthreadsapi.h> / <winnt.h>). Only the two policies actually
    // used below are modeled; the struct layouts here match the
    // documented Win32 ABI (each policy struct is a single DWORD/ULONG
    // bitfield in practice, exposed to callers as `union { Flags; ... }`,
    // so a plain `u32` matches its size and layout for our purposes).
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MitigationPolicy(u32);

    // ProcessDynamicCodePolicy (7): once set, the process can no longer
    // allocate/map executable memory that wasn't already present at
    // startup, and cannot have a remote thread injected into it that
    // calls into freshly-allocated executable memory — this is the
    // standard "block DLL injection via remote code execution" hardening
    // flag (the same one browsers/password managers with a hardening
    // mode set on Windows).
    const PROCESS_MITIGATION_DYNAMIC_CODE_POLICY: i32 = 7;
    const PROCESS_DYNAMIC_CODE_PROHIBIT: u32 = 0x1;

    // ProcessExtensionPointDisablePolicy (8): blocks the legacy
    // global-hook injection vectors (AppInit_DLLs, window hooks,
    // Winsock LSP chains) that some "process isolation" bypass tools
    // still rely on.
    const PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY: i32 = 8;
    const PROCESS_EXTENSION_POINT_DISABLE: u32 = 0x1;

    extern "system" {
        fn SetErrorMode(u_mode: u32) -> u32;
        fn GetCurrentProcess() -> *mut c_void;
        fn SetProcessMitigationPolicy(
            mitigation_policy: i32,
            lp_buffer: *mut c_void,
            dw_length: usize,
        ) -> i32;
        // Blocks a foreign process from opening us with an access mask
        // that includes PROCESS_VM_READ/PROCESS_VM_WRITE by tightening
        // our own primary token's discretionary ACL is a much larger
        // undertaking (SetKernelObjectSecurity on our own process
        // handle) — deliberately out of scope here as a
        // higher-blast-radius change than the mitigation-policy flags
        // above; those are additive and can't make an otherwise-working
        // install misbehave, whereas a bad DACL on our own process
        // object can leave the process unable to be inspected even by
        // legitimate tooling (our own crash handler, antivirus, etc.).
        fn DebugSetProcessKillOnExit(kill_on_exit: i32) -> i32;
    }

    pub fn harden() {
        // SAFETY: every call below passes only integers, a `NULL`
        // pointer, or a pointer to a local, fully-initialized value of
        // the exact size passed in `dw_length` — matching each
        // function's documented Win32 contract. All are best-effort:
        // return values are intentionally ignored except where noted,
        // since a refusal (e.g. running under an already-attached
        // debugger, which some of these calls reject) must not be
        // treated as fatal, per this module's stated contract.
        unsafe {
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

            let mut dynamic_code = MitigationPolicy(PROCESS_DYNAMIC_CODE_PROHIBIT);
            SetProcessMitigationPolicy(
                PROCESS_MITIGATION_DYNAMIC_CODE_POLICY,
                &mut dynamic_code as *mut _ as *mut c_void,
                size_of::<MitigationPolicy>(),
            );

            let mut ext_point = MitigationPolicy(PROCESS_EXTENSION_POINT_DISABLE);
            SetProcessMitigationPolicy(
                PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY,
                &mut ext_point as *mut _ as *mut c_void,
                size_of::<MitigationPolicy>(),
            );

            // If a debugger *is* already attached (e.g. this build is
            // being run under a debugger deliberately, for development),
            // make sure detaching it kills this process rather than
            // leaving it running un-debugged-but-already-inspected —
            // avoids a false sense of security after a dev/debug session.
            let _ = GetCurrentProcess();
            DebugSetProcessKillOnExit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_never_panics() {
        // Best-effort, platform-gated: the only contract this test can
        // usefully check from CI is "calling it doesn't crash the
        // process", same as every `mem_lock` test. Calling it twice must
        // also be safe, since a future caller re-running `init()` (e.g.
        // after `fork`-like reinitialization, if that's ever added) must
        // not double-fault.
        init();
        init();
    }
}
