//! Cross-platform "keep this memory out of swap" primitive.
//!
//! Wraps the three platform mechanisms this app can use to ask the OS to
//! keep a range of process memory resident and excluded from swap/the
//! pagefile:
//!
//!   * Linux / macOS (and other Unix): `mlock(2)` / `munlock(2)`.
//!   * Windows: `VirtualLock` / `VirtualUnlock`.
//!   * Anything else: no primitive exists, so `lock` always reports
//!     failure and `unlock` is a no-op.
//!
//! This is `SecretBytes`/`SecretString`'s and `main.rs`'s single point of
//! contact with the raw syscalls, so the "best effort, not a guarantee"
//! contract only has to be documented once: on every platform above, the
//! OS is free to refuse the request (Unix: `RLIMIT_MEMLOCK`; Windows: the
//! process's working-set quota — see the note on `lock` below), and a
//! `false`/no-op return here must never be treated as fatal by callers.

#[cfg(unix)]
extern "C" {
    fn mlock(addr: *const std::ffi::c_void, len: usize) -> i32;
    fn munlock(addr: *const std::ffi::c_void, len: usize) -> i32;
}

#[cfg(windows)]
extern "system" {
    fn VirtualLock(lp_address: *mut std::ffi::c_void, dw_size: usize) -> i32;
    fn VirtualUnlock(lp_address: *mut std::ffi::c_void, dw_size: usize) -> i32;
}

/// Best-effort: ask the OS to keep `[addr, addr + len)` resident and out
/// of swap (Unix) or the pagefile (Windows) for as long as the caller
/// also calls the matching [`unlock`] before the memory is freed or
/// reused. Returns `false` if the platform has no such primitive, or if
/// the OS refuses the request — on Unix this is typically `RLIMIT_MEMLOCK`
/// being exceeded; on Windows, `VirtualLock` additionally requires the
/// locked region to fit inside the process's current working-set quota
/// (`ERROR_WORKING_SET_QUOTA`). This deliberately does not attempt to grow
/// the working set via `SetProcessWorkingSetSize` — doing so would make
/// locking behave differently (and have different failure modes) across
/// platforms, which would undermine the "best effort, not a guarantee"
/// contract every call site here already relies on. Callers must treat a
/// `false` return the same way they treat a refused Unix `mlock`: log/warn
/// if useful, but never fail the operation because of it.
pub fn lock(addr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    #[cfg(unix)]
    {
        // SAFETY: `addr` is valid for `len` bytes for the duration of
        // this call (caller's invariant, same as any FFI pointer+len
        // pair); `mlock` only reads these arguments and does not retain
        // the pointer past the call.
        unsafe { mlock(addr as *const std::ffi::c_void, len) == 0 }
    }
    #[cfg(windows)]
    {
        // SAFETY: same as above — `addr`/`len` describe a valid live
        // range for the duration of this call. `VirtualLock` returns
        // nonzero on success (opposite polarity from `mlock`'s 0-on-
        // success).
        unsafe { VirtualLock(addr as *mut std::ffi::c_void, len) != 0 }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (addr, len);
        false
    }
}

/// Release a lock previously taken by [`lock`] on the same `[addr, addr +
/// len)` range. Best-effort/no-op on failure, same as `lock` — there is
/// nothing a caller can usefully do if the OS refuses an unlock request,
/// and on platforms without a lock primitive this is simply a no-op.
pub fn unlock(addr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    #[cfg(unix)]
    {
        // SAFETY: see `lock` above.
        unsafe {
            munlock(addr as *const std::ffi::c_void, len);
        }
    }
    #[cfg(windows)]
    {
        // SAFETY: see `lock` above.
        unsafe {
            VirtualUnlock(addr as *mut std::ffi::c_void, len);
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (addr, len);
    }
}

/// Whether this platform has a memory-locking primitive at all. Used to
/// decide whether to surface the "keep passphrase out of swap" UI option
/// and related warnings; on targets without one (any non-Unix,
/// non-Windows target) there is nothing for the checkbox to do.
pub const SUPPORTED: bool = cfg!(any(unix, windows));

/// U-06 fix: human-readable status for the "keep secrets out of swap" UI
/// control, given whether the user has the setting enabled and whether
/// the field's live buffer is currently believed to be locked (per
/// `SecretString::is_locked`/`SecretBytes::locked` — the result of the
/// most recent `mlock`/`VirtualLock` attempt for that specific buffer).
///
/// Before this, the checkbox that opts into memory locking had no
/// feedback loop at all beyond a one-shot warning message shown only if
/// the very first lock attempt at encrypt-time failed — a user could tick
/// the box, have every `mlock` call silently fail for the rest of the
/// session (`RLIMIT_MEMLOCK` exhausted, working-set quota, unsupported
/// filesystem/config), and have no way to tell the setting wasn't
/// actually doing anything. This gives every call site that renders the
/// checkbox (or a password field affected by it) a live, per-field status
/// label to show next to it.
///
/// Returns `(text, kind)` in the same convention as
/// [`crate::charsets::rate_entropy`] (`kind` is one of `"success"`,
/// `"warning"`, `"danger"`, `"neutral"`), so call sites can reuse the
/// same rating-color mapping.
pub fn status_label(enabled: bool, locked: bool) -> (&'static str, &'static str) {
    if !SUPPORTED {
        ("Not available on this platform", "warning")
    } else if !enabled {
        ("Disabled", "neutral")
    } else if locked {
        ("Locked in RAM (mlock/VirtualLock)", "success")
    } else {
        (
            "Not locked — OS may have refused the request, or nothing to lock yet",
            "danger",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_lock_is_a_trivial_success() {
        // No real memory is touched for a zero-length range, on any
        // platform, so this must always report success rather than
        // depend on OS lock-limit availability.
        assert!(lock(std::ptr::NonNull::<u8>::dangling().as_ptr(), 0));
    }

    #[test]
    fn zero_length_unlock_does_not_panic() {
        unlock(std::ptr::NonNull::<u8>::dangling().as_ptr(), 0);
    }

    #[test]
    fn lock_then_unlock_a_real_buffer_does_not_panic() {
        // Best-effort: the OS may refuse the lock (e.g. RLIMIT_MEMLOCK /
        // working-set quota in a constrained CI sandbox), so this
        // intentionally does not assert `lock(..)` returns `true` — only
        // that calling lock/unlock on a real, valid range never panics
        // or misbehaves, matching every other best-effort mlock call site
        // in this app.
        let mut buf = vec![0u8; 4096];
        let ok = lock(buf.as_ptr(), buf.len());
        let _ = ok;
        unlock(buf.as_ptr(), buf.len());
        buf.fill(0);
    }

    #[test]
    fn supported_matches_target_family() {
        assert_eq!(SUPPORTED, cfg!(any(unix, windows)));
    }

    #[test]
    fn status_label_disabled_takes_priority_over_locked_state_when_supported() {
        if SUPPORTED {
            let (text, kind) = status_label(false, true);
            assert_eq!(kind, "neutral");
            assert_eq!(text, "Disabled");
        }
    }

    #[test]
    fn status_label_reports_locked_and_unlocked_when_enabled() {
        if SUPPORTED {
            let (_, locked_kind) = status_label(true, true);
            assert_eq!(locked_kind, "success");
            let (_, unlocked_kind) = status_label(true, false);
            assert_eq!(unlocked_kind, "danger");
        }
    }

    #[test]
    fn status_label_reports_unsupported_platform_regardless_of_other_args() {
        if !SUPPORTED {
            for enabled in [false, true] {
                for locked in [false, true] {
                    let (_, kind) = status_label(enabled, locked);
                    assert_eq!(kind, "warning");
                }
            }
        }
    }
}
