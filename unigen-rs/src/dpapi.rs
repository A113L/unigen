//! Windows DPAPI (`CryptProtectData`/`CryptUnprotectData`) wrapper.
//!
//! DPAPI ties ciphertext to the *current Windows user account* (and,
//! with `CRYPTPROTECT_LOCAL_MACHINE` unset, as here, only that user can
//! ever unprotect it — not even an Administrator on the same machine,
//! without the user's own logon secrets). The OS derives and manages the
//! key material itself; this app never sees or stores a DPAPI key.
//!
//! What this is *for* in UNIGEN: the vault's master password is never
//! written to disk in any form by default (matching the rest of this
//! app's "nothing sensitive touches disk unless the user explicitly
//! exports/saves it" design). This module exists so that the one place
//! the app *optionally* lets the user trade a little security for
//! convenience — "keep this vault unlocked across a lock without
//! retyping the master password" (see `vault::RememberSession` for the
//! exact policies this can mean) — can do so without ever storing the
//! password in plaintext: see `vault::SessionUnlockCache` for the call
//! site, gated behind an explicit opt-in and cleared on every event that
//! should invalidate it. DPAPI is the right primitive for that specific
//! job because it's already how Windows itself protects saved-Wi-Fi-
//! password-style "remember this for me" secrets, and it doesn't
//! require this app to manage or protect a key of its own — the OS
//! does, tied to the user's own account (see the caveat on
//! `RememberSession::UntilLogout` about what that guarantees in
//! practice, and what this app enforces on top of it).
//!
//! Non-Windows builds compile this module too (so call sites don't need
//! `#[cfg(windows)]` scattered through `main.rs`), but every function
//! simply returns an error — there is no DPAPI equivalent on other
//! platforms, and callers must treat "the session-remember convenience
//! feature isn't available" as an acceptable degraded mode, not a fatal
//! error, exactly like `mem_lock::SUPPORTED == false` elsewhere.

#[cfg(not(windows))]
use anyhow::{anyhow, Result};

/// Whether this platform actually has DPAPI. Mirrors `mem_lock::SUPPORTED`
/// — used to decide whether to show the "remember for this session"
/// checkbox in the UI at all, rather than showing it and having it always
/// fail.
pub const SUPPORTED: bool = cfg!(windows);

#[cfg(windows)]
mod imp {
    use anyhow::{anyhow, Context, Result};
    use std::ffi::c_void;
    use std::ptr;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            psz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            p_reserved: *const c_void,
            p_prompt_struct: *const c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;

        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            psz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            p_reserved: *const c_void,
            p_prompt_struct: *const c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;

        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    // Never show any OS UI (a password/credential prompt) for either
    // call — this is a background convenience cache, not an interactive
    // credential store, and a surprise OS dialog popping up over this
    // app's own window would be a confusing UX regression, not a
    // legitimate extra confirmation step.
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    /// Wrap `plaintext` with `CryptProtectData`, scoped to the current
    /// Windows user (no `CRYPTPROTECT_LOCAL_MACHINE` flag, so no other
    /// account — including an Administrator — can call
    /// `CryptUnprotectData` on the result without this user's own logon
    /// context). `label` is stored alongside the ciphertext by DPAPI
    /// itself (visible without unprotecting, like a filename) purely for
    /// operator/forensic clarity if this blob is ever found on disk —
    /// keep it non-sensitive.
    ///
    /// `entropy` is DPAPI's "optional entropy": extra bytes folded into
    /// the protection so `CryptUnprotectData` only succeeds when the
    /// *same* entropy is supplied again, on top of the same-user-account
    /// requirement DPAPI always enforces. Callers should derive this from
    /// whatever the sealed blob is meant to be tied to (e.g. a specific
    /// vault file's identity) — see this module's caller in `vault.rs`
    /// (`SessionUnlockCache`) for why that binding matters: without it, a
    /// sealed blob is valid for *any* ciphertext under this user account,
    /// including one copied next to a different vault file.
    pub fn protect(plaintext: &[u8], label: &str, entropy: &[u8]) -> Result<Vec<u8>> {
        let mut in_blob = DataBlob {
            cb_data: plaintext.len() as u32,
            pb_data: plaintext.as_ptr() as *mut u8,
        };
        let descr: Vec<u16> = label.encode_utf16().chain(std::iter::once(0)).collect();
        let mut entropy_blob = DataBlob {
            cb_data: entropy.len() as u32,
            pb_data: entropy.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        // SAFETY: `in_blob` points at `plaintext`, valid for the call's
        // duration; `descr` is a live, NUL-terminated UTF-16 buffer for
        // the same duration; `entropy_blob` points at `entropy`, valid
        // for the call's duration; `out_blob` is an out-parameter DPAPI
        // fills in on success, freed via `LocalFree` below once we've
        // copied its contents into an owned `Vec`.
        let ok = unsafe {
            CryptProtectData(
                &mut in_blob,
                descr.as_ptr(),
                &mut entropy_blob,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if ok == 0 {
            return Err(anyhow!(
                "DPAPI CryptProtectData failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // SAFETY: `out_blob.pb_data` was allocated by DPAPI (via LocalAlloc
        // internally) and is valid for `out_blob.cb_data` bytes per the
        // documented CryptProtectData contract; we copy it into an owned
        // buffer before freeing the original with `LocalFree`.
        let result = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
        };
        unsafe {
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        Ok(result)
    }

    /// Reverse of [`protect`]. Fails (rather than silently returning
    /// garbage) if `blob` wasn't produced by this same Windows user
    /// account via `protect` — DPAPI itself enforces this, the same way
    /// AES-GCM's auth tag enforces "this ciphertext wasn't tampered
    /// with" for the vault file format elsewhere in this app. `entropy`
    /// must exactly match what was passed to `protect` when `blob` was
    /// created, or this fails the same way a wrong user account would.
    pub fn unprotect(blob: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let mut in_blob = DataBlob {
            cb_data: blob.len() as u32,
            pb_data: blob.as_ptr() as *mut u8,
        };
        let mut entropy_blob = DataBlob {
            cb_data: entropy.len() as u32,
            pb_data: entropy.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        // SAFETY: same reasoning as `protect` above; `descr_out` is an
        // out-parameter we don't need (the label is informational only),
        // freed immediately if DPAPI populates it.
        let mut descr_out: *mut u16 = ptr::null_mut();
        let ok = unsafe {
            CryptUnprotectData(
                &mut in_blob,
                &mut descr_out,
                &mut entropy_blob,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };
        if !descr_out.is_null() {
            unsafe {
                LocalFree(descr_out as *mut c_void);
            }
        }
        if ok == 0 {
            return Err(anyhow!(
                "DPAPI CryptUnprotectData failed (wrong user account, or data \
                 corrupted/tampered): {}",
                std::io::Error::last_os_error()
            ))
            .context("failed to unprotect DPAPI-sealed data");
        }

        // SAFETY: same as `protect` — copy out, then free DPAPI's own
        // allocation. The returned plaintext buffer contains sensitive
        // data (a master password, in this app's only caller); the
        // caller is responsible for wrapping it in a `SecretString`/
        // `Zeroizing` buffer immediately, same convention as every other
        // plaintext-secret-producing function in this codebase.
        let result = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
        };
        unsafe {
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        Ok(result)
    }
}

#[cfg(windows)]
pub use imp::{protect, unprotect};

#[cfg(not(windows))]
pub fn protect(_plaintext: &[u8], _label: &str, _entropy: &[u8]) -> Result<Vec<u8>> {
    Err(anyhow!("DPAPI is only available on Windows"))
}

#[cfg(not(windows))]
pub fn unprotect(_blob: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
    Err(anyhow!("DPAPI is only available on Windows"))
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;

    #[test]
    fn protect_unprotect_round_trip() {
        let plaintext = b"correct horse battery staple";
        let entropy = b"vault-a-entropy";
        let protected = protect(plaintext, "unigen-test", entropy).expect("protect");
        assert_ne!(protected, plaintext, "DPAPI output must not equal input");
        let recovered = unprotect(&protected, entropy).expect("unprotect");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn unprotect_rejects_garbage() {
        let garbage = vec![0u8; 64];
        assert!(unprotect(&garbage, b"whatever").is_err());
    }

    #[test]
    fn unprotect_rejects_wrong_entropy() {
        // SECURITY REGRESSION TEST: a blob sealed under one vault's
        // entropy must not unprotect under a different vault's entropy —
        // this is exactly what stops a copied `.session-cache` sidecar
        // from unlocking against the wrong vault file.
        let plaintext = b"correct horse battery staple";
        let protected = protect(plaintext, "unigen-test", b"vault-a-entropy").expect("protect");
        let result = unprotect(&protected, b"vault-b-entropy");
        assert!(result.is_err(), "unprotect must fail under mismatched entropy");
    }
}

#[cfg(test)]
#[cfg(not(windows))]
mod non_windows_tests {
    use super::*;

    #[test]
    fn unsupported_off_windows() {
        assert!(!SUPPORTED);
        assert!(protect(b"x", "label", b"entropy").is_err());
        assert!(unprotect(b"x", b"entropy").is_err());
    }
}
