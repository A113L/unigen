//! Fuzzes `unigen::crypto::decrypt_blob(password, combined)`.
//!
//! `combined` is the on-disk blob container: MAGIC || VERSION || kdf_id ||
//! kdf_params(v3+) || salt(16) || nonce(12) || ciphertext(+tag). The
//! password is fixed (fuzzing can't productively search a passphrase
//! space) — what we're checking is that `decrypt_blob` never panics,
//! never allocates/derives beyond the U-A01 runtime budget
//! (`validate_runtime_budget` in crypto.rs), and never returns `Ok` for
//! ciphertext whose AES-GCM tag doesn't actually verify.
//!
//! Run with a memory ceiling so a *regression* of the U-A01 fix (someone
//! loosening `MAX_ARGON2_MEMORY_KIB` etc.) shows up as an OOM/timeout
//! finding rather than silently passing:
//!
//!   cargo +nightly fuzz run decrypt_blob -- -rss_limit_mb=512 -timeout=5

#![no_main]
use libfuzzer_sys::fuzz_target;
use unigen::crypto;

const FUZZ_PASSWORD: &str = "correct horse battery staple";

fuzz_target!(|data: &[u8]| {
    let _ = crypto::decrypt_blob(FUZZ_PASSWORD, data);
});
