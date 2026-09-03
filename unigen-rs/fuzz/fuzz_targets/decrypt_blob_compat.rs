//! Fuzzes `unigen::crypto::decrypt_blob_compat(password, combined)` — the
//! codepath that also has to accept the legacy (pre-Rust-rewrite,
//! no-AAD) Python container format, i.e. more header-shape ambiguity to
//! get wrong than the current-format-only `decrypt_blob`.

#![no_main]
use libfuzzer_sys::fuzz_target;
use unigen::crypto;

const FUZZ_PASSWORD: &str = "correct horse battery staple";

fuzz_target!(|data: &[u8]| {
    let _ = crypto::decrypt_blob_compat(FUZZ_PASSWORD, data);
});
