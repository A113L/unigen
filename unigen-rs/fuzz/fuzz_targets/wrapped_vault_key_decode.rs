//! Fuzzes `unigen::crypto::WrappedVaultKey::decode(data)` — the
//! fixed-plus-length-prefixed header parser at the very front of every
//! vault container (`kdf_id || kdf_params(12) || kek_salt(16) ||
//! wrap_nonce(12) || wrapped_len(4) || wrapped_key_and_tag`). This is the
//! very first thing `vault::decrypt_vault_envelope` touches on untrusted
//! bytes, and it's also where `KdfParams::validate` (the format-level
//! bound) and `validate_runtime_budget` (the U-A01 application-level
//! bound) get exercised via `KdfParams::from_bytes(..).validate(kdf_id)`.
//!
//! We only care that `decode` never panics (integer overflow on the
//! `off + n` arithmetic, out-of-bounds slicing, etc.) — it's expected to
//! frequently return `Err` on fuzzer-generated garbage, that's fine.

#![no_main]
use libfuzzer_sys::fuzz_target;
use unigen::crypto::WrappedVaultKey;

fuzz_target!(|data: &[u8]| {
    let _ = WrappedVaultKey::decode(data);
});
