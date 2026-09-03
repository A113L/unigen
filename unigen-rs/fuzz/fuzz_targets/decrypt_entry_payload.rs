//! Fuzzes `unigen::crypto::decrypt_entry_payload(vault_key, entry_id,
//! sealed)`.
//!
//! Unlike the container-level targets, an attacker fuzzing this function
//! in isolation is assumed to already know `vault_key` (see the audit's
//! own framing of U-A0x findings that touch entry-level ciphertext: "if
//! an attacker has the vault key" — the interesting question at *that*
//! point is only "can malformed/tampered `sealed` bytes cause a panic or
//! an entry-ID confusion", not "can they recover the key"). So this
//! target fixes `vault_key` to an arbitrary constant and lets the fuzzer
//! vary `entry_id` and `sealed` freely via `arbitrary`, which also
//! exercises the entry_id/AAD binding described in the crypto.rs docs
//! (entry ciphertext A framed under entry_id B should fail auth, never
//! panic).

#![no_main]
use libfuzzer_sys::{arbitrary::Arbitrary, fuzz_target};
use unigen::crypto;

const FUZZ_VAULT_KEY: [u8; 32] = [0x42; 32];

// Derive via `libfuzzer_sys::arbitrary` (its re-export) rather than adding
// a direct `arbitrary` dependency, so this always matches whatever
// `arbitrary` version `libfuzzer-sys` itself was built against — an
// explicit separate dependency risks a version mismatch where two
// different `Arbitrary` traits exist and the derive picks the wrong one.
#[derive(Arbitrary, Debug)]
struct Input {
    entry_id: u64,
    sealed: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let _ = crypto::decrypt_entry_payload(&FUZZ_VAULT_KEY, input.entry_id, &input.sealed);
});
