//! Fuzzes `unigen::vault::decrypt_vault(master_password, combined)` — the
//! top-level entry point that ties together `WrappedVaultKey::decode`,
//! the entry-count/entry-id/sealed_len framing loop, `decrypt_entry_payload`
//! per entry, and `serde_json::from_slice` into `VaultEntry` (falling back
//! to the legacy single-blob format internally if the envelope magic
//! doesn't match). This is the closest single target to "what happens
//! when a user double-clicks a byte-flipped or entirely-garbage .vault
//! file" — the scenario the audit's own byte-flip test proposal
//! describes.
//!
//! Password is fixed for the same reason as the other targets: fuzzing a
//! passphrase search isn't productive, we're checking parser/allocation
//! robustness against untrusted framing, not confidentiality.

#![no_main]
use libfuzzer_sys::fuzz_target;
use unigen::vault;

const FUZZ_PASSWORD: &str = "correct horse battery staple";

fuzz_target!(|data: &[u8]| {
    let _ = vault::decrypt_vault(FUZZ_PASSWORD, data);
});
