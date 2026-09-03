//! Fuzzes `unigen::crypto::stream_decrypt_file(in_path, out_path, password,
//! on_progress)` — the chunked/streaming container format used for large
//! files. This is the codepath that owns the per-chunk `is_final` byte
//! (U-A03), the chunk-length prefix bound check, and the running chunk
//! counter folded into each chunk's AAD.
//!
//! `stream_decrypt_file` reads from a `&Path`, not a byte slice, so the
//! fuzz input is materialized as a temp file per iteration. `out_path` is
//! `None` — we only care about whether parsing/decryption panics or
//! misbehaves, not about writing plaintext to disk.

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;
use unigen::crypto;

const FUZZ_PASSWORD: &str = "correct horse battery staple";

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    if tmp.flush().is_err() {
        return;
    }

    let _ = crypto::stream_decrypt_file(tmp.path(), None, FUZZ_PASSWORD, None);
});
