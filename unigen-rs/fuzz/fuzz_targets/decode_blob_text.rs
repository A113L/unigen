//! Fuzzes `unigen::crypto::decode_blob_text(file_contents)` — the
//! text-encoding layer above the raw blob container (used when a vault
//! blob is round-tripped through something text-oriented, e.g. clipboard
//! or a text field, rather than raw bytes on disk). Its doc-adjacent
//! sibling `decode_blob_text_falls_back_to_raw_bytes` (see the existing
//! unit test of the same name) already covers the "not valid encoded
//! text" fallback path as a directed test; this target fuzzes the same
//! function for panics across the full input space instead of just that
//! one hand-picked case.

#![no_main]
use libfuzzer_sys::fuzz_target;
use unigen::crypto;

fuzz_target!(|data: &[u8]| {
    let _ = crypto::decode_blob_text(data);
});
