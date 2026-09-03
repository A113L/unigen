//! Fuzzes `unigen::vault::parse_csv(contents, source)` — the hand-rolled
//! CSV parser (`split_csv_line` / `split_csv_records`) flagged in U-A09 as
//! a quote-parity heuristic rather than a full RFC 4180 parser. This is
//! exactly the kind of "own parser on untrusted input" the audit's
//! attacker-mindset pass calls out: embedded/escaped quotes (`""`), mixed
//! CRLF/LF, empty fields, very long fields, and malformed quote parity
//! are the specific shapes worth throwing at it.
//!
//! `CsvSource` isn't `arbitrary::Arbitrary` (it's a plain
//! `#[derive(Clone, Copy, PartialEq)]` enum in vault.rs, no reason to add
//! a fuzzing-only dependency to the main crate for it), so the first
//! fuzz-input byte selects which of the 6 known layouts to parse against,
//! and the rest of the bytes are the CSV text itself.

#![no_main]
use libfuzzer_sys::fuzz_target;
use unigen::vault::{self, CsvSource};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let source = match data[0] % 6 {
        0 => CsvSource::Chromium,
        1 => CsvSource::Firefox,
        2 => CsvSource::Bitwarden,
        3 => CsvSource::OnePassword,
        4 => CsvSource::KeePass,
        _ => CsvSource::Generic,
    };
    // parse_csv takes &str, not &[u8] — real CSV imports are read as text,
    // so invalid-UTF-8 input is out of scope for this parser (the file
    // read/import path elsewhere is responsible for that boundary); skip
    // rather than lossily convert, which would fuzz a different string
    // than what a real caller would ever pass in.
    if let Ok(contents) = std::str::from_utf8(&data[1..]) {
        let _ = vault::parse_csv(contents, source);
    }
});
