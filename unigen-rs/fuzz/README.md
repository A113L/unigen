# unigen fuzz targets

Requires nightly + cargo-fuzz:

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

All targets link against `unigen` as a library (`src/lib.rs`), not the
`unigen` binary — no eframe/GUI code is in the fuzzed dependency graph.

## Targets

| Target                     | Function                                    | Covers |
|-----------------------------|----------------------------------------------|--------|
| `decrypt-blob`               | `crypto::decrypt_blob`                       | U-A01 (KDF runtime budget), blob header parsing |
| `decrypt-blob-compat`        | `crypto::decrypt_blob_compat`                | legacy/compat container shape ambiguity |
| `stream-decrypt-file`        | `crypto::stream_decrypt_file`                | U-A03 (`is_final` flag), chunk framing/counter |
| `wrapped-vault-key-decode`   | `crypto::WrappedVaultKey::decode`            | vault header parsing, KDF params validation |
| `decrypt-entry-payload`      | `crypto::decrypt_entry_payload`              | per-entry AEAD, entry_id/AAD binding |
| `parse-csv`                  | `vault::parse_csv`                           | U-A09, hand-rolled CSV quote-parity parser |
| `decode-blob-text`           | `crypto::decode_blob_text`                   | text-encoding wrapper around blob bytes |
| `decrypt-vault-bytes`        | `vault::decrypt_vault`                       | full end-to-end: header + entry loop + JSON |

## Running

Always set an RSS limit — this is precisely what verifies the U-A01 fix
(`validate_runtime_budget` in `crypto.rs`) actually holds:

```bash
cargo +nightly fuzz run decrypt-blob -- -rss_limit_mb=512 -timeout=5 -max_total_time=600
cargo +nightly fuzz run stream-decrypt-file -- -rss_limit_mb=512 -timeout=5 -max_total_time=600
cargo +nightly fuzz run wrapped-vault-key-decode -- -rss_limit_mb=512 -timeout=5 -max_total_time=300
cargo +nightly fuzz run decrypt-entry-payload -- -rss_limit_mb=512 -timeout=5 -max_total_time=300
cargo +nightly fuzz run parse-csv -- -rss_limit_mb=512 -timeout=5 -max_total_time=300
cargo +nightly fuzz run decode-blob-text -- -rss_limit_mb=512 -timeout=5 -max_total_time=180
cargo +nightly fuzz run decrypt-vault-bytes -- -rss_limit_mb=512 -timeout=5 -max_total_time=600
```

A crash/timeout/OOM finding is written to
`fuzz/artifacts/<target>/crash-<hash>`; re-run against just that input with:

```bash
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>
```

to get a reproducible, minimizable failing case — worth committing as a
regression test (`fuzz/corpus/<target>/` or a dedicated `#[test]` in the
relevant module) once fixed.

## Coverage-guided minimization

```bash
cargo +nightly fuzz cmin decrypt-blob
cargo +nightly fuzz tmin decrypt-blob fuzz/artifacts/decrypt-blob/crash-<hash>
```

---

# UNIGEN Fuzz — 2026-09-03
 
**Run:** `./run_fuzz.sh --log` · 8 targets × 10 min (`-max_total_time=600 -rss_limit_mb=512 -timeout=5`)

**Result: ✅ 0 crashes / 0 timeouts / 0 OOMs across all 8 targets**
 
## Summary
 
| Target | Duration | Executions | Cov (edges) | Features | Corpus | Avg exec/s | Status |
|---|---|---|---|---|---|---|---|
| `decrypt-blob` | 10m09s | 2,842 | 753 | 809 | 40 / 2.4 KB | 4 | ✅ clean |
| `decrypt-blob-compat` | 10m02s | 1,613 | 304 | 309 | 10 / 144 B | 2 | ✅ clean |
| `stream-decrypt-file` | 10m03s | 2,815 | 458 | 500 | 23 / 544 B | 4 | ✅ clean |
| `wrapped-vault-key-decode` | 10m02s | 176,522,524 | 99 | 103 | 15 / 635 B | 293,714 | ✅ clean |
| `decrypt-entry-payload` | 10m00s | 36,163,834 | 379 | 524 | 46 / 11.0 KB | 60,172 | ✅ clean |
| `parse-csv` | 10m02s | 6,043,189 | 545 | 3,251 | 992 / 188 KB | 10,055 | ✅ clean |
| `decode-blob-text` | 10m01s | 67,886,446 | 306 | 894 | 227 / 8.0 KB | 112,955 | ✅ clean |
| `decrypt-vault-bytes` | 10m03s | 5,399 | 327 | 332 | 13 / 192 B | 8 | ✅ clean |
