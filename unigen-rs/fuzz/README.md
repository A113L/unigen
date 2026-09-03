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
