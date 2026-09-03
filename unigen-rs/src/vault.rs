//! Password-manager vault: a single encrypted file holding many named
//! credential entries.
//!
//! ENVELOPE KEY HIERARCHY: unlike the flat `encrypt_blob`/`decrypt_blob`
//! containers in `crypto.rs` (one password-derived key, used directly on
//! the whole ciphertext — right for a one-shot file), the vault format
//! here uses a three-level hierarchy: **master password -> KEK -> vault
//! key -> per-entry key**. See `crypto.rs`'s "Envelope key hierarchy"
//! module section for the full design rationale (one-directional key
//! containment, and the cheap, O(1)-in-entry-count re-wrap-only password
//! change this hierarchy enables — see [`change_master_password`]'s own
//! doc comment); this module is the consumer of those primitives and
//! owns the on-disk container layout:
//!
//! ```text
//! VAULT_MAGIC(4="UGV1")
//! WrappedVaultKey::encode() — kdf_id(1) || kdf_params(12) || kek_salt(16)
//!                              || wrap_nonce(12) || wrapped_len(4) || wrapped_vault_key(..)
//! entry_count(4, u32 BE)
//! repeated entry_count times:
//!   entry_id(8, u64 BE)        — same id as VaultEntry::id, unencrypted
//!                                 (needed to derive/look up the right
//!                                 entry key before anything can be
//!                                 decrypted at all — see the note on
//!                                 `decrypt_vault_envelope`)
//!   sealed_len(4, u32 BE)
//!   sealed_entry — nonce(12) || AES-256-GCM(entry_key, this entry's
//!                  serialized-JSON `VaultEntry`)+tag, from
//!                  `crypto::encrypt_entry_payload`
//! ```
//!
//! This whole container is then base64-text-encoded the same way every
//! other UNIGEN `.enc`/vault file is (`crypto::encode_blob_text`) — see
//! [`read_vault_file`]/[`write_vault_file`] — so a vault file still
//! looks and round-trips through the filesystem exactly like before;
//! only the bytes *inside* that text envelope changed shape.
//!
//! BACKWARD COMPATIBILITY: vaults saved by earlier builds are a flat
//! `crypto::encrypt_blob` container (`crypto::BLOB_MAGIC`) whose
//! plaintext is one JSON array of every entry — the single-derived-key
//! design this replaces. [`decrypt_vault`] still reads those directly
//! (see `decrypt_vault_legacy_blob`), so upgrading to this build doesn't
//! strand anyone's existing vault file unreadable. [`encrypt_vault`]
//! (and therefore every *save* — add/edit/delete an entry, or "change
//! master password") always writes the new envelope format, so a legacy
//! vault transparently upgrades the first time anything about it is
//! saved, the same "old files stay old-format until next write, new
//! writes always use the current format" convention `crypto.rs`'s own
//! v1/v2/v3 blob-format history already established for U-01.

use crate::crypto;
use crate::dpapi;
use crate::secret::{LockedSecret, SecretString};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// A single credential record.
///
/// `password` is the only field that gets special handling in the UI
/// (masked by default, cleared from any transient copy buffers on close);
/// the whole entry is only ever kept in memory as part of the already
/// `Zeroizing`-wrapped vault, and only ever touches disk inside the
/// encrypted blob.
// SECURITY (U-02 fix): `SecretString`/`LockedSecret` deliberately don't
// implement the generic `serde::Serialize`/`Deserialize` traits anymore
// (see `secret.rs`), so a plain `#[derive(Serialize, Deserialize)]`
// would no longer compile here. Each secret-bearing field instead opts
// in *explicitly, by name*, to the crate-private serialize/deserialize
// functions — this is the one deliberate call path in the codebase
// where turning a secret into plaintext is correct, because the result
// is immediately fed into whole-vault AES-256-GCM encryption a few lines
// away in `encrypt_vault`, never written out or logged on its own.
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Stable id so the UI can reference an entry (e.g. for edit/delete)
    /// without relying on its position in the list, which changes under
    /// sorting/filtering.
    pub id: u64,
    #[serde(
        serialize_with = "crate::secret::secret_string_serialize",
        deserialize_with = "crate::secret::secret_string_deserialize"
    )]
    pub title: SecretString,
    #[serde(
        serialize_with = "crate::secret::secret_string_serialize",
        deserialize_with = "crate::secret::secret_string_deserialize"
    )]
    pub username: SecretString,
    /// Kept encrypted-at-rest in RAM (see `secret::LockedSecret`) rather
    /// than as a plain `SecretString`: unlike the other fields, this one
    /// sits in memory for the entire time the vault stays unlocked (not
    /// just while actively being edited), which is by far the longest
    /// plaintext-exposure window for a credential in this app. Use
    /// `.reveal()` to get a short-lived plaintext `SecretString` (e.g.
    /// for the edit pane or "show password"/copy actions) and re-`seal`
    /// it back on commit — see `UnigenApp::vault_select`/edit-commit.
    #[serde(
        serialize_with = "crate::secret::locked_secret_serialize",
        deserialize_with = "crate::secret::locked_secret_deserialize"
    )]
    pub password: LockedSecret,
    #[serde(
        serialize_with = "crate::secret::secret_string_serialize",
        deserialize_with = "crate::secret::secret_string_deserialize"
    )]
    pub url: SecretString,
    #[serde(
        serialize_with = "crate::secret::secret_string_serialize",
        deserialize_with = "crate::secret::secret_string_deserialize"
    )]
    pub notes: SecretString,
    pub created_at: u64,
    pub updated_at: u64,
}


// `Vec<Box<VaultEntry>>` doesn't implement `Zeroize` itself (no blanket
// impl for `Vec<T: Zeroize>` in this crate's zeroize version), so the app
// wraps entries in `Zeroizing<Vec<Box<VaultEntry>>>` and this manual impl
// is what makes that wrapper's `Drop` actually scrub the string contents
// instead of only dropping the `Vec`'s spine. `Zeroize` on `Box<T>`
// resolves through auto-deref to this impl, so callers can write
// `boxed_entry.zeroize()` directly without a separate `Box`-specific impl.
//
// FIX (previously a documented known limitation): entries used to live
// inline in the outer `Vec<VaultEntry>`. Every growth reallocation
// (`push()` past capacity) or shift (`remove()`) copied whichever
// `VaultEntry` structs the operation touched to a new/different location
// in the backing buffer, and the vacated bytes were never explicitly
// wiped before the allocator reused them. Wrapping each entry in its own
// `Box` fixes the part of that gap the outer `Vec` was responsible for:
// a `VaultEntry`'s fields now live at one fixed heap address for the
// entry's whole lifetime, and growing/shrinking the outer `Vec` only ever
// copies 8-byte `Box` pointers around — never the entry's own bytes.
//
// FIX (previously the last open item in this comment, and in the
// project's README "Known limitations" section): each field used to be
// a plain `String`, which owns its *own* separate heap buffer that can
// reallocate independently of the outer `Vec` — e.g. `push`/`push_str`
// crossing capacity, or `.clone()`. `String`'s growth/clone path is
// "allocate new buffer, copy, free the old one" with no wipe step, so
// the vacated bytes (a stale copy of a password, in the worst case) were
// left readable in freed-but-not-yet-reused heap memory. Boxing the
// entry (above) did nothing about this — it only removed the
// outer-`Vec`-reallocation source of stray copies.
//
// Every field is now `secret::SecretString` instead of `String`.
// `SecretString` owns its own growth/clone path end-to-end (see
// `src/secret.rs`) and zeroizes the old buffer before every relocation
// and on `Drop` — not just "the wrapper was dropped" like
// `Zeroizing<String>` gives you, but every intermediate reallocation
// during the value's own lifetime. This closes the gap for incremental
// construction (e.g. CSV import field concatenation) and `.clone()`
// alike, without needing a custom global allocator.
impl Zeroize for VaultEntry {
    fn zeroize(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        self.id = 0;
        self.created_at = 0;
        self.updated_at = 0;
    }
}

// `zeroize` (as of the pinned 1.7.x line, and still true in later 1.9.x
// releases) only provides blanket `Zeroize` impls for `Box<[Z]>` and
// `Box<str>` — not for `Box<Z>` generically. Since `vault_entries` is
// `Zeroizing<Vec<Box<VaultEntry>>>`, the outer `Vec<Z>: Zeroize` blanket
// impl needs `Z = Box<VaultEntry>: Zeroize`, which doesn't exist without
// this explicit impl. `Box` is a `#[fundamental]` type, so implementing a
// foreign trait (`Zeroize`) for `Box<VaultEntry>` is allowed under the
// orphan rules because `VaultEntry` itself is local to this crate.
//
// (This impl was missing from the first cut of the `Box<VaultEntry>`
// change and broke the `Zeroizing<Vec<Box<VaultEntry>>>` field in
// main.rs at compile time — caught by a build against the real
// zeroize 1.9.0 that main.rs's Cargo.lock resolves to, and now covered
// by `main_shape_tests` in the standalone logic crate used for CI-less
// verification in this environment.)
impl Zeroize for Box<VaultEntry> {
    fn zeroize(&mut self) {
        (**self).zeroize();
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serialize entries to JSON and encrypt them with the same blob format
/// used for the "encrypt a small file" path elsewhere in the app.
///
/// SECURITY (U-03 fix — streaming serializer): this used to build the
/// whole vault's plaintext JSON via `serde_json::to_vec(entries)`, whose
/// internal buffer is a plain `Vec<u8>` — every capacity-crossing
/// reallocation during serialization (which happens repeatedly for any
/// vault with more than a few entries, as the buffer doubles: hundreds
/// of bytes, then ~1 KiB, ~2 KiB, ...) freed a smaller buffer that
/// already contained plaintext passwords, without wiping it first. The
/// call site only zeroized the *final* buffer, once, after encryption —
/// every earlier, smaller intermediate copy was already leaked to
/// whatever the allocator does with freed memory. See
/// `secret::SecretJsonBuffer`'s doc comment for the full explanation.
///
/// Now `serde_json::to_writer` streams directly into a
/// `secret::SecretJsonBuffer` — a `std::io::Write` sink backed by the
/// same wipe-before-relocate/free buffer type (`SecretBytes`) that
/// `SecretString` already uses — so every reallocation the serialized
/// JSON ever triggers is zeroize-before-free, not just the one at the
/// very end. `encrypt_blob` reads the finished bytes via `as_slice()`;
/// the buffer is dropped (and wiped) automatically when this function
/// returns, whether it returns `Ok` or an early `Err` from `to_writer`
/// or `encrypt_blob` — no separate `.zeroize()` call needed at the call
/// site anymore, unlike the old plain-`Vec<u8>` version.
///
/// COLD-BOOT / STALE-COPY HARDENING: `entries` is `&[Box<VaultEntry>]`
/// rather than `&[VaultEntry]` everywhere in this module and in the
/// caller's app state. The entries themselves are heap-allocated one at a
/// time via `Box`, at a stable address that never moves for the lifetime
/// of that entry. Only the *pointers* live inside the outer `Vec`, so when
/// that `Vec` grows past capacity or shrinks (`push`/`remove`/`reserve`),
/// what gets copied to a new backing allocation is 8-byte pointers — never
/// password bytes. This closes the gap documented below on `impl Zeroize
/// for VaultEntry`: a `Vec<VaultEntry>` resize could leave an unzeroized
/// copy of a whole entry (password included) behind at the old address;
/// a `Vec<Box<VaultEntry>>` resize cannot, because no `VaultEntry` bytes
/// are ever part of what the `Vec`'s own reallocation copies.
/// Encrypt `entries` into the vault envelope container described in this
/// module's docs: a freshly-generated vault key wrapped under a KEK
/// derived from `master_password`, followed by every entry individually
/// encrypted under its own key derived from that vault key.
///
/// SECURITY (U-03, still honored here): each entry is serialized via
/// `serde_json::to_writer` straight into a `secret::SecretJsonBuffer`
/// (the same wipe-before-relocate/free buffer type this function used
/// for the whole vault before the envelope-hierarchy rewrite — see its
/// doc comment) — if anything, this is a strict improvement over the
/// old one-buffer-for-everything shape: each entry's buffer is smaller,
/// and is dropped (wiping it) at the end of *that* loop iteration rather
/// than only once at the very end of the whole vault.
pub fn encrypt_vault(
    master_password: &str,
    entries: &[Box<VaultEntry>],
    kdf_id: u8,
) -> Result<Vec<u8>> {
    let vault_key = crypto::generate_vault_key();
    let wrapped = crypto::wrap_vault_key(master_password, &vault_key, kdf_id)
        .context("failed to wrap vault key")?;
    let header = wrapped.encode();

    let mut out = Vec::with_capacity(4 + header.len() + 4 + entries.len() * 256);
    out.extend_from_slice(crypto::VAULT_MAGIC);
    out.extend_from_slice(&header);
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    for entry in entries {
        // Capacity hint only — see `SecretJsonBuffer::with_capacity`'s
        // doc comment — sized for one entry now instead of the whole
        // vault.
        let mut buf = crate::secret::SecretJsonBuffer::with_capacity(256);
        serde_json::to_writer(&mut buf, entry.as_ref())
            .context("failed to serialize vault entry")?;
        let sealed = crypto::encrypt_entry_payload(&vault_key, entry.id, buf.as_slice());
        out.extend_from_slice(&entry.id.to_be_bytes());
        out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
        out.extend_from_slice(&sealed);
        // `buf` drops here (end of this loop body), wiping this entry's
        // serialized JSON before the next entry's buffer is allocated.
    }
    Ok(out)
}

/// Decrypt and parse a vault file's contents (already read into memory by
/// the caller via [`read_vault_file`]). Dispatches on the container's
/// magic bytes — see this module's docs for why both formats need to
/// stay supported here.
pub fn decrypt_vault(master_password: &str, combined: &[u8]) -> Result<Vec<Box<VaultEntry>>> {
    if combined.len() >= 4 && &combined[0..4] == crypto::VAULT_MAGIC {
        decrypt_vault_envelope(master_password, combined)
    } else {
        decrypt_vault_legacy_blob(master_password, combined)
    }
}

/// Current (envelope-hierarchy) vault format: unwrap the vault key, then
/// decrypt each entry independently under its own derived key — see this
/// module's top-level docs for the exact byte layout being parsed here.
///
/// Each entry is individually boxed on the way out of `serde_json`
/// deserialization (matching the pre-rewrite behavior this preserves) so
/// the in-memory vault never stores `VaultEntry` values inline inside a
/// `Vec`'s own resizable buffer — see the note that used to live on
/// `encrypt_vault` before the envelope-hierarchy rewrite, now folded into
/// this function since it's the one that actually builds that `Vec`.
///
/// SECURITY (U-03, read side): unlike the old whole-vault-as-one-blob
/// design, decrypting one entry at a time here means the *decrypted*
/// plaintext in memory at any moment is one entry's JSON, not the entire
/// vault's — a smaller, shorter-lived exposure window per entry, though
/// the aggregate amount of plaintext that exists across the whole
/// unlock (every entry, briefly, one after another) is unchanged. Each
/// entry's `plaintext` (a `Zeroizing<Vec<u8>>` — see
/// `crypto::decrypt_entry_payload`) is wiped automatically when it drops
/// at the end of the loop body, same guarantee the old single big buffer
/// had via its own explicit `.zeroize()`, just now scoped per entry
/// instead of once for everything.
fn decrypt_vault_envelope(master_password: &str, combined: &[u8]) -> Result<Vec<Box<VaultEntry>>> {
    let body = &combined[4..]; // VAULT_MAGIC already matched by the caller
    let (wrapped, header_len) =
        crypto::WrappedVaultKey::decode(body).context("invalid vault envelope header")?;
    let vault_key = crypto::unwrap_vault_key(master_password, &wrapped)
        .context("wrong master password, or file is not a valid vault")?;

    let rest = &body[header_len..];
    if rest.len() < 4 {
        bail!("Invalid vault envelope (truncated entry count)");
    }
    let entry_count = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as usize;
    // SECURITY (DoS): `entry_count` is attacker-controlled — it comes
    // straight off disk before anything else in this file has been
    // authenticated. Without this check a small crafted file (a few KB)
    // can claim `entry_count = u32::MAX` and drive `Vec::with_capacity`
    // below to attempt a multi-gigabyte allocation, which is an easy
    // OOM/crash — the file-size cap enforced elsewhere (`MAX_BLOB_SIZE`,
    // via `check_blob_file_size`) does not help here since it bounds the
    // whole file, not this specific field, and is checked separately
    // from this parse. Bound `entry_count` by what the remaining bytes
    // could *possibly* hold: every entry needs at least
    // `MIN_ENTRY_FRAME_SIZE` bytes (8-byte entry_id + 4-byte sealed_len,
    // even for a zero-length sealed payload), so an `entry_count` beyond
    // that is provably a corrupt/malicious file and can be rejected
    // before any allocation sized by it.
    const MIN_ENTRY_FRAME_SIZE: usize = 8 + 4; // entry_id(8) + sealed_len(4)
    let max_possible_entries = rest.len().saturating_sub(4) / MIN_ENTRY_FRAME_SIZE;
    if entry_count > max_possible_entries {
        bail!(
            "Invalid vault envelope: entry_count ({entry_count}) exceeds what the \
             remaining {} bytes could possibly contain",
            rest.len().saturating_sub(4)
        );
    }
    let mut off = 4;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        if rest.len() < off + 8 + 4 {
            bail!("Invalid vault envelope (truncated entry header)");
        }
        let entry_id = u64::from_be_bytes(rest[off..off + 8].try_into().unwrap());
        off += 8;
        let sealed_len = u32::from_be_bytes(rest[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if rest.len() < off + sealed_len {
            bail!("Invalid vault envelope (truncated entry payload)");
        }
        let sealed = &rest[off..off + sealed_len];
        off += sealed_len;

        let plaintext = crypto::decrypt_entry_payload(&vault_key, entry_id, sealed)
            .with_context(|| format!("failed to decrypt vault entry {entry_id}"))?;
        let entry: VaultEntry = serde_json::from_slice(&plaintext)
            .context("vault entry contents are not valid entry data")?;
        // Sanity check, not a security boundary on its own (a mismatch
        // here couldn't happen without either a bug in `encrypt_vault`
        // or `sealed` having been swapped for a *different* entry_id's
        // ciphertext at that same id slot — which would itself already
        // require forging a valid AES-GCM tag under that id's own AAD to
        // get this far, since `vault_entry_aad` binds `entry_id`). Catch
        // it explicitly anyway rather than silently trusting the JSON's
        // own `id` field over the envelope framing's.
        if entry.id != entry_id {
            bail!(
                "Invalid vault envelope: entry framed as id {entry_id} decrypted to a payload \
                 claiming id {}",
                entry.id
            );
        }
        entries.push(Box::new(entry));
        // `plaintext` (`Zeroizing<Vec<u8>>`) drops here, wiping this
        // entry's decrypted JSON before the next entry is decrypted.
    }
    Ok(entries)
}

/// Legacy (pre-envelope-hierarchy) vault format: a single
/// `crypto::encrypt_blob` container whose plaintext is one JSON array of
/// every entry, decrypted under one key derived directly from the master
/// password. This is exactly what `encrypt_vault`/`decrypt_vault` were
/// before the envelope-hierarchy rewrite — kept as-is (not merely
/// similar code, the literal previous implementation) so any vault file
/// saved by an earlier build keeps opening correctly. See this module's
/// top-level docs for the "old files stay old-format until next write"
/// migration story.
fn decrypt_vault_legacy_blob(master_password: &str, combined: &[u8]) -> Result<Vec<Box<VaultEntry>>> {
    let mut plaintext = crypto::decrypt_blob_compat(master_password, combined)
        .context("wrong master password, or file is not a valid vault")?;
    let entries: Vec<VaultEntry> =
        serde_json::from_slice(&plaintext).context("vault contents are not valid entry data")?;
    plaintext.zeroize();
    Ok(entries.into_iter().map(Box::new).collect())
}

/// Read a vault file from disk, enforcing the same size cap as the
/// blob (small-file) crypto path before it's loaded into memory.
pub fn read_vault_file(path: &Path) -> Result<Vec<u8>> {
    crypto::check_blob_file_size(path)?;
    let raw = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(crypto::decode_blob_text(&raw))
}

/// Encrypt `entries` and durably write them to `path` using the same
/// write-to-temp-then-rename + fsync + restricted-permissions sequence
/// the rest of the app uses for encrypted output, so a vault save can't
/// leave a half-written file behind on crash/power-loss.
///
/// BUG FIX (self-verification before publish): this used to go straight
/// from `write_durable(&tmp, ...)` to `replace_file(&tmp, path)` — the
/// temp file was never read back before becoming the vault's one-and-
/// only on-disk copy. That meant *any* bit-level fault between "the
/// ciphertext bytes exist in this function's local `Vec`" and "the bytes
/// that ended up readable at `tmp`" — a disk/controller/filesystem fault
/// on the write path, a bug in a future edit to `write_durable`, faulty
/// RAM flipping a bit in the buffer between encryption and the
/// `write_all` call, etc. — would silently become the vault's only
/// surviving copy. The failure wouldn't surface until the *next* time
/// the vault was unlocked (typically after an auto-lock, since that's
/// the routine "close and reopen the same file" path), at which point
/// `decrypt_vault` fails an AES-GCM authentication check against
/// perfectly good ciphertext for a *reason completely unrelated to the
/// password the user just typed* — but still gets reported as "wrong
/// master password, or file is not a valid vault", since that's the
/// only failure mode `decrypt_vault`'s AEAD check can distinguish from
/// an actual wrong-password attempt. A one-entry vault's tiny buffer
/// happening to round-trip cleanly while a several-hundred-entry vault's
/// larger buffer hits a transient fault is exactly the "works for a
/// small file, intermittently fails to reopen for a large one" pattern
/// this class of bug produces — without needing the write path itself to
/// contain any size-dependent logic error at all.
///
/// The fix: decrypt `tmp` back with the same password *before* it's
/// ever allowed to become `path`, using the exact same `decrypt_vault`
/// codepath a real future "Unlock" click will use, and comparing entry
/// counts. Only a `tmp` that already proves it can be read back correctly
/// is atomically published over the previous, still-good `path`. Any
/// corruption is now caught immediately, at save time, with a clear
/// "the file we just wrote didn't read back correctly" error — while
/// the previous good vault file is left completely untouched — instead
/// of surfacing later as a confusing "wrong password" on the next
/// unlock, with the previous good version already overwritten.
pub fn write_vault_file(
    path: &Path,
    master_password: &str,
    entries: &[Box<VaultEntry>],
    kdf_id: u8,
) -> Result<()> {
    let combined = encrypt_vault(master_password, entries, kdf_id)?;
    write_and_verify_vault_bytes(path, combined, master_password, entries.len())
}

/// Shared "durably publish these already-encrypted vault bytes" tail end
/// for both a normal save ([`write_vault_file`]) and the fast rewrap-only
/// password change ([`change_master_password_fast`]): verify in memory,
/// write to a temp file, read *that* back and verify it too, and only
/// then atomically replace `path`. Factored out of what used to be
/// `write_vault_file`'s own body so both callers share one copy of this
/// crash-safety sequence instead of two copies drifting apart over time
/// — see the extended comment that used to sit directly on
/// `write_vault_file` (still applies verbatim here) for the full
/// "why read back before publishing" rationale.
fn write_and_verify_vault_bytes(
    path: &Path,
    combined: Vec<u8>,
    master_password: &str,
    expected_entry_count: usize,
) -> Result<()> {
    // Verify in-memory first: decrypt straight from `combined` (no disk
    // round-trip yet) so a bug in encryption itself is caught before
    // anything ever touches the filesystem.
    let verify = decrypt_vault(master_password, &combined)
        .context("internal error: freshly-encrypted vault failed to decrypt in memory")?;
    if verify.len() != expected_entry_count {
        bail!(
            "internal error: freshly-encrypted vault has {} entries, expected {}",
            verify.len(),
            expected_entry_count
        );
    }

    // Store as base64 text, matching the on-disk convention every other
    // small-file (.enc) blob in this app uses — keeps vault files
    // consistent with the rest of UNIGEN's output and diff/copy-paste
    // friendly.
    let text = crypto::encode_blob_text(&combined);
    let tmp = crypto::unique_tmp_path(path);
    crypto::write_durable(&tmp, text.as_bytes())
        .with_context(|| format!("failed to write {}", tmp.display()))?;

    // Read `tmp` back from disk and decrypt *that* — this is the step
    // that actually catches a write-path fault, as opposed to the
    // in-memory check above which only catches an encryption-logic bug.
    // Any failure from here on cleans up `tmp` (best-effort) before
    // returning, so a failed verification never leaves a stray
    // `*.unigen-tmp` file behind, and — critically — `path` itself is
    // never touched until verification has already succeeded.
    let verify_result = read_vault_file(&tmp)
        .with_context(|| format!("failed to read back {} for verification", tmp.display()))
        .and_then(|readback| {
            decrypt_vault(master_password, &readback).with_context(|| {
                format!(
                    "wrote {} but it failed to decrypt back correctly — the vault on disk at \
                     {} has NOT been touched; this looks like a disk/write fault rather than a \
                     wrong password (the same password that was just used to encrypt these \
                     entries failed to decrypt the file we just wrote)",
                    tmp.display(),
                    path.display()
                )
            })
        })
        .and_then(|verify| {
            if verify.len() == expected_entry_count {
                Ok(())
            } else {
                bail!(
                    "wrote {} but it read back with {} entries instead of {} — the vault on \
                     disk at {} has NOT been touched",
                    tmp.display(),
                    verify.len(),
                    expected_entry_count,
                    path.display()
                );
            }
        });
    if let Err(e) = verify_result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    crypto::replace_file(&tmp, path)
        .with_context(|| format!("failed to finalize {}", path.display()))?;
    crypto::restrict_permissions(path);
    Ok(())
}

/// Minimum capacity reserved up front for a freshly unlocked/created
/// vault's entry list, so ordinary day-to-day use (adding a handful of
/// entries) doesn't trigger a `Vec` growth reallocation at all. See the
/// note on [`encrypt_vault`]: growth reallocations only ever move 8-byte
/// `Box` pointers now, not entry contents, but avoiding them entirely
/// where cheap to do so is still strictly better than relying on that
/// mitigation alone.
pub const VAULT_MIN_RESERVED_CAPACITY: usize = 64;

/// Load and decrypt a vault, returning an empty vault (not an error) if
/// the file doesn't exist yet — this is what lets "unlock" double as
/// "create a new vault on first use" in the UI. The returned `Vec` has
/// at least [`VAULT_MIN_RESERVED_CAPACITY`] reserved.
pub fn open_or_create(path: &Path, master_password: &str) -> Result<Vec<Box<VaultEntry>>> {
    if !path.exists() {
        let mut entries = Vec::new();
        entries.reserve(VAULT_MIN_RESERVED_CAPACITY);
        return Ok(entries);
    }
    let combined = read_vault_file(path)?;
    let mut entries = decrypt_vault(master_password, &combined)?;
    if entries.capacity() - entries.len() < VAULT_MIN_RESERVED_CAPACITY {
        entries.reserve(VAULT_MIN_RESERVED_CAPACITY - (entries.capacity() - entries.len()));
    }
    Ok(entries)
}

/// Changes the vault's master password.
///
/// Callers are expected to have already verified `old_password` against
/// the file before calling this (as `main.rs` does before invoking it)
/// — this function itself also needs `old_password` for the fast path
/// below, since unwrapping the existing vault key requires it, but it
/// does not perform that verification-for-its-own-sake; a wrong
/// `old_password` here simply surfaces as the same "wrong current
/// master password" error [`crypto::rewrap_vault_key`] returns.
///
/// For the current envelope container format (`crypto::VAULT_MAGIC`),
/// this takes the fast path: unwrap the *existing* vault key with
/// `old_password`, re-wrap that same key under `new_password`, and
/// splice the new wrapped-key header onto the untouched entry bytes —
/// see [`change_master_password_fast`]. No entry is ever decrypted or
/// re-encrypted, so the cost is one Argon2id derivation plus one small
/// AES-GCM operation on a 32-byte key, independent of how many entries
/// the vault holds — O(1) instead of the previous O(entry count).
///
/// For a legacy (pre-envelope) vault there's no separable wrapped-key
/// header to rewrap — the whole blob was encrypted under one flat
/// KDF-derived key — so changing the password there necessarily
/// re-encrypts everything via [`write_vault_file`], which also upgrades
/// the file to the envelope format as a side effect, same as any other
/// save of a legacy vault would.
///
/// `entries` is only used as the expected-entry-count sanity check that
/// both paths' read-back verification compares against (see
/// [`write_and_verify_vault_bytes`]) — the fast path never touches
/// entry *contents*, decrypted or otherwise.
pub fn change_master_password(
    path: &Path,
    old_password: &str,
    entries: &[Box<VaultEntry>],
    new_password: &str,
    kdf_id: u8,
) -> Result<()> {
    let combined = read_vault_file(path)?;
    let is_envelope_format = combined.len() >= 4 && &combined[0..4] == crypto::VAULT_MAGIC;

    if is_envelope_format {
        change_master_password_fast(
            path,
            &combined,
            old_password,
            new_password,
            kdf_id,
            entries.len(),
        )
    } else {
        write_vault_file(path, new_password, entries, kdf_id)
    }
}

/// Fast, O(1)-in-entry-count master password change for a vault already
/// in the envelope container format: rewrap the vault key in place and
/// splice it onto the existing entry bytes, byte-for-byte, without
/// decrypting a single entry.
///
/// `combined` is the full on-disk container (as returned by
/// `read_vault_file`) — reused from the caller rather than re-read here
/// so callers that already have it in hand (or that read it for their
/// own current-password verification, as `main.rs` does before calling
/// [`change_master_password`]) don't pay for a second disk read.
///
/// Security note: the vault key itself is unchanged by this path — only
/// the password-derived wrapping around it changes. That's safe (the
/// AES-GCM nonce/key pairing for every entry stays exactly as unique as
/// it already was, since neither the vault key nor any entry's nonce
/// changes), but it does mean this specifically does *not* protect
/// against a scenario where an attacker already recovered the old vault
/// key itself (e.g. via a memory-disclosure attack during a past
/// session) — changing the password afterwards wouldn't invalidate a
/// key that was already extracted, the way a full re-encrypt under a
/// brand-new vault key would. That's judged an acceptable, deliberate
/// trade-off for the routine "I want a stronger/different password"
/// case this function optimizes for, not a substitute for full
/// re-encryption in a suspected-compromise scenario — if a vault key
/// leak is ever suspected, use [`write_vault_file`] directly (or
/// recreate the vault) to force a fresh vault key instead.
fn change_master_password_fast(
    path: &Path,
    combined: &[u8],
    old_password: &str,
    new_password: &str,
    new_kdf_id: u8,
    expected_entry_count: usize,
) -> Result<()> {
    let body = &combined[4..];
    let (old_wrapped, header_len) =
        crypto::WrappedVaultKey::decode(body).context("invalid vault envelope header")?;
    let new_wrapped =
        crypto::rewrap_vault_key(old_password, &old_wrapped, new_password, new_kdf_id)?;
    let new_header = new_wrapped.encode();

    let mut out = Vec::with_capacity(4 + new_header.len() + (body.len() - header_len));
    out.extend_from_slice(crypto::VAULT_MAGIC);
    out.extend_from_slice(&new_header);
    // Everything after the old header — `entry_count` and every entry's
    // framing + ciphertext — is copied verbatim. None of it depends on
    // the password; it's encrypted under the (unchanged) vault key.
    out.extend_from_slice(&body[header_len..]);

    write_and_verify_vault_bytes(path, out, new_password, expected_entry_count)
}

// ---------------------------------------------------------------------
// U-05: "remember master password after lock" session cache
// ---------------------------------------------------------------------

/// How long (if at all) UNIGEN is allowed to remember a vault's master
/// password after it locks, so re-unlocking doesn't require retyping it.
/// Only ever consulted on Windows (`dpapi::SUPPORTED`) — every mode
/// behaves exactly like `Never` on any other platform, since there's no
/// non-DPAPI primitive in this app for sealing a password at rest.
///
/// This replaces what used to be a single ad hoc bool
/// (`vault_remember_session`) plus a bare `Option<Vec<u8>>`
/// (`vault_dpapi_cache`) directly on `UnigenApp` — that pairing only
/// ever implemented one specific policy ("remember across an auto-lock,
/// in memory only, for as long as this run of the app lasts") with no
/// way to ask for anything looser or stricter, and — see
/// `SessionUnlockCache`'s doc comment below — had a real gap where
/// switching to a *different* vault file didn't clear the previous
/// vault's cached password at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum RememberSession {
    /// Never cache anything. Every unlock — including the very next one
    /// right after an auto-lock — requires typing the master password
    /// again. Default: this app never remembers a credential unless the
    /// user explicitly opts in.
    #[default]
    Never,
    /// Keep a DPAPI-sealed copy of the master password in memory only,
    /// for exactly as long as this app process keeps running. Survives
    /// an auto-lock (that's the point) but never touches disk, so it
    /// cannot outlive this run of the app: closing UNIGEN, or the
    /// process dying for any other reason, destroys it as a side effect
    /// of the process's own memory going away — there is no code path
    /// here that needs to explicitly clear it for that case to hold.
    UntilAppExit,
    /// Same DPAPI-sealed blob, but also written to a small sidecar file
    /// next to the vault (see `SessionUnlockCache::sidecar_path`), so it
    /// survives restarting the app too — not just an auto-lock, but
    /// quitting UNIGEN entirely and reopening it later, without retyping
    /// the master password.
    ///
    /// CAVEAT (documented, not silently assumed away): standard
    /// per-user DPAPI (no `CRYPTPROTECT_LOCAL_MACHINE`, the only mode
    /// this app uses — see `dpapi.rs`) derives its key from the Windows
    /// user account, not from any one specific login *session* — in
    /// practice a per-user DPAPI blob can often still be unprotected
    /// after a normal logout/login (even a reboot) by the same account,
    /// which is a looser guarantee than the name "until logout" implies
    /// on its own. What *this app* actually enforces for "until logout"
    /// is narrower and fully within its control: the sidecar file this
    /// mode writes is the only thing that makes the cache outlive an app
    /// restart, and every explicit "I'm done with this" signal this app
    /// can observe — a manual "Lock" click, changing the master
    /// password, or switching to a different vault file — deletes it
    /// (see `SessionUnlockCache::clear`). Whether the OS-level DPAPI key
    /// itself also survives a full logout is up to Windows, not this
    /// app; this mode's guarantee is "gone the moment any of the above
    /// happens", not "provably destroyed at the OS level on logout".
    UntilLogout,
}

/// Owns the "remember the master password after a lock" cache for one
/// vault session: the [`RememberSession`] policy currently selected, and
/// whatever DPAPI-sealed bytes are currently cached for it (in memory,
/// and — for [`RememberSession::UntilLogout`] — on disk next to the
/// vault). All DPAPI calls and the sidecar file's path/permissions are
/// centralized here so `main.rs`'s UI code never touches `dpapi::*` or a
/// raw `Vec<u8>` directly, the same separation `vault.rs` already keeps
/// between file-format details and the UI layer for the rest of the
/// vault.
pub struct SessionUnlockCache {
    pub mode: RememberSession,
    sealed_in_memory: Option<Vec<u8>>,
}

impl SessionUnlockCache {
    pub fn new() -> Self {
        Self {
            mode: RememberSession::Never,
            sealed_in_memory: None,
        }
    }

    /// Sidecar file for `vault_path`'s cached password: same directory,
    /// same filename, with `.session-cache` appended (not inserted
    /// before the vault's own extension, so `foo.uvault` and a
    /// hypothetical `foo.uvault.session-cache.uvault` can never collide
    /// with a real vault file the OS file picker would offer to open).
    fn sidecar_path(vault_path: &Path) -> PathBuf {
        let mut os = vault_path.as_os_str().to_owned();
        os.push(".session-cache");
        PathBuf::from(os)
    }

    /// SECURITY: DPAPI's per-user protection alone does *not* tie a
    /// sealed blob to any particular vault file — without this, a
    /// `foo.uvault.session-cache` sidecar copied next to a different
    /// vault (`bar.uvault`, under the same Windows account) would happily
    /// unprotect and hand back `foo`'s cached master password while
    /// posing as `bar`'s cache. Folding this vault's own path into
    /// DPAPI's "optional entropy" closes that: `dpapi::unprotect` now
    /// fails unless the *same* vault path's entropy is supplied again,
    /// the same way a wrong Windows user account already made it fail.
    ///
    /// Canonicalizes first so the same on-disk vault reached via a
    /// symlink, a relative path, or `..` components still derives the
    /// same entropy (falls back to the given path as-is if
    /// canonicalization fails, e.g. the file doesn't exist yet at seal
    /// time — this only needs to be *consistent* between `remember()`
    /// and `recover()` for the same logical vault, not stable across
    /// every possible spelling of a path that doesn't exist).
    fn session_entropy(vault_path: &Path) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let canon = fs::canonicalize(vault_path).unwrap_or_else(|_| vault_path.to_path_buf());
        let mut hasher = Sha256::new();
        // Domain-separation prefix, distinct from the DPAPI `label`
        // string used elsewhere, so this entropy could never accidentally
        // collide with entropy derived for some unrelated future purpose
        // that also happens to hash a path.
        hasher.update(b"unigen-vault-session-entropy-v1\0");
        hasher.update(canon.to_string_lossy().as_bytes());
        hasher.finalize().into()
    }

    fn try_unprotect(sealed: &[u8], vault_path: &Path) -> Option<SecretString> {
        let mut recovered = dpapi::unprotect(sealed, &Self::session_entropy(vault_path)).ok()?;
        // `from_utf8` borrows `recovered`; build the `SecretString` from
        // that borrow *before* wiping, then wipe the now-redundant
        // plaintext `Vec<u8>` DPAPI handed back — mirroring the
        // `recovered.zeroize()` pattern the old inline call site in
        // `main.rs::unlock_vault` used.
        let out = std::str::from_utf8(&recovered)
            .ok()
            .map(SecretString::from_str);
        recovered.zeroize();
        out
    }

    /// Seal `master_password` and remember it according to `self.mode`.
    /// A no-op (beyond clearing any stale existing cache) when
    /// `self.mode == Never` or this platform has no DPAPI — callers
    /// don't need their own `if dpapi::SUPPORTED` guard.
    ///
    /// `vault_path` identifies which vault this password unlocks, both
    /// for the `UntilLogout` sidecar file's name and so a mode-`Never`
    /// or failed-seal call also cleans up any leftover cache for this
    /// specific vault (not just the in-memory copy).
    pub fn remember(&mut self, vault_path: &Path, master_password: &str) {
        if self.mode == RememberSession::Never || !dpapi::SUPPORTED {
            self.clear(Some(vault_path));
            return;
        }
        match dpapi::protect(
            master_password.as_bytes(),
            "unigen-vault-session",
            &Self::session_entropy(vault_path),
        ) {
            Ok(sealed) => {
                if self.mode == RememberSession::UntilLogout {
                    // Best-effort: a failed write here just means the
                    // "survives an app restart" convenience doesn't kick
                    // in for this vault — the in-memory copy set below
                    // still covers the UntilAppExit-equivalent
                    // auto-lock case for the rest of this run, so this
                    // is not treated as an error the user needs to see.
                    if let Ok(mut f) = crypto::create_private_file(&Self::sidecar_path(vault_path))
                    {
                        use std::io::Write;
                        let _ = f.write_all(&sealed);
                    }
                }
                self.sealed_in_memory = Some(sealed);
            }
            Err(_) => self.clear(Some(vault_path)),
        }
    }

    /// Try to recover a previously-remembered password for `vault_path`.
    /// Checks the in-memory copy first (covers "survived an auto-lock
    /// earlier this run", true for both `UntilAppExit` and
    /// `UntilLogout`), then — only for `UntilLogout` — falls back to the
    /// on-disk sidecar (covers "the app was restarted since").
    ///
    /// Returns `None` on any failure — wrong Windows account, no cache
    /// present, a tampered/corrupted sidecar file, unsupported platform,
    /// `Never` mode — never an error, because the caller's fallback is
    /// always exactly the same regardless of *why* recovery didn't work:
    /// fall through to asking the user to type the password, the same
    /// way `unlock_vault` already treats this as a bonus, not a
    /// requirement.
    pub fn recover(&mut self, vault_path: &Path) -> Option<SecretString> {
        if self.mode == RememberSession::Never || !dpapi::SUPPORTED {
            return None;
        }
        if let Some(sealed) = &self.sealed_in_memory {
            if let Some(s) = Self::try_unprotect(sealed, vault_path) {
                return Some(s);
            }
        }
        if self.mode == RememberSession::UntilLogout {
            if let Ok(sealed) = fs::read(Self::sidecar_path(vault_path)) {
                if let Some(s) = Self::try_unprotect(&sealed, vault_path) {
                    // Promote to the in-memory copy too, so a second
                    // recovery this run (e.g. another auto-lock) doesn't
                    // need to touch disk again.
                    self.sealed_in_memory = Some(sealed);
                    return Some(s);
                }
            }
        }
        None
    }

    /// Drop the in-memory cache, and — if `vault_path` is given — delete
    /// the on-disk sidecar for it too (best-effort; a failed delete just
    /// leaves a stray sealed file that a future `recover()` call for a
    /// *different* cached password would still correctly ignore, since
    /// it only ever looks for this exact vault's sidecar path).
    ///
    /// Called on every explicit "this cache should no longer apply"
    /// event: a manual "Lock" click, a successful "Change master
    /// password", switching to a different vault file, and any time
    /// `remember()`/`recover()` itself hits a failure that makes the
    /// cache untrustworthy. Deliberately *not* called on a plain
    /// auto-lock (see `RememberSession::UntilAppExit`'s doc comment —
    /// surviving exactly that case is the feature) or on ordinary app
    /// exit (the in-memory half disappears on its own when the process
    /// exits; the on-disk half, for `UntilLogout`, is supposed to
    /// survive exactly that).
    pub fn clear(&mut self, vault_path: Option<&Path>) {
        self.sealed_in_memory = None;
        if let Some(path) = vault_path {
            let _ = fs::remove_file(Self::sidecar_path(path));
        }
    }
}

impl Default for SessionUnlockCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod session_cache_tests {
    use super::*;

    fn temp_vault_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "unigen_session_cache_test_{}_{}_{}",
            tag,
            std::process::id(),
            {
                use rand::rngs::OsRng;
                use rand::RngCore;
                let mut n = [0u8; 8];
                OsRng.fill_bytes(&mut n);
                hex::encode(n)
            }
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("test.uvault")
    }

    // These first tests hold regardless of platform (they only exercise
    // the `Never`/unsupported-platform degrade path, which is exactly
    // what this non-Windows sandbox always takes) — the DPAPI-backed
    // round trip below is `#[cfg(windows)]`-only, same restriction
    // `dpapi.rs`'s own tests already have, since there's no DPAPI to
    // call into on any other OS.

    #[test]
    fn never_mode_remembers_nothing() {
        let path = temp_vault_path("never");
        let mut cache = SessionUnlockCache::new();
        assert_eq!(cache.mode, RememberSession::Never);
        cache.remember(&path, "hunter2");
        assert!(cache.recover(&path).is_none());
    }

    #[test]
    fn unsupported_platform_remembers_nothing_regardless_of_mode() {
        // On this sandbox `dpapi::SUPPORTED` is false, so every mode
        // should behave like `Never` — this is the exact guarantee
        // `RememberSession`'s doc comment makes ("every mode behaves
        // exactly like `Never` on any other platform").
        if dpapi::SUPPORTED {
            return; // this test's premise only holds off Windows
        }
        let path = temp_vault_path("unsupported");
        for mode in [RememberSession::UntilAppExit, RememberSession::UntilLogout] {
            let mut cache = SessionUnlockCache::new();
            cache.mode = mode;
            cache.remember(&path, "hunter2");
            assert!(
                cache.recover(&path).is_none(),
                "mode {mode:?} must not remember anything without DPAPI"
            );
        }
    }

    #[test]
    fn clear_removes_sidecar_file_regardless_of_platform() {
        // Exercises the file-handling half of `clear()` directly (not
        // gated on DPAPI actually having sealed anything) — write a
        // dummy sidecar by hand, at the exact path `sidecar_path`
        // derives, and confirm `clear()` deletes it.
        let path = temp_vault_path("clear");
        let sidecar = SessionUnlockCache::sidecar_path(&path);
        std::fs::write(&sidecar, b"dummy sealed bytes").unwrap();
        assert!(sidecar.exists());

        let mut cache = SessionUnlockCache::new();
        cache.clear(Some(&path));
        assert!(!sidecar.exists());
    }

    #[test]
    fn sidecar_path_is_distinct_from_vault_path() {
        let vault = Path::new("/tmp/example.uvault");
        let sidecar = SessionUnlockCache::sidecar_path(vault);
        assert_ne!(sidecar, vault);
        assert!(sidecar.to_string_lossy().ends_with(".uvault.session-cache"));
    }

    #[cfg(windows)]
    #[test]
    fn until_app_exit_survives_in_memory_but_never_touches_disk() {
        let path = temp_vault_path("app_exit");
        let mut cache = SessionUnlockCache::new();
        cache.mode = RememberSession::UntilAppExit;
        cache.remember(&path, "correct horse battery staple");

        let recovered = cache.recover(&path).expect("in-memory recovery should work");
        assert_eq!(recovered.as_str(), "correct horse battery staple");

        // The defining difference from `UntilLogout`: nothing was ever
        // written to disk for this mode.
        assert!(!SessionUnlockCache::sidecar_path(&path).exists());

        // A *fresh* cache (simulating an app restart) has nothing to
        // recover, since the previous cache only ever lived in memory.
        let mut fresh = SessionUnlockCache::new();
        fresh.mode = RememberSession::UntilAppExit;
        assert!(fresh.recover(&path).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn until_logout_survives_a_simulated_app_restart() {
        let path = temp_vault_path("logout");
        let mut cache = SessionUnlockCache::new();
        cache.mode = RememberSession::UntilLogout;
        cache.remember(&path, "correct horse battery staple");
        assert!(SessionUnlockCache::sidecar_path(&path).exists());

        // Simulate restarting the app: a brand new `SessionUnlockCache`
        // with no in-memory state, same mode, same vault path — it
        // should recover the password from the sidecar file alone.
        let mut restarted = SessionUnlockCache::new();
        restarted.mode = RememberSession::UntilLogout;
        let recovered = restarted
            .recover(&path)
            .expect("sidecar-backed recovery should work after a simulated restart");
        assert_eq!(recovered.as_str(), "correct horse battery staple");
    }

    #[cfg(windows)]
    #[test]
    fn sidecar_copied_to_a_different_vault_does_not_unlock_it() {
        // SECURITY REGRESSION TEST: this is the exact scenario the
        // `session_entropy` binding exists to prevent — copying vault
        // A's `.session-cache` sidecar next to vault B (same Windows
        // account) must not recover A's password under B's identity.
        let path_a = temp_vault_path("cross_vault_a");
        let path_b = temp_vault_path("cross_vault_b");

        let mut cache = SessionUnlockCache::new();
        cache.mode = RememberSession::UntilLogout;
        cache.remember(&path_a, "vault-a-password");
        assert!(SessionUnlockCache::sidecar_path(&path_a).exists());

        // Copy A's sealed sidecar bytes to B's sidecar path, simulating
        // an attacker (or careless user) copying the file.
        let sealed_bytes = fs::read(SessionUnlockCache::sidecar_path(&path_a)).unwrap();
        fs::write(SessionUnlockCache::sidecar_path(&path_b), &sealed_bytes).unwrap();

        let mut fresh = SessionUnlockCache::new();
        fresh.mode = RememberSession::UntilLogout;
        assert!(
            fresh.recover(&path_b).is_none(),
            "a sidecar copied from a different vault must not unprotect"
        );
    }

    #[cfg(windows)]
    #[test]
    fn clear_deletes_both_memory_and_sidecar() {
        let path = temp_vault_path("clear_full");
        let mut cache = SessionUnlockCache::new();
        cache.mode = RememberSession::UntilLogout;
        cache.remember(&path, "hunter2");
        assert!(cache.recover(&path).is_some());
        assert!(SessionUnlockCache::sidecar_path(&path).exists());

        cache.clear(Some(&path));
        assert!(!SessionUnlockCache::sidecar_path(&path).exists());

        let mut fresh = SessionUnlockCache::new();
        fresh.mode = RememberSession::UntilLogout;
        assert!(fresh.recover(&path).is_none());
    }
}

/// One row imported from another password manager's CSV export.
/// Deliberately narrower than `VaultEntry` — importers only ever produce
/// a subset of fields, and this keeps the parsing/mapping logic in one
/// place instead of scattered across call sites that build `VaultEntry`
/// directly (and would each need to remember to fill in `id`/timestamps).
#[derive(Debug)]
pub struct ImportedRow {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

// Imported rows carry plaintext passwords from another password
// manager's export until they're folded into a `VaultEntry`. This impl
// lets a caller explicitly scrub a row it's discarding (e.g. on a parse
// error, or a row a future filter step decides not to import) — it's
// deliberately *not* wired up as `Drop`, because `into_entry` below
// needs to move fields out of `self`, which Rust disallows for any type
// that implements `Drop`.
impl Zeroize for ImportedRow {
    fn zeroize(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
    }
}

impl ImportedRow {
    fn into_entry(self, id: u64) -> VaultEntry {
        let now = now_unix();
        VaultEntry {
            id,
            // `From<String> for SecretString` copies into the new
            // controlled buffer and zeroizes the source `String`'s
            // buffer afterward, so the plaintext CSV-parsed field
            // doesn't linger unzeroized once it's folded into the entry.
            title: self.title.into(),
            username: self.username.into(),
            // Seal on the way into long-term storage: once a plaintext
            // imported row becomes a real `VaultEntry` its password
            // inherits the same "encrypted at rest in RAM" treatment
            // every other entry's password gets. `String -> SecretString`
            // zeroizes the source `String`'s buffer (see the note above),
            // and `LockedSecret::seal` then consumes that `SecretString`
            // without creating any further plaintext copy.
            password: LockedSecret::seal(self.password.into()),
            url: self.url.into(),
            notes: self.notes.into(),
            created_at: now,
            updated_at: now,
        }
    }
}

/// Common CSV export column layouts from other password managers. The
/// importer sniffs the header row against these known layouts rather
/// than assuming a fixed column order, since every vendor uses different
/// column names/ordering for the same underlying fields.
#[derive(Clone, Copy, PartialEq)]
pub enum CsvSource {
    /// Chrome/Edge/Brave (Chromium-based) export: `name,url,username,password`
    Chromium,
    /// Firefox export: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged`
    Firefox,
    /// Bitwarden export: `folder,favorite,type,name,notes,fields,login_uri,login_username,login_password,login_totp`
    Bitwarden,
    /// 1Password export: `Title,Url,Username,Password,Notes,Type`
    OnePassword,
    /// KeePass (via the built-in CSV exporter) export:
    /// `"Group","Title","Username","Password","URL","Notes"`
    KeePass,
    /// Generic fallback: looks for header names containing
    /// title/name, user/login/email, pass, url/uri/site, note(s) in any
    /// order/casing, so exports this app has never seen still have a
    /// chance of importing something useful instead of failing outright.
    Generic,
}

impl CsvSource {
    pub fn label(self) -> &'static str {
        match self {
            CsvSource::Chromium => "Chrome / Edge / Brave",
            CsvSource::Firefox => "Firefox",
            CsvSource::Bitwarden => "Bitwarden",
            CsvSource::OnePassword => "1Password",
            CsvSource::KeePass => "KeePass",
            CsvSource::Generic => "Generic / auto-detect",
        }
    }

    pub const ALL: [CsvSource; 6] = [
        CsvSource::Chromium,
        CsvSource::Firefox,
        CsvSource::Bitwarden,
        CsvSource::OnePassword,
        CsvSource::KeePass,
        CsvSource::Generic,
    ];
}

/// Minimal CSV line splitter: handles double-quoted fields (with `""` as
/// an escaped quote inside a quoted field) and comma separators. Not a
/// full RFC 4180 parser (no embedded-newline-inside-quoted-field
/// support), which is a deliberate scope cut — every export format this
/// function targets writes one record per line, and pulling in a CSV
/// crate for a single-purpose importer isn't worth the extra dependency.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '"' if !in_quotes && cur.is_empty() => in_quotes = true,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    fields.push(cur);
    fields
}

/// Split raw CSV `contents` into logical records, merging together any
/// physical lines that fall *inside* a quoted field.
///
/// `split_csv_line` only ever sees one physical line at a time, so on
/// its own it can't handle exports (KeePassXC's CSV exporter is the
/// common case) that write multi-line Notes fields as a single quoted
/// field containing literal `\n` characters. Splitting purely on
/// `contents.lines()` — as this function used to — chops such a field
/// into multiple bogus "records": the remainder of the real row (and
/// whatever comes after, e.g. a `Last Modified`/`Created` timestamp
/// column KeePassXC includes) gets reinterpreted with the header's
/// column order, which is how a timestamp ends up parsed straight into
/// `title` as an orphaned entry.
///
/// This tracks the running double-quote parity across line boundaries
/// (the same "toggle on every unescaped `"`" rule `split_csv_line` uses
/// within a line — a doubled `""` toggles twice, i.e. net no-op, so it
/// stays consistent whether or not the pair straddles a line break) and
/// only closes a record once parity is even, i.e. no field is left open.
fn split_csv_records(contents: &str) -> Vec<String> {
    let mut records = Vec::new();
    let mut current = String::new();
    let mut quote_count = 0usize;

    for line in contents.lines() {
        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(line);
        quote_count += line.chars().filter(|&c| c == '"').count();

        // Even quote count => every opened field on this record has
        // also been closed, so the record is complete. Odd => we're
        // still inside a quoted field and the next physical line is a
        // continuation of the same record, not a new one.
        if quote_count % 2 == 0 {
            if !current.trim().is_empty() {
                records.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            quote_count = 0;
        }
    }
    // Leftover with an unterminated quote (malformed/truncated export):
    // still surface it rather than silently dropping data.
    if !current.trim().is_empty() {
        records.push(current);
    }
    records
}

fn header_index(header: &[String], candidates: &[&str]) -> Option<usize> {
    header.iter().position(|h| {
        let h = h.trim().to_lowercase();
        candidates.iter().any(|c| h == *c)
    })
}

/// Loosely match a header cell against a set of substrings, for the
/// `Generic` fallback layout where column names vary a lot between
/// vendors (e.g. "login", "user name", "e-mail" all mean "username").
fn header_index_contains(header: &[String], candidates: &[&str]) -> Option<usize> {
    header.iter().position(|h| {
        let h = h.trim().to_lowercase();
        candidates.iter().any(|c| h.contains(c))
    })
}

/// Parse CSV `contents` according to `source`, returning one
/// [`ImportedRow`] per data row. Rows that end up with an empty title
/// *and* empty username *and* empty password are skipped (typically
/// blank trailing lines), everything else is imported even if some
/// fields are blank, since a partially-filled entry is still more useful
/// than silently dropping it.
pub fn parse_csv(contents: &str, source: CsvSource) -> Result<Vec<ImportedRow>> {
    let mut records = split_csv_records(contents).into_iter();
    let header_line = records.next().context("CSV file is empty")?;
    let header: Vec<String> = split_csv_line(&header_line);

    let (title_i, user_i, pass_i, url_i, notes_i) = match source {
        CsvSource::Chromium => (
            header_index(&header, &["name"]),
            header_index(&header, &["username"]),
            header_index(&header, &["password"]),
            header_index(&header, &["url"]),
            None,
        ),
        CsvSource::Firefox => (
            None, // Firefox exports have no title column; derive from URL below.
            header_index(&header, &["username"]),
            header_index(&header, &["password"]),
            header_index(&header, &["url"]),
            None,
        ),
        CsvSource::Bitwarden => (
            header_index(&header, &["name"]),
            header_index(&header, &["login_username"]),
            header_index(&header, &["login_password"]),
            header_index(&header, &["login_uri"]),
            header_index(&header, &["notes"]),
        ),
        CsvSource::OnePassword => (
            header_index(&header, &["title"]),
            header_index(&header, &["username"]),
            header_index(&header, &["password"]),
            header_index(&header, &["url"]),
            header_index(&header, &["notes"]),
        ),
        CsvSource::KeePass => (
            header_index(&header, &["title"]),
            header_index(&header, &["username"]),
            header_index(&header, &["password"]),
            header_index(&header, &["url"]),
            header_index(&header, &["notes"]),
        ),
        CsvSource::Generic => (
            header_index_contains(&header, &["title", "name"]),
            header_index_contains(&header, &["user", "login", "email"]),
            header_index_contains(&header, &["pass"]),
            header_index_contains(&header, &["url", "uri", "site", "web"]),
            header_index_contains(&header, &["note"]),
        ),
    };

    if user_i.is_none() && pass_i.is_none() && url_i.is_none() {
        bail!(
            "Couldn't find recognizable username/password/url columns for the \"{}\" layout — \
             check that this is actually a {} export, or try \"Generic / auto-detect\".",
            source.label(),
            source.label()
        );
    }

    let get = |fields: &[String], idx: Option<usize>| -> String {
        idx.and_then(|i| fields.get(i)).cloned().unwrap_or_default()
    };

    // KeePass's CSV exporter includes a "Group" (folder) column with no
    // equivalent field in `VaultEntry`. Rather than silently dropping
    // that context, fold it into notes as a prefix — cheap to ignore if
    // the user doesn't care, but recoverable if they do.
    let group_i = if source == CsvSource::KeePass {
        header_index(&header, &["group"])
    } else {
        None
    };

    let mut rows = Vec::new();
    for record in records {
        if record.trim().is_empty() {
            continue;
        }
        let fields = split_csv_line(&record);
        let mut title = get(&fields, title_i);
        let username = get(&fields, user_i);
        let password = get(&fields, pass_i);
        let url = get(&fields, url_i);
        let mut notes = get(&fields, notes_i);

        if let Some(gi) = group_i {
            let raw_group = get(&fields, Some(gi));
            // KeePass's default top-level group is always literally named
            // "Root" for every entry that isn't filed into a sub-folder
            // (and nested groups export as "Root/Sub/Folder"), so a bare
            // "Root" carries no information — folding it in unconditionally
            // just prefixes every single imported entry's notes with
            // "Group: Root\n" noise. Only fold the group in when it names
            // an actual sub-folder.
            let group = raw_group.strip_prefix("Root/").unwrap_or(&raw_group);
            if !group.is_empty() && !group.eq_ignore_ascii_case("root") {
                notes = if notes.is_empty() {
                    format!("Group: {group}")
                } else {
                    format!("Group: {group}\n{notes}")
                };
            }
        }

        if title.is_empty() {
            // Firefox (and any other title-less layout) — fall back to
            // the URL's host so the entry has some human-readable label
            // instead of showing up blank in the vault list.
            title = url
                .split("://")
                .nth(1)
                .unwrap_or(&url)
                .split('/')
                .next()
                .unwrap_or(&url)
                .to_string();
        }

        if title.is_empty() && username.is_empty() && password.is_empty() {
            continue;
        }

        rows.push(ImportedRow {
            title,
            username,
            password,
            url,
            notes,
        });
    }
    Ok(rows)
}

/// Append imported rows to `entries`, assigning each a fresh unique id.
/// Returns the number of rows added. Existing entries are left untouched
/// — this never overwrites/merges by title, so accidental duplicate
/// imports are visible (and deletable) rather than silently clobbering
/// something already in the vault.
///
/// `entries` is `Vec<Box<VaultEntry>>`: each imported row is boxed
/// individually (its own stable heap allocation) before being pushed, so
/// growing this outer `Vec` — whether via this bulk import or any later
/// single `push()` elsewhere in the app — only ever copies 8-byte
/// pointers around, never `VaultEntry` contents (see the note on
/// `encrypt_vault` in this module). The `reserve()` call below is still
/// worth keeping even though it's no longer covering a passwords-in-heap
/// risk: it avoids the (cheap but non-zero) pointer-churn cost of growing
/// one push at a time for a large import.
/// # Panics
///
/// U-A07 fix: `next_id` is a `u64` derived from the current Unix
/// timestamp and bumped by one per imported row (plus extra bumps to skip
/// any collisions with existing entries). That previously relied on plain
/// `+= 1`, which under the release-profile default (`overflow-checks =
/// false`) would silently *wrap* back to `0` on overflow rather than
/// panic — and a wrapped/duplicate ID is a correctness and (if it happens
/// to collide with a differently-owned entry ID scheme in the future)
/// potential data-integrity hazard, not just a cosmetic one. Reaching
/// `u64::MAX` via a `now_unix()`-seeded counter is astronomically
/// unrealistic in practice (it would require importing more than
/// `u64::MAX - now_unix()` rows in one call), but this is
/// security/parsing-adjacent code handling untrusted import data, so it
/// uses `checked_add` and panics with a clear message rather than
/// silently wrapping into a duplicate/incorrect ID.
pub fn append_imported(entries: &mut Vec<Box<VaultEntry>>, rows: Vec<ImportedRow>) -> usize {
    let mut next_id = now_unix();
    let count = rows.len();
    entries.reserve(count);
    for row in rows {
        while entries.iter().any(|e| e.id == next_id) {
            next_id = next_id
                .checked_add(1)
                .expect("entry ID space exhausted while skipping a collision");
        }
        entries.push(Box::new(row.into_entry(next_id)));
        next_id = next_id
            .checked_add(1)
            .expect("entry ID space exhausted during import");
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "correct horse battery staple";

    fn sample_entry(id: u64, title: &str) -> Box<VaultEntry> {
        Box::new(VaultEntry {
            id,
            title: title.into(),
            username: "user@example.com".into(),
            password: LockedSecret::from_str("s3cr3t-password"),
            url: "https://example.com".into(),
            notes: "some notes".into(),
            created_at: 1,
            updated_at: 1,
        })
    }

    #[test]
    fn vault_round_trip_boxed_entries() {
        let entries = vec![sample_entry(1, "first"), sample_entry(2, "second")];
        let combined = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        let decrypted = decrypt_vault(PWD, &combined).unwrap();
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].title, "first");
        assert_eq!(decrypted[1].password.reveal(), "s3cr3t-password");
    }

    #[test]
    fn vault_wrong_password_fails() {
        let entries = vec![sample_entry(1, "only")];
        let combined = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        assert!(decrypt_vault("wrong password", &combined).is_err());
    }

    // --- Envelope key hierarchy: vault.rs container-format tests ---

    #[test]
    fn encrypt_vault_writes_the_envelope_magic() {
        let entries = vec![sample_entry(1, "only")];
        let combined = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        assert_eq!(&combined[0..4], crypto::VAULT_MAGIC);
    }

    #[test]
    fn legacy_blob_vault_still_decrypts() {
        // Reconstructs exactly what `encrypt_vault` produced *before*
        // the envelope-hierarchy rewrite: one `crypto::encrypt_blob`
        // container holding a plain JSON array of every entry, under a
        // single password-derived key — this is what a vault file saved
        // by an earlier build of the app looks like on disk today.
        // `decrypt_vault` must still read it correctly (see this
        // module's top-level "BACKWARD COMPATIBILITY" docs).
        let entries = vec![sample_entry(1, "legacy one"), sample_entry(2, "legacy two")];
        let json = serde_json::to_vec(&entries).unwrap();
        let legacy_combined = crypto::encrypt_blob(PWD, &json, crypto::KDF_ARGON2ID).unwrap();
        assert_ne!(&legacy_combined[0..4], crypto::VAULT_MAGIC);

        let decrypted = decrypt_vault(PWD, &legacy_combined).unwrap();
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].title, "legacy one");
        assert_eq!(decrypted[1].password.reveal(), "s3cr3t-password");
    }

    #[test]
    fn legacy_blob_vault_wrong_password_fails() {
        let entries = vec![sample_entry(1, "only")];
        let json = serde_json::to_vec(&entries).unwrap();
        let legacy_combined = crypto::encrypt_blob(PWD, &json, crypto::KDF_ARGON2ID).unwrap();
        assert!(decrypt_vault("wrong password", &legacy_combined).is_err());
    }

    #[test]
    fn saving_a_legacy_vault_upgrades_it_to_the_envelope_format() {
        // Read a legacy-format vault (see `legacy_blob_vault_still_decrypts`),
        // then save it again via `encrypt_vault` — the result must be the
        // new envelope format, not another legacy blob. This is the
        // "old files stay old-format until next write, new writes
        // always use the current format" migration story this module's
        // docs describe.
        let entries = vec![sample_entry(1, "only")];
        let json = serde_json::to_vec(&entries).unwrap();
        let legacy_combined = crypto::encrypt_blob(PWD, &json, crypto::KDF_ARGON2ID).unwrap();

        let decrypted = decrypt_vault(PWD, &legacy_combined).unwrap();
        let resaved = encrypt_vault(PWD, &decrypted, crypto::KDF_ARGON2ID).unwrap();
        assert_eq!(&resaved[0..4], crypto::VAULT_MAGIC);
        // And it still round-trips correctly under the new format.
        let reread = decrypt_vault(PWD, &resaved).unwrap();
        assert_eq!(reread.len(), 1);
        assert_eq!(reread[0].title, "only");
    }

    #[test]
    fn tampering_with_one_entrys_ciphertext_fails_the_whole_decrypt() {
        // Fail-closed choice, documented on `decrypt_vault_envelope`:
        // a corrupted/tampered entry aborts the whole vault decrypt
        // rather than silently dropping just that one entry.
        let entries = vec![sample_entry(1, "first"), sample_entry(2, "second")];
        let mut combined = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        let last = combined.len() - 1;
        combined[last] ^= 0xFF; // corrupts the final entry's ciphertext tag
        assert!(decrypt_vault(PWD, &combined).is_err());
    }

    #[test]
    fn absurd_entry_count_is_rejected_without_allocating() {
        // SECURITY REGRESSION TEST: a crafted vault claiming
        // `entry_count = u32::MAX` while actually containing only a
        // couple KB of real data must be rejected cleanly (an `Err`)
        // rather than attempting a multi-gigabyte `Vec::with_capacity`
        // allocation. Build a real, validly-encrypted single-entry
        // vault, then overwrite just the 4-byte `entry_count` field with
        // `u32::MAX`, leaving everything else (including the one real
        // entry's bytes) untouched.
        let entries = vec![sample_entry(1, "only")];
        let mut combined = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();

        let (_, header_len) = crypto::WrappedVaultKey::decode(&combined[4..]).unwrap();
        let entry_count_offset = 4 + header_len;
        combined[entry_count_offset..entry_count_offset + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());

        let result = decrypt_vault(PWD, &combined);
        assert!(
            result.is_err(),
            "an entry_count far exceeding the file's actual remaining bytes must be rejected"
        );
    }

    #[test]
    fn tampering_with_the_wrapped_vault_key_fails_the_whole_decrypt() {
        let entries = vec![sample_entry(1, "only")];
        let mut combined = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        // Byte 4 is the first byte after VAULT_MAGIC — inside
        // WrappedVaultKey's encoded header (kdf_id).
        combined[4] ^= 0xFF;
        assert!(decrypt_vault(PWD, &combined).is_err());
    }

    #[test]
    fn two_entries_with_identical_content_get_independent_ciphertext() {
        // Confirms distinct per-entry keys/nonces are actually in play
        // end-to-end (not just at the `crypto.rs` unit-test level):
        // encrypting two entries with the same field values but
        // different ids must not produce identical sealed bytes.
        let e1 = sample_entry(1, "same title");
        let e2 = sample_entry(2, "same title");
        let entries = vec![e1, e2];
        let combined = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        // Both entries' serialized JSON (title/username/url/notes/
        // password all identical apart from `id`) are the same length,
        // so their sealed payloads are too — just grab the two
        // fixed-size records and diff them directly instead of fully
        // reparsing the container.
        let (wrapped, header_len) =
            crypto::WrappedVaultKey::decode(&combined[4..]).unwrap();
        let _ = wrapped;
        let rest = &combined[4 + header_len..];
        let record1 = &rest[4..]; // skip entry_count; first record starts here
        let id1_len = 8 + 4 + u32::from_be_bytes(record1[8..12].try_into().unwrap()) as usize;
        let record2 = &record1[id1_len..];
        assert_ne!(record1[..id1_len], record2[..id1_len]);
        // And both still decrypt back correctly despite differing on
        // the wire.
        let decrypted = decrypt_vault(PWD, &combined).unwrap();
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].title, "same title");
        assert_eq!(decrypted[1].title, "same title");
    }

    #[test]
    fn every_encrypt_vault_call_generates_a_fresh_vault_key() {
        // Honest documentation of `encrypt_vault`'s own behavior: it
        // always calls `generate_vault_key` fresh, so two consecutive
        // calls with the *same* entries and *same* password still
        // produce completely different envelope bytes throughout — not
        // just a different wrapped-key header, but different entry
        // ciphertext too, since a new vault key means new derived entry
        // keys as well. (This is what every ordinary save — add/edit/
        // delete an entry — goes through. `change_master_password`
        // specifically no longer goes through this path for an
        // already-envelope-format vault; see
        // `change_master_password_preserves_entry_ciphertext_and_vault_key`
        // below for the fast path's very different, deliberate
        // behavior.)
        let entries = vec![sample_entry(1, "only")];
        let combined1 = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        let combined2 = encrypt_vault(PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        assert_ne!(combined1, combined2);

        // Both still decrypt to the same plaintext, of course — this
        // test is about ciphertext bytes, not correctness.
        let d1 = decrypt_vault(PWD, &combined1).unwrap();
        let d2 = decrypt_vault(PWD, &combined2).unwrap();
        assert_eq!(d1[0].title, d2[0].title);
        assert_eq!(d1[0].password.reveal(), d2[0].password.reveal());
    }

    #[test]
    fn change_master_password_preserves_entry_ciphertext_and_vault_key() {
        // SECURITY/PERFORMANCE REGRESSION TEST for the fast rewrap-only
        // password change path: for an envelope-format vault,
        // `change_master_password` must leave every entry's ciphertext
        // byte-for-byte untouched (only the small wrapped-key header at
        // the front changes) — this is both what makes the change O(1)
        // in entry count instead of O(n), and a check that the fast path
        // didn't accidentally regenerate the vault key (which would
        // silently make it O(n) again, just via a different code path).
        let dir = std::env::temp_dir().join(format!(
            "unigen_vault_pwdchange_test_{}_{}",
            std::process::id(),
            {
                use rand::rngs::OsRng;
                use rand::RngCore;
                let mut n = [0u8; 8];
                OsRng.fill_bytes(&mut n);
                u64::from_le_bytes(n)
            }
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.uvault");

        let entries = vec![sample_entry(1, "first"), sample_entry(2, "second")];
        write_vault_file(&path, PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        let before = read_vault_file(&path).unwrap();

        change_master_password(&path, PWD, &entries, "a completely different password!", crypto::KDF_ARGON2ID)
            .unwrap();
        let after = read_vault_file(&path).unwrap();

        assert_ne!(before, after, "the wrapped-key header must change");

        let (_, before_header_len) = crypto::WrappedVaultKey::decode(&before[4..]).unwrap();
        let (_, after_header_len) = crypto::WrappedVaultKey::decode(&after[4..]).unwrap();
        assert_eq!(
            &before[4 + before_header_len..],
            &after[4 + after_header_len..],
            "entry_count and every entry's bytes must be byte-for-byte identical — the fast \
             path must never touch entry ciphertext"
        );

        // And it still decrypts correctly under the *new* password, with
        // the same plaintext as before.
        let decrypted = decrypt_vault("a completely different password!", &after).unwrap();
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].title, "first");
        assert_eq!(decrypted[1].title, "second");

        // The *old* password must no longer work.
        assert!(decrypt_vault(PWD, &after).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn change_master_password_fails_closed_on_wrong_old_password() {
        let dir = std::env::temp_dir().join(format!(
            "unigen_vault_pwdchange_wrong_test_{}_{}",
            std::process::id(),
            {
                use rand::rngs::OsRng;
                use rand::RngCore;
                let mut n = [0u8; 8];
                OsRng.fill_bytes(&mut n);
                u64::from_le_bytes(n)
            }
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.uvault");

        let entries = vec![sample_entry(1, "only")];
        write_vault_file(&path, PWD, &entries, crypto::KDF_ARGON2ID).unwrap();
        let before = read_vault_file(&path).unwrap();

        let result = change_master_password(
            &path,
            "definitely the wrong password",
            &entries,
            "new password",
            crypto::KDF_ARGON2ID,
        );
        assert!(result.is_err());

        // And the file on disk must be completely untouched by the
        // failed attempt.
        let after = read_vault_file(&path).unwrap();
        assert_eq!(before, after);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_or_create_reserves_minimum_capacity_for_new_vault() {
        let dir = std::env::temp_dir().join(format!(
            "unigen_vault_test_{}_{}",
            std::process::id(),
            {
                use rand::rngs::OsRng;
                use rand::RngCore;
                let mut n = [0u8; 8];
                OsRng.fill_bytes(&mut n);
                hex::encode(n)
            }
        ));
        let path = dir.join("nonexistent.vault");
        let entries = open_or_create(&path, PWD).unwrap();
        assert!(entries.is_empty());
        assert!(entries.capacity() >= VAULT_MIN_RESERVED_CAPACITY);
    }

    #[test]
    fn open_or_create_reserves_minimum_capacity_after_loading_existing_vault() {
        let dir = std::env::temp_dir().join(format!(
            "unigen_vault_test2_{}_{}",
            std::process::id(),
            {
                use rand::rngs::OsRng;
                use rand::RngCore;
                let mut n = [0u8; 8];
                OsRng.fill_bytes(&mut n);
                hex::encode(n)
            }
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("existing.vault");

        let entries = vec![sample_entry(1, "seed")];
        write_vault_file(&path, PWD, &entries, crypto::KDF_ARGON2ID).unwrap();

        let loaded = open_or_create(&path, PWD).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.capacity() - loaded.len() >= VAULT_MIN_RESERVED_CAPACITY);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_imported_assigns_unique_ids_and_reserves_capacity() {
        let mut entries: Vec<Box<VaultEntry>> = Vec::new();
        let rows = vec![
            ImportedRow {
                title: "a".to_string(),
                username: "ua".to_string(),
                password: "pa".to_string(),
                url: "".to_string(),
                notes: "".to_string(),
            },
            ImportedRow {
                title: "b".to_string(),
                username: "ub".to_string(),
                password: "pb".to_string(),
                url: "".to_string(),
                notes: "".to_string(),
            },
        ];
        let added = append_imported(&mut entries, rows);
        assert_eq!(added, 2);
        assert_eq!(entries.len(), 2);
        assert_ne!(entries[0].id, entries[1].id);
        assert!(entries.capacity() >= 2);
    }

    #[test]
    fn keepass_csv_with_singleline_notes_parses_one_row_per_entry() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n\
                    \"Root\",\"Bank\",\"alice\",\"hunter2\",\"https://bank.example\",\"plain note\"\n\
                    \"Root\",\"Email\",\"bob\",\"swordfish\",\"https://mail.example\",\"another note\"\n";
        let rows = parse_csv(csv, CsvSource::KeePass).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].title, "Bank");
        assert_eq!(rows[1].title, "Email");
    }

    /// Reproduces the "orphaned timestamp entries" bug: KeePassXC's CSV
    /// exporter writes multi-line Notes as a single quoted field
    /// containing literal newlines, plus a trailing timestamp-like
    /// column. Splitting records purely by `contents.lines()` used to
    /// chop that field apart, producing a bogus extra row whose `title`
    /// ended up being the timestamp column's value.
    #[test]
    fn keepass_csv_with_multiline_notes_does_not_produce_orphaned_rows() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"Last Modified\"\n\
                    \"Root\",\"Recovery codes\",\"alice\",\"hunter2\",\"https://example.com\",\"line one\nline two\nline three\",\"2024-01-02 03:04:05\"\n\
                    \"Root\",\"Email\",\"bob\",\"swordfish\",\"https://mail.example\",\"no newline here\",\"2024-02-03 04:05:06\"\n";

        let rows = parse_csv(csv, CsvSource::KeePass).unwrap();

        // Exactly two real entries — no extra row spawned from the
        // second half of the multi-line note / the timestamp column.
        assert_eq!(rows.len(), 2, "unexpected rows: {:#?}", rows);

        assert_eq!(rows[0].title, "Recovery codes");
        assert_eq!(rows[0].notes, "line one\nline two\nline three");

        assert_eq!(rows[1].title, "Email");
        assert_eq!(rows[1].notes, "no newline here");

        // Nothing that looks like the bare timestamp should have leaked
        // into a title on its own.
        assert!(rows.iter().all(|r| r.title != "2024-01-02 03:04:05"));
    }

    /// A bare "Root" group (KeePass's unavoidable default for every
    /// top-level entry) carries no information and must not be folded
    /// into notes. An actual sub-folder — exported as "Root/Sub" — does
    /// carry information and should show up, with the redundant "Root/"
    /// prefix stripped.
    #[test]
    fn keepass_csv_root_group_is_not_folded_into_notes_but_subfolders_are() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\"\n\
                    \"Root\",\"Top-level entry\",\"alice\",\"hunter2\",\"\",\"\"\n\
                    \"Root/Banking\",\"Sub-folder entry\",\"bob\",\"swordfish\",\"\",\"existing note\"\n";

        let rows = parse_csv(csv, CsvSource::KeePass).unwrap();
        assert_eq!(rows.len(), 2);

        assert_eq!(rows[0].title, "Top-level entry");
        assert_eq!(rows[0].notes, "");

        assert_eq!(rows[1].title, "Sub-folder entry");
        assert_eq!(rows[1].notes, "Group: Banking\nexisting note");
    }

    #[test]
    fn split_csv_records_merges_embedded_newlines() {
        let contents = "a,\"b\nc\",d\ne,f,g\n";
        let records = split_csv_records(contents);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], "a,\"b\nc\",d");
        assert_eq!(records[1], "e,f,g");
    }
}

#[cfg(test)]
mod repro_tests {
    use super::*;

    #[test]
    fn vault_round_trip_many_entries() {
        let pwd = "correct horse battery staple";
        let mut entries: Vec<Box<VaultEntry>> = Vec::new();
        for i in 0..500u64 {
            entries.push(Box::new(VaultEntry {
                id: i,
                title: format!("title-{i}").as_str().into(),
                username: format!("user-{i}").as_str().into(),
                password: LockedSecret::from_str(&format!("password-{i}-xxxxxxxxxxxxxxxxxxxx")),
                url: format!("https://example.com/{i}").as_str().into(),
                notes: "some notes here for padding".into(),
                created_at: 1,
                updated_at: 1,
            }));
        }
        let combined = encrypt_vault(pwd, &entries, crypto::KDF_ARGON2ID).unwrap();
        eprintln!("combined len = {}", combined.len());
        let decrypted = decrypt_vault(pwd, &combined).unwrap();
        assert_eq!(decrypted.len(), 500);

        // Now simulate write+read via file, like the app does (base64 text).
        let dir = std::env::temp_dir().join(format!("unigen_repro_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("many.vault");
        write_vault_file(&path, pwd, &entries, crypto::KDF_ARGON2ID).unwrap();

        let loaded = open_or_create(&path, pwd).unwrap();
        assert_eq!(loaded.len(), 500);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
