//! Password-manager vault: a single encrypted file holding many named
//! credential entries, layered on top of the existing blob crypto in
//! `crypto.rs` (same AES-256-GCM container, same Argon2id/PBKDF2 KDF
//! choice, same `Zeroizing` discipline used elsewhere in this app).
//!
//! On disk a vault is just an `encrypt_blob()` container whose plaintext
//! payload is JSON (a `Vec<VaultEntry>`). Nothing here invents a new file
//! format — it reuses the one `crypto.rs` already defines, so a vault file
//! benefits from the same AAD-bound header, same size cap, and same
//! future-format-version handling as encrypted regular files.

use crate::crypto;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// A single credential record.
///
/// `password` is the only field that gets special handling in the UI
/// (masked by default, cleared from any transient copy buffers on close);
/// the whole entry is only ever kept in memory as part of the already
/// `Zeroizing`-wrapped vault, and only ever touches disk inside the
/// encrypted blob.
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Stable id so the UI can reference an entry (e.g. for edit/delete)
    /// without relying on its position in the list, which changes under
    /// sorting/filtering.
    pub id: u64,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub created_at: u64,
    pub updated_at: u64,
}


// `Vec<VaultEntry>` doesn't implement `Zeroize` itself (no blanket impl
// for `Vec<T: Zeroize>` in this crate's zeroize version), so the app wraps
// entries in `Zeroizing<Vec<VaultEntry>>` and this manual impl is what
// makes that wrapper's `Drop` actually scrub the string contents instead
// of only dropping the `Vec`'s spine.
//
// KNOWN LIMITATION: `Zeroizing`'s guarantee only covers the moment the
// wrapper itself is dropped. It does *not* intercept `Vec`'s internal
// reallocations — `push()` past capacity, or the internal shift a
// `remove()` does — which can memcpy entries (passwords included) to a
// different heap address and leave the old bytes behind, unzeroed, until
// the allocator hands that memory to something else. This is the same
// category of gap the Python prototype was retired over (see README),
// reintroduced here one level up, at the `Vec` growth/shrink level
// rather than the per-`String` level.
//
// Two mitigations are applied where the call sites live (`main.rs`):
//   - `reserve_vault_capacity()` pre-reserves room in bulk-growth paths
//     (CSV import) so many pushes in a row don't each trigger their own
//     reallocation-and-copy.
//   - `vault_delete_entry` explicitly zeroizes the *removed* entry before
//     dropping it, which is the one case this module can fully control.
// Neither mitigation closes the gap for a single `push()` that happens to
// cross capacity, or for the internal shift inside `remove()` — a full
// fix would need a custom zeroizing allocator or a `Vec` replacement
// that never moves its backing storage without scrubbing the vacated
// bytes first, which is out of scope here. Treat "no plaintext password
// ever survives a `Vec` resize" as unmet, the same honest way the
// now-retired Python prototype's README section documents its own
// best-effort-not-a-guarantee gaps.
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serialize entries to JSON and encrypt them with the same blob format
/// used for the "encrypt a small file" path elsewhere in the app.
pub fn encrypt_vault(master_password: &str, entries: &[VaultEntry], kdf_id: u8) -> Result<Vec<u8>> {
    let mut json = serde_json::to_vec(entries).context("failed to serialize vault entries")?;
    let out = crypto::encrypt_blob(master_password, &json, kdf_id);
    json.zeroize();
    out.context("failed to encrypt vault")
}

/// Decrypt and parse a vault file's contents (already read into memory by
/// the caller via [`read_vault_file`]).
pub fn decrypt_vault(master_password: &str, combined: &[u8]) -> Result<Vec<VaultEntry>> {
    let mut plaintext = crypto::decrypt_blob_compat(master_password, combined)
        .context("wrong master password, or file is not a valid vault")?;
    let entries: Vec<VaultEntry> =
        serde_json::from_slice(&plaintext).context("vault contents are not valid entry data")?;
    plaintext.zeroize();
    Ok(entries)
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
pub fn write_vault_file(
    path: &Path,
    master_password: &str,
    entries: &[VaultEntry],
    kdf_id: u8,
) -> Result<()> {
    let combined = encrypt_vault(master_password, entries, kdf_id)?;
    // Store as base64 text, matching the on-disk convention every other
    // small-file (.enc) blob in this app uses — keeps vault files
    // consistent with the rest of UNIGEN's output and diff/copy-paste
    // friendly.
    let text = crypto::encode_blob_text(&combined);
    let tmp = crypto::unique_tmp_path(path);
    crypto::write_durable(&tmp, text.as_bytes())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    crypto::replace_file(&tmp, path)
        .with_context(|| format!("failed to finalize {}", path.display()))?;
    crypto::restrict_permissions(path);
    Ok(())
}

/// Load and decrypt a vault, returning an empty vault (not an error) if
/// the file doesn't exist yet — this is what lets "unlock" double as
/// "create a new vault on first use" in the UI.
pub fn open_or_create(path: &Path, master_password: &str) -> Result<Vec<VaultEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let combined = read_vault_file(path)?;
    decrypt_vault(master_password, &combined)
}

/// Re-encrypt an already-unlocked vault's entries under a new master
/// password and KDF choice, writing them back to `path`.
///
/// Callers are expected to have already verified `old_password` (e.g. the
/// vault is currently unlocked in the UI with entries decrypted under
/// it) — this function does not itself re-check `old_password` against
/// the file, it just performs the write with the new password. Keeping
/// that verification in the caller means the UI can require the user to
/// type the *current* password once (proving they still have it) before
/// this ever runs, rather than this module silently trusting whatever
/// string it's handed.
pub fn change_master_password(
    path: &Path,
    entries: &[VaultEntry],
    new_password: &str,
    kdf_id: u8,
) -> Result<()> {
    write_vault_file(path, new_password, entries, kdf_id)
}

/// One row imported from another password manager's CSV export.
/// Deliberately narrower than `VaultEntry` — importers only ever produce
/// a subset of fields, and this keeps the parsing/mapping logic in one
/// place instead of scattered across call sites that build `VaultEntry`
/// directly (and would each need to remember to fill in `id`/timestamps).
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
            title: self.title,
            username: self.username,
            password: self.password,
            url: self.url,
            notes: self.notes,
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
    let mut lines = contents.lines();
    let header_line = lines.next().context("CSV file is empty")?;
    let header: Vec<String> = split_csv_line(header_line);

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
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv_line(line);
        let mut title = get(&fields, title_i);
        let username = get(&fields, user_i);
        let password = get(&fields, pass_i);
        let url = get(&fields, url_i);
        let mut notes = get(&fields, notes_i);

        if let Some(gi) = group_i {
            let group = get(&fields, Some(gi));
            if !group.is_empty() {
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
pub fn append_imported(entries: &mut Vec<VaultEntry>, rows: Vec<ImportedRow>) -> usize {
    let mut next_id = now_unix();
    let count = rows.len();
    // Reserve the needed capacity up front: importing N rows one push()
    // at a time can otherwise trigger several reallocate-and-copy growth
    // steps along the way, each one leaving a stale, unzeroized copy of
    // earlier entries' passwords behind on the heap (see the note on
    // `impl Zeroize for VaultEntry` above). Reserving once doesn't fully
    // close that gap — a single push crossing capacity is still possible
    // elsewhere — but it collapses "several copies" down to "at most
    // one" for the common bulk-import case.
    entries.reserve(count);
    for row in rows {
        while entries.iter().any(|e| e.id == next_id) {
            next_id += 1;
        }
        entries.push(row.into_entry(next_id));
        next_id += 1;
    }
    count
}
