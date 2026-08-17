//! Encryption core: AES-256-GCM with Argon2id (preferred) or PBKDF2-HMAC-SHA256
//! (legacy/fallback) key derivation.
//!
//! Format notes (see README "Security notes" for the audit trail this
//! addresses):
//!
//! * HIGH-1 fix: both the small-file "blob" container and the streaming
//!   container now bind an AAD (Associated Authenticated Data) into every
//!   AES-GCM call. The AAD is `MAGIC || FORMAT_VERSION || kdf_id` (streaming
//!   additionally folds in the chunk counter + final-chunk flag, as the
//!   Python original already did for streaming). This cryptographically
//!   ties a ciphertext to its format/version/KDF, so a blob can't be
//!   silently swapped for a different-context ciphertext without the
//!   authentication tag failing to verify.
//! * Passphrases are zeroized (via the `zeroize` crate) the moment they are
//!   no longer needed — something the Python original could only
//!   best-effort approximate with `bytearray` + `ctypes` mlock, since
//!   Python has no real owned-buffer wipe-on-drop primitive. Rust's
//!   `Zeroizing<Vec<u8>>` guarantees the wipe runs via `Drop`, even on an
//!   early return or a `?`-propagated error.
//! * This is a NEW container format (magic bytes below), not
//!   byte-compatible with the original Python app's `.enc` files. That is
//!   intentional: the old format's biggest issue (HIGH-1) is a wire-format
//!   problem, not something fixable while staying byte-compatible.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// ---- KDF identifiers -------------------------------------------------
pub const KDF_PBKDF2: u8 = 1;
pub const KDF_ARGON2ID: u8 = 2;

/// Argon2id is the preferred/default KDF for all new encryptions (OWASP
/// baseline: 64 MiB memory, 3 iterations, 4 lanes). PBKDF2-HMAC-SHA256 is kept
/// only so this app can still decrypt files it produced before Argon2id
/// support existed, or as an explicit user override.
pub const DEFAULT_KDF: u8 = KDF_ARGON2ID;

pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const ARGON2_TIME_COST: u32 = 3;
pub const ARGON2_LANES: u32 = 4;
pub const PBKDF2_ITERATIONS: u32 = 600_000;

pub const MAX_PASSPHRASE_LEN: usize = 1024;
pub const MIN_PASSPHRASE_LEN: usize = 8;

// ---- Container formats -------------------------------------------------
pub const BLOB_MAGIC: &[u8; 4] = b"UGR1";
pub const STREAM_MAGIC: &[u8; 4] = b"UGRS";
// MEDIUM-1 fix bumped this from 1 -> 2: the streaming container's
// base_nonce shrank from 8 to 4 random bytes (freeing a full 8-byte,
// non-truncated chunk counter) to eliminate a nonce-reuse risk on very
// large files. Blob format (encrypt_blob/decrypt_blob) is unaffected by
// this bump but shares the constant, so its on-disk layout is unchanged.
pub const FORMAT_VERSION: u8 = 2;

pub const STREAM_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB plaintext/chunk
pub const STREAM_SIZE_THRESHOLD: u64 = 20 * 1024 * 1024; // switch above 20 MiB

// MEDIUM-2 fix: encrypt_blob/decrypt_blob load their entire input into
// memory (that's the whole point of the "small file" path — the streaming
// path exists precisely for anything bigger). Without a cap, decrypt_blob
// on an attacker-supplied or accidentally-huge file is an easy memory-DoS:
// the file gets read fully into a Vec before any crypto check happens.
// This is a generous ceiling for the intended use case (small text/password
// files, clipboard contents) while still bounding worst-case memory use.
pub const MAX_BLOB_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

pub fn kdf_name(id: u8) -> &'static str {
    match id {
        KDF_ARGON2ID => "Argon2id",
        KDF_PBKDF2 => "PBKDF2-HMAC-SHA256",
        _ => "unknown",
    }
}

/// Derive a 32-byte AES-256 key from a passphrase + salt using the given
/// KDF. The passphrase bytes are held in a `Zeroizing` buffer for the
/// duration and wiped on drop regardless of the return path.
///
/// NOTE on [`MIN_PASSPHRASE_LEN`]: this function deliberately does **not**
/// enforce it. `derive_key` is also the decrypt-side codepath (blob,
/// stream, and legacy-Python-format decryption all call it), and a strict
/// length floor here would make it impossible to ever decrypt a file that
/// was originally encrypted with a shorter passphrase — including files
/// from the legacy Python format, which never enforced a minimum at all.
/// The minimum is enforced instead at the *encryption* entry points
/// ([`encrypt_blob`], [`stream_encrypt_file`]), where rejecting a weak new
/// passphrase is safe because no existing ciphertext depends on it. Any
/// other caller that derives a key for a brand-new encryption (rather than
/// decrypting existing data) is responsible for checking
/// `MIN_PASSPHRASE_LEN` itself before calling in here.
fn derive_key(password: &str, salt: &[u8], kdf_id: u8) -> Result<Zeroizing<[u8; 32]>> {
    let char_count = password.chars().count();
    if char_count > MAX_PASSPHRASE_LEN {
        bail!(
            "Passphrase too long ({} chars). Maximum is {} characters.",
            char_count,
            MAX_PASSPHRASE_LEN
        );
    }
    let pwd_bytes = Zeroizing::new(password.as_bytes().to_vec());
    let mut key = Zeroizing::new([0u8; 32]);

    match kdf_id {
        KDF_ARGON2ID => {
            let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_TIME_COST, ARGON2_LANES, Some(32))
                .map_err(|e| anyhow!("invalid Argon2id parameters: {e}"))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into(&pwd_bytes, salt, key.as_mut())
                .map_err(|e| anyhow!("Argon2id key derivation failed: {e}"))?;
        }
        KDF_PBKDF2 => {
            pbkdf2_hmac::<Sha256>(&pwd_bytes, salt, PBKDF2_ITERATIONS, key.as_mut());
        }
        other => bail!("Unknown KDF id: {other}"),
    }
    Ok(key)
}

/// Enforce [`MIN_PASSPHRASE_LEN`] for a *new* encryption. Call this from
/// every encrypt entry point (never from a decrypt path — see the note on
/// `derive_key`).
fn require_min_passphrase_len(password: &str) -> Result<()> {
    let char_count = password.chars().count();
    if char_count < MIN_PASSPHRASE_LEN {
        bail!(
            "Passphrase too short ({} chars). Minimum is {} characters.",
            char_count,
            MIN_PASSPHRASE_LEN
        );
    }
    Ok(())
}

fn aead_for_key(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
}

// BUG FIX: blob_aad used to always bake in the compile-time FORMAT_VERSION
// constant. That's correct for encrypt_blob (always writes the current
// version) but wrong for decrypt_blob once FORMAT_VERSION was bumped to 2:
// a v1-encrypted blob has v1 baked into its AAD at encryption time, but
// decrypt_blob was still building the AAD with the *current* constant (2),
// so the AES-GCM auth tag would never verify for v1 files — decryption
// failed outright (not "wrong plaintext", but an authentication failure
// surfaced as "wrong passphrase or corrupted file"). Fix: pass the actual
// version byte in, sourced from FORMAT_VERSION on encrypt and from the
// file's own version field on decrypt.
fn blob_aad(kdf_id: u8, version: u8) -> [u8; 6] {
    let mut aad = [0u8; 6];
    aad[0..4].copy_from_slice(BLOB_MAGIC);
    aad[4] = version;
    aad[5] = kdf_id;
    aad
}

/// Encrypt an in-memory buffer (used for the small-file / clipboard path).
/// Returns the full container: MAGIC || VERSION || kdf_id || salt(16) ||
/// nonce(12) || ciphertext(+tag).
pub fn encrypt_blob(password: &str, data: &[u8], kdf_id: u8) -> Result<Vec<u8>> {
    require_min_passphrase_len(password)?;
    if data.len() > MAX_BLOB_SIZE {
        bail!(
            "Input too large for the in-memory blob format ({} bytes > {} MiB limit); \
             use the streaming file encryption path instead",
            data.len(),
            MAX_BLOB_SIZE / (1024 * 1024)
        );
    }
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt, kdf_id)?;
    let cipher = aead_for_key(&key);
    let aad = blob_aad(kdf_id, FORMAT_VERSION);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(nonce, Payload { msg: data, aad: &aad })
        .map_err(|_| anyhow!("encryption failed"))?;

    let mut out = Vec::with_capacity(4 + 1 + 1 + 16 + 12 + ct.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.push(FORMAT_VERSION);
    out.push(kdf_id);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Check a file's size against [`MAX_BLOB_SIZE`] *before* reading it fully
/// into memory. Callers on the blob (small-file) path should call this
/// ahead of `fs::read`, otherwise the size check inside `decrypt_blob`
/// only rejects the file *after* the DoS-relevant allocation already
/// happened.
pub fn check_blob_file_size(path: &Path) -> Result<()> {
    let len = fs::metadata(path)?.len();
    if len > MAX_BLOB_SIZE as u64 {
        bail!(
            "File too large for the in-memory blob format ({len} bytes > {} MiB limit); \
             use the streaming file encryption/decryption path instead",
            MAX_BLOB_SIZE / (1024 * 1024)
        );
    }
    Ok(())
}

/// Decrypt a container produced by [`encrypt_blob`].
pub fn decrypt_blob(password: &str, combined: &[u8]) -> Result<Vec<u8>> {
    if combined.len() > MAX_BLOB_SIZE {
        bail!(
            "File too large for the in-memory blob format ({} bytes > {} MiB limit); \
             this doesn't look like a small-file UNIGEN blob",
            combined.len(),
            MAX_BLOB_SIZE / (1024 * 1024)
        );
    }
    if combined.len() < 4 + 1 + 1 + 16 + 12 {
        bail!("Invalid file format (too short)");
    }
    if &combined[0..4] != BLOB_MAGIC {
        bail!("Not a recognized UNIGEN encrypted blob (bad magic)");
    }
    let version = combined[4];
    // v1 and v2 share the exact same blob container layout — only the
    // *streaming* format changed base_nonce size between v1 and v2 (see
    // FORMAT_VERSION doc comment), so both are accepted here.
    if version != 1 && version != FORMAT_VERSION {
        bail!("Unsupported format version: {version}");
    }
    let kdf_id = combined[5];
    let salt = &combined[6..22];
    let nonce_bytes = &combined[22..34];
    let ct = &combined[34..];

    let key = derive_key(password, salt, kdf_id)?;
    let cipher = aead_for_key(&key);
    let aad = blob_aad(kdf_id, version);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, Payload { msg: ct, aad: &aad })
        .map_err(|_| anyhow!("Decryption failed: wrong passphrase or corrupted/tampered file"))
}

// ---- Legacy Python container format (backward compatibility) ---------
// The original Tkinter app's small-file container:
//   New:    ENC_MAGIC(4=b"UG2\x00") + kdf_id(1) + salt(16) + iv(12) + ct
//   Legacy: salt(16) + iv(12) + ct   (no magic/kdf_id byte -> always PBKDF2)
// Neither variant binds an AAD (that was HIGH-1 in the audit trail this
// Rust port fixes for *new* encryptions — see module docs above). We still
// need to be able to *decrypt* files produced by the Python app, so this
// mirrors its exact byte layout and does not add the AAD check.
pub const PY_ENC_MAGIC: &[u8; 4] = b"UG2\0";

fn decrypt_legacy_python_blob(password: &str, combined: &[u8]) -> Result<Vec<u8>> {
    let (kdf_id, rest) = if combined.starts_with(PY_ENC_MAGIC) {
        if combined.len() < 4 + 1 {
            bail!("Invalid file format (too short)");
        }
        (combined[4], &combined[5..])
    } else {
        (KDF_PBKDF2, combined)
    };
    if rest.len() < 16 + 12 {
        bail!("Invalid file format (too short)");
    }
    let salt = &rest[0..16];
    let iv = &rest[16..28];
    let ct = &rest[28..];

    let key = derive_key(password, salt, kdf_id)?;
    let cipher = aead_for_key(&key);
    let nonce = Nonce::from_slice(iv);

    cipher
        .decrypt(nonce, Payload { msg: ct, aad: &[] })
        .map_err(|_| anyhow!("Decryption failed: wrong passphrase or corrupted/tampered file"))
}

/// Decrypt a container that may be in any of three formats: this port's
/// own AAD-bound format (`BLOB_MAGIC`/"UGR1", tried first since it's what
/// this app produces by default), the original Python app's post-Argon2id
/// format (`PY_ENC_MAGIC`/"UG2"), or that app's pre-Argon2id legacy format
/// (no magic, always PBKDF2). This gives full backward compatibility with
/// `.enc` files produced by the Python original, in either of its eras.
pub fn decrypt_blob_compat(password: &str, combined: &[u8]) -> Result<Vec<u8>> {
    if combined.starts_with(BLOB_MAGIC) {
        return decrypt_blob(password, combined);
    }
    decrypt_legacy_python_blob(password, combined)
}

/// Best-effort peek at the KDF a container's header claims to use, without
/// deriving any key or decrypting anything. Returns `None` for the
/// magic-less legacy Python format (its bytes are indistinguishable from
/// noise without attempting a decrypt — it's *always* PBKDF2 by
/// convention, but that's an assumption, not something read off the
/// header) so callers can tell "no KDF marker to show" apart from "shown
/// KDF is Argon2id/PBKDF2".
pub fn peek_kdf_id(combined: &[u8]) -> Option<u8> {
    if combined.starts_with(BLOB_MAGIC) && combined.len() > 5 {
        return Some(combined[5]);
    }
    if combined.starts_with(PY_ENC_MAGIC) && combined.len() > 4 {
        return Some(combined[4]);
    }
    None
}

/// True if `combined` will be (or was) decrypted via the legacy Python
/// container path in [`decrypt_blob_compat`] — i.e. it does *not* start
/// with this port's own [`BLOB_MAGIC`]. Both legacy sub-formats (with or
/// without [`PY_ENC_MAGIC`]) bind no AAD to the ciphertext (see the module
/// docs and [`decrypt_legacy_python_blob`]), so callers can use this to
/// surface a "this file's format doesn't authenticate its context" notice
/// after a successful legacy decrypt.
pub fn is_legacy_no_aad_format(combined: &[u8]) -> bool {
    !combined.starts_with(BLOB_MAGIC)
}

/// Base64-encode a blob container to ASCII text, matching the Python
/// original's on-disk `.enc` representation (and enabling the same
/// copy/paste-to-clipboard flow).
pub fn encode_blob_text(combined: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(combined)
}

/// Decode a `.enc` file's contents back to the raw container bytes. Tries
/// base64 text first (what this app and the Python original both write
/// for the small-file path); if that fails, falls back to treating the
/// content as already-raw binary, for compatibility with `.enc` files
/// written by earlier builds of this Rust port that wrote raw bytes
/// instead of base64 text.
pub fn decode_blob_text(file_contents: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let trimmed: Vec<u8> = file_contents
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed) {
        return decoded;
    }
    file_contents.to_vec()
}



// Same bug/fix as blob_aad above: version must be a parameter (sourced from
// FORMAT_VERSION on encrypt, from the file's own header byte on decrypt),
// not always the current compile-time constant, or old-version files fail
// AES-GCM authentication instead of decrypting.
fn stream_chunk_aad(kdf_id: u8, version: u8, counter: u64, is_final: bool) -> [u8; 15] {
    let mut aad = [0u8; 15];
    aad[0..4].copy_from_slice(STREAM_MAGIC);
    aad[4] = version;
    aad[5] = kdf_id;
    aad[6..14].copy_from_slice(&counter.to_be_bytes());
    aad[14] = if is_final { 1 } else { 0 };
    aad
}

/// Build a unique temp-file path alongside `final_path`.
///
/// MEDIUM-1 fix: the Python original used a plain `<output>.tmp` name. If
/// the app were ever launched from (or pointed at output paths inside) a
/// working directory that already contained unrelated `*.tmp` files
/// important to the user, a crash-cleanup or a second concurrent run could
/// collide with / clobber those files. Here every temp file gets a random
/// 64-bit suffix plus a nanosecond timestamp baked into its name
/// (`<name>.<unix_nanos>.<rand_hex>.unigen-tmp`), making an accidental
/// collision with a pre-existing unrelated temp file astronomically
/// unlikely, regardless of which directory the program is run from.
pub fn unique_tmp_path(final_path: &Path) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut rand_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut rand_bytes);
    let rand_hex = hex::encode(rand_bytes);
    let file_name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unigen_output".to_string());
    let tmp_name = format!("{file_name}.{ts}.{rand_hex}.unigen-tmp");
    final_path.with_file_name(tmp_name)
}

/// Best-effort fsync of a path's parent directory, so the directory entry
/// (not just the file's data) survives a crash right after an
/// `fs::rename`. No-op on platforms/filesystems where this isn't
/// supported (e.g. it's a documented no-op-ish operation on Windows).
fn fsync_dir(path: &Path) {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

#[cfg(unix)]
pub fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
pub fn restrict_permissions(_path: &Path) {
    // Windows: full ACL manipulation is out of scope here; the file is at
    // least written under the user's own profile/output directory.
}

pub struct Progress<'a> {
    pub callback: Box<dyn FnMut(u64, u64) + 'a>,
}

/// Chunk-encrypt `in_path` -> `out_path` without loading the whole file
/// into memory. Writes to a uniquely-named temp file first, fsyncs it,
/// then atomically renames into place, then fsyncs the parent directory —
/// so a crash mid-write can never leave a truncated/corrupt file at
/// `out_path`.
pub fn stream_encrypt_file(
    in_path: &Path,
    out_path: &Path,
    password: &str,
    kdf_id: u8,
    mut on_progress: Option<Progress<'_>>,
) -> Result<()> {
    require_min_passphrase_len(password)?;
    if in_path == out_path {
        bail!("Input and output paths must be different");
    }
    let mut salt = [0u8; 16];
    let mut base_nonce = [0u8; 4];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut base_nonce);

    let key = derive_key(password, &salt, kdf_id)?;
    let cipher = aead_for_key(&key);

    let total = fs::metadata(in_path)?.len();
    let tmp_path = unique_tmp_path(out_path);

    let result = (|| -> Result<()> {
        let fin = File::open(in_path).with_context(|| format!("opening {in_path:?}"))?;
        let mut reader = BufReader::with_capacity(STREAM_CHUNK_SIZE, fin);
        let fout = File::create(&tmp_path).with_context(|| format!("creating {tmp_path:?}"))?;
        let mut writer = BufWriter::with_capacity(STREAM_CHUNK_SIZE + 4096, fout);

        writer.write_all(STREAM_MAGIC)?;
        writer.write_all(&[FORMAT_VERSION, kdf_id])?;
        writer.write_all(&salt)?;
        writer.write_all(&base_nonce)?;

        // Wire format per chunk: [is_final:1][ct_len:4 BE][ciphertext...].
        // An explicit is_final byte (rather than "peek at the next read to
        // see if it's EOF", as the Python original did) makes the decoder
        // a simple straight-line loop with no lookahead/rewind bookkeeping.
        let mut counter: u64 = 0;
        let mut done: u64 = 0;
        let mut chunk = vec![0u8; STREAM_CHUNK_SIZE];
        let mut chunk_len = read_full(&mut reader, &mut chunk)?;

        loop {
            let mut next_chunk = vec![0u8; STREAM_CHUNK_SIZE];
            let next_len = read_full(&mut reader, &mut next_chunk)?;
            let is_final = next_len == 0;

            // MEDIUM-1 fix: previously base_nonce was 8 random bytes and the
            // remaining 4 bytes carried `counter as u32` — truncating a u64
            // counter to 32 bits. After 2^32 chunks (with a small chunk size,
            // reachable on a large file) the counter wraps and the exact
            // same 12-byte nonce gets reused under the same key, breaking
            // AES-GCM's confidentiality/integrity guarantees. Fix: shrink
            // base_nonce to 4 random bytes and give the full 64-bit counter
            // its own 8 bytes, so the nonce never repeats for the lifetime
            // of a single key (2^64 chunks is unreachable in practice).
            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..4].copy_from_slice(&base_nonce);
            nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_bytes);
            let aad = stream_chunk_aad(kdf_id, FORMAT_VERSION, counter, is_final);
            let ct = cipher
                .encrypt(
                    nonce,
                    Payload { msg: &chunk[..chunk_len], aad: &aad },
                )
                .map_err(|_| anyhow!("chunk encryption failed"))?;

            writer.write_all(&[if is_final { 1 } else { 0 }])?;
            writer.write_all(&(ct.len() as u32).to_be_bytes())?;
            writer.write_all(&ct)?;

            done += chunk_len as u64;
            if let Some(p) = on_progress.as_mut() {
                (p.callback)(done, total);
            }
            counter += 1;
            if is_final {
                break;
            }
            chunk = next_chunk;
            chunk_len = next_len;
        }

        writer.flush()?;
        writer.get_ref().sync_all()?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            fs::rename(&tmp_path, out_path)
                .with_context(|| format!("renaming {tmp_path:?} -> {out_path:?}"))?;
            fsync_dir(out_path);
            restrict_permissions(out_path);
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Reads until `buf` is full or EOF; returns the number of bytes actually
/// read (may be less than `buf.len()` only at EOF).
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

/// Chunk-decrypt `in_path` -> `out_path` (or hash/verify-only if
/// `out_path` is `None`) without loading the whole file into memory.
pub fn stream_decrypt_file(
    in_path: &Path,
    out_path: Option<&Path>,
    password: &str,
    mut on_progress: Option<Progress<'_>>,
) -> Result<()> {
    if let Some(out) = out_path {
        if in_path == out {
            bail!("Input and output paths must be different");
        }
    }

    let fin = File::open(in_path)?;
    let total = fs::metadata(in_path)?.len();
    let mut reader = BufReader::with_capacity(STREAM_CHUNK_SIZE + 4096, fin);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != STREAM_MAGIC {
        bail!("Not a streamed-format UNIGEN encrypted file");
    }
    let mut header = [0u8; 2];
    reader.read_exact(&mut header)?;
    let (version, kdf_id) = (header[0], header[1]);
    if version != 1 && version != FORMAT_VERSION {
        bail!("Unsupported format version: {version}");
    }
    // v1 wrote an 8-byte base_nonce and truncated the per-chunk counter to
    // u32; v2 (current) writes a 4-byte base_nonce and uses the full u64
    // counter (see FORMAT_VERSION doc comment). Read the size matching the
    // version so both old and new files remain decryptable.
    let base_nonce_len: usize = if version == 1 { 8 } else { 4 };
    let mut salt = [0u8; 16];
    reader.read_exact(&mut salt)?;
    let mut base_nonce = [0u8; 8];
    reader.read_exact(&mut base_nonce[..base_nonce_len])?;

    let key = derive_key(password, &salt, kdf_id)?;
    let cipher = aead_for_key(&key);

    let tmp_path = out_path.map(unique_tmp_path);
    let result = (|| -> Result<()> {
        let mut writer = match &tmp_path {
            Some(p) => Some(BufWriter::with_capacity(
                STREAM_CHUNK_SIZE + 4096,
                File::create(p)?,
            )),
            None => None,
        };

        let mut counter: u64 = 0;
        // Header already consumed from `reader`: magic (4) + version/kdf (2)
        // + salt (16) + base_nonce (base_nonce_len). Count them so `done`
        // stays in the same units as `total` (encrypted file size).
        let mut done: u64 = 4 + 2 + 16 + base_nonce_len as u64;
        loop {
            let mut final_byte = [0u8; 1];
            match reader.read_exact(&mut final_byte) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    bail!("Truncated encrypted file (missing chunk)")
                }
                Err(e) => return Err(e.into()),
            }
            let is_final = final_byte[0] == 1;

            let mut len_bytes = [0u8; 4];
            reader.read_exact(&mut len_bytes)?;
            let ct_len = u32::from_be_bytes(len_bytes) as usize;
            if ct_len < 16 || ct_len > STREAM_CHUNK_SIZE + 64 {
                bail!("Corrupted or malicious chunk length");
            }
            let mut ct = vec![0u8; ct_len];
            reader.read_exact(&mut ct)?;
            // Count encrypted bytes consumed (flag + length prefix + ciphertext)
            // so the progress numerator is in the same units as `total`
            // (the encrypted file size), letting the bar actually reach 100%.
            done += 1 + 4 + ct_len as u64;

            let mut nonce_bytes = [0u8; 12];
            if version == 1 {
                nonce_bytes[..8].copy_from_slice(&base_nonce[..8]);
                nonce_bytes[8..].copy_from_slice(&(counter as u32).to_be_bytes());
            } else {
                nonce_bytes[..4].copy_from_slice(&base_nonce[..4]);
                nonce_bytes[4..].copy_from_slice(&counter.to_be_bytes());
            }
            let nonce = Nonce::from_slice(&nonce_bytes);
            let aad = stream_chunk_aad(kdf_id, version, counter, is_final);

            let plain = cipher
                .decrypt(nonce, Payload { msg: &ct, aad: &aad })
                .map_err(|_| {
                    anyhow!("Decryption failed: wrong passphrase or corrupted/tampered file")
                })?;

            if let Some(w) = writer.as_mut() {
                w.write_all(&plain)?;
            }
            if let Some(p) = on_progress.as_mut() {
                (p.callback)(done, total);
            }

            counter += 1;
            if is_final {
                break;
            }
        }

        if let Some(w) = writer.as_mut() {
            w.flush()?;
            w.get_ref().sync_all()?;
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            if let (Some(tmp), Some(out)) = (&tmp_path, out_path) {
                fs::rename(tmp, out)?;
                fsync_dir(out);
                restrict_permissions(out);
            }
            Ok(())
        }
        Err(e) => {
            if let Some(tmp) = &tmp_path {
                let _ = fs::remove_file(tmp);
            }
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "correct horse battery staple";

    #[test]
    fn blob_round_trip_argon2id() {
        let data = b"hello world, this is a secret";
        let combined = encrypt_blob(PWD, data, KDF_ARGON2ID).unwrap();
        let plain = decrypt_blob(PWD, &combined).unwrap();
        assert_eq!(plain, data);
    }

    #[test]
    fn blob_round_trip_pbkdf2() {
        let data = b"another secret payload";
        let combined = encrypt_blob(PWD, data, KDF_PBKDF2).unwrap();
        let plain = decrypt_blob(PWD, &combined).unwrap();
        assert_eq!(plain, data);
    }

    #[test]
    fn blob_round_trip_empty_input() {
        let combined = encrypt_blob(PWD, b"", KDF_ARGON2ID).unwrap();
        let plain = decrypt_blob(PWD, &combined).unwrap();
        assert!(plain.is_empty());
    }

    #[test]
    fn blob_wrong_password_fails() {
        let combined = encrypt_blob(PWD, b"secret", KDF_ARGON2ID).unwrap();
        assert!(decrypt_blob("wrong password entirely", &combined).is_err());
    }

    #[test]
    fn blob_tampered_ciphertext_fails() {
        let mut combined = encrypt_blob(PWD, b"secret data here", KDF_ARGON2ID).unwrap();
        let last = combined.len() - 1;
        combined[last] ^= 0xFF;
        assert!(decrypt_blob(PWD, &combined).is_err());
    }

    #[test]
    fn blob_header_layout_is_stable() {
        // MAGIC(4) || VERSION(1) || kdf_id(1) || salt(16) || nonce(12) || ct(+tag)
        let combined = encrypt_blob(PWD, b"x", KDF_ARGON2ID).unwrap();
        assert_eq!(&combined[0..4], BLOB_MAGIC);
        assert_eq!(combined[4], FORMAT_VERSION);
        assert_eq!(combined[5], KDF_ARGON2ID);
        assert!(combined.len() >= 4 + 1 + 1 + 16 + 12 + 1 + 16); // + tag
    }

    #[test]
    fn blob_rejects_bad_magic() {
        let mut combined = encrypt_blob(PWD, b"x", KDF_ARGON2ID).unwrap();
        combined[0] = b'X';
        assert!(decrypt_blob(PWD, &combined).is_err());
    }

    #[test]
    fn blob_rejects_too_short() {
        assert!(decrypt_blob(PWD, b"short").is_err());
    }

    #[test]
    fn blob_rejects_oversized_input() {
        // Cheaply construct something over MAX_BLOB_SIZE without actually
        // allocating that much real data content.
        let oversized = vec![0u8; MAX_BLOB_SIZE + 1];
        assert!(decrypt_blob(PWD, &oversized).is_err());
    }

    #[test]
    fn encrypt_blob_enforces_min_passphrase_len() {
        let short = "short";
        assert!(short.len() < MIN_PASSPHRASE_LEN);
        assert!(encrypt_blob(short, b"data", KDF_ARGON2ID).is_err());
    }

    #[test]
    fn encrypt_blob_enforces_max_passphrase_len() {
        let long: String = "a".repeat(MAX_PASSPHRASE_LEN + 1);
        assert!(encrypt_blob(&long, b"data", KDF_ARGON2ID).is_err());
    }

    #[test]
    fn decrypt_blob_v1_aad_uses_stored_version_not_current_constant() {
        // Regression test for the HIGH bug documented above blob_aad:
        // decrypt must build the AAD from the version byte stored in the
        // file, not from the current FORMAT_VERSION constant, or old
        // (v1) files fail authentication even with the right passphrase.
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_bytes);
        let key = derive_key(PWD, &salt, KDF_ARGON2ID).unwrap();
        let cipher = aead_for_key(&key);
        let old_version: u8 = 1;
        let aad = blob_aad(KDF_ARGON2ID, old_version);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: b"legacy-versioned data", aad: &aad })
            .unwrap();

        let mut combined = Vec::new();
        combined.extend_from_slice(BLOB_MAGIC);
        combined.push(old_version);
        combined.push(KDF_ARGON2ID);
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ct);

        let plain = decrypt_blob(PWD, &combined).unwrap();
        assert_eq!(plain, b"legacy-versioned data");
    }

    #[test]
    fn legacy_python_format_with_magic_round_trips() {
        // New-style Python container: PY_ENC_MAGIC || kdf_id || salt(16) ||
        // iv(12) || ct, no AAD.
        let salt = [7u8; 16];
        let iv = [9u8; 12];
        let key = derive_key(PWD, &salt, KDF_PBKDF2).unwrap();
        let cipher = aead_for_key(&key);
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher
            .encrypt(nonce, Payload { msg: b"old app data", aad: &[] })
            .unwrap();

        let mut combined = Vec::new();
        combined.extend_from_slice(PY_ENC_MAGIC);
        combined.push(KDF_PBKDF2);
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&ct);

        let plain = decrypt_blob_compat(PWD, &combined).unwrap();
        assert_eq!(plain, b"old app data");
    }

    #[test]
    fn legacy_python_format_no_magic_round_trips() {
        // Oldest-style Python container: salt(16) || iv(12) || ct, always
        // PBKDF2, no magic byte, no AAD.
        let salt = [3u8; 16];
        let iv = [4u8; 12];
        let key = derive_key(PWD, &salt, KDF_PBKDF2).unwrap();
        let cipher = aead_for_key(&key);
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher
            .encrypt(nonce, Payload { msg: b"very old app data", aad: &[] })
            .unwrap();

        let mut combined = Vec::new();
        combined.extend_from_slice(&salt);
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&ct);

        let plain = decrypt_blob_compat(PWD, &combined).unwrap();
        assert_eq!(plain, b"very old app data");
    }

    #[test]
    fn blob_text_encode_decode_round_trips() {
        let combined = encrypt_blob(PWD, b"round trip via base64 text", KDF_ARGON2ID).unwrap();
        let text = encode_blob_text(&combined);
        // Should be plain base64 ASCII, not raw binary.
        assert!(text.is_ascii());
        let decoded = decode_blob_text(text.as_bytes());
        assert_eq!(decoded, combined);
    }

    #[test]
    fn decode_blob_text_falls_back_to_raw_bytes() {
        let combined = encrypt_blob(PWD, b"raw fallback", KDF_ARGON2ID).unwrap();
        // Not base64 (contains raw binary), should fall back to identity.
        let decoded = decode_blob_text(&combined);
        assert_eq!(decoded, combined);
    }

    #[test]
    fn stream_round_trip_small_file() {
        let dir = std::env::temp_dir().join(format!(
            "unigen_test_{}_{}",
            std::process::id(),
            {
                let mut n = [0u8; 8];
                OsRng.fill_bytes(&mut n);
                hex::encode(n)
            }
        ));
        fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("plain.bin");
        let enc_path = dir.join("plain.enc");
        let out_path = dir.join("plain.out");

        let payload = vec![0x42u8; STREAM_CHUNK_SIZE + 12345]; // spans 2 chunks
        fs::write(&in_path, &payload).unwrap();

        stream_encrypt_file(&in_path, &enc_path, PWD, KDF_ARGON2ID, None).unwrap();
        stream_decrypt_file(&enc_path, Some(&out_path), PWD, None).unwrap();

        let round_tripped = fs::read(&out_path).unwrap();
        assert_eq!(round_tripped, payload);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stream_wrong_password_fails() {
        let dir = std::env::temp_dir().join(format!(
            "unigen_test2_{}_{}",
            std::process::id(),
            {
                let mut n = [0u8; 8];
                OsRng.fill_bytes(&mut n);
                hex::encode(n)
            }
        ));
        fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("plain.bin");
        let enc_path = dir.join("plain.enc");

        fs::write(&in_path, b"small stream payload").unwrap();
        stream_encrypt_file(&in_path, &enc_path, PWD, KDF_ARGON2ID, None).unwrap();

        let result = stream_decrypt_file(&enc_path, None, "totally wrong password", None);
        assert!(result.is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stream_encrypt_rejects_same_in_out_path() {
        let p = std::env::temp_dir().join("unigen_same_path_test.bin");
        assert!(stream_encrypt_file(&p, &p, PWD, KDF_ARGON2ID, None).is_err());
    }

    #[test]
    fn stream_encrypt_enforces_min_passphrase_len() {
        let dir = std::env::temp_dir().join(format!(
            "unigen_test3_{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("plain.bin");
        let enc_path = dir.join("plain.enc");
        fs::write(&in_path, b"data").unwrap();
        assert!(stream_encrypt_file(&in_path, &enc_path, "short", KDF_ARGON2ID, None).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn kdf_name_covers_known_ids() {
        assert_eq!(kdf_name(KDF_ARGON2ID), "Argon2id");
        assert_eq!(kdf_name(KDF_PBKDF2), "PBKDF2-HMAC-SHA256");
        assert_eq!(kdf_name(255), "unknown");
    }
}
