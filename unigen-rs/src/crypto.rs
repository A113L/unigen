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
//! * U-01 fix (format version 3, "UGR2" in the audit spec): the header now
//!   also carries the actual KDF parameters used for that file (Argon2id
//!   memory/time/lanes, or PBKDF2 iteration count) instead of relying on
//!   whatever this build's compile-time constants currently are, and those
//!   parameters are folded into the AAD (`MAGIC || FORMAT_VERSION || kdf_id
//!   || kdf_params`) so they're tamper-evident too. See [`KdfParams`] and
//!   the `FORMAT_VERSION` doc comment for the full rationale. v1/v2 files
//!   remain fully decryptable (they didn't store params, so decrypt falls
//!   back to the legacy fixed constants for whichever KDF they used).
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
use std::fs::{self, File, OpenOptions};
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
//
// U-01 fix bumped this from 2 -> 3 ("UGR2" in the audit spec — the magic
// bytes themselves didn't change, only this version byte): both the blob
// and streaming containers now carry the actual KDF parameters used
// (Argon2id memory/time/lanes, or PBKDF2 iterations) in their header, and
// those parameters are folded into the AAD alongside kdf_id. Before this,
// `derive_key` always re-derived using whatever the *current* build's
// `ARGON2_MEMORY_KIB`/`ARGON2_TIME_COST`/`ARGON2_LANES`/`PBKDF2_ITERATIONS`
// constants happened to be — so if those defaults were ever tuned
// (upgrading the Argon2id memory cost, say), every previously-encrypted
// file would silently start being decrypted with the *new* parameters
// instead of the ones it was actually encrypted with, which for Argon2id
// means a completely different derived key (decrypt failure, reported
// confusingly as "wrong passphrase"). Storing the parameters removes that
// implicit "current build's constants" dependency and also authenticates
// them: an attacker can no longer get a victim's future re-encryption to
// silently downgrade to weaker KDF parameters by tampering with a header
// byte, since the AAD binds the params the same way it already bound
// kdf_id.
pub const FORMAT_VERSION: u8 = 3;

/// On-disk/AAD-bound KDF parameters. Interpretation depends on `kdf_id`:
/// - Argon2id: `p1` = memory (KiB), `p2` = time cost (iterations), `p3` = lanes.
/// - PBKDF2-HMAC-SHA256: `p1` = iteration count, `p2`/`p3` unused (0).
///
/// Serialized as 12 bytes: three big-endian `u32`s (`p1 || p2 || p3`).
/// Present in the header (and folded into the AAD) for [`FORMAT_VERSION`]
/// >= 3 containers. Older (v1/v2) containers don't carry this — they are
/// decrypted using the hardcoded legacy constants below, matching what a
/// v1/v2 encryptor always used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub p1: u32,
    pub p2: u32,
    pub p3: u32,
}

impl KdfParams {
    pub const ENCODED_LEN: usize = 12;

    fn to_bytes(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..4].copy_from_slice(&self.p1.to_be_bytes());
        out[4..8].copy_from_slice(&self.p2.to_be_bytes());
        out[8..12].copy_from_slice(&self.p3.to_be_bytes());
        out
    }

    fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != Self::ENCODED_LEN {
            bail!("Invalid KDF parameter block length");
        }
        Ok(Self {
            p1: u32::from_be_bytes(b[0..4].try_into().unwrap()),
            p2: u32::from_be_bytes(b[4..8].try_into().unwrap()),
            p3: u32::from_be_bytes(b[8..12].try_into().unwrap()),
        })
    }

    /// The parameters this build currently uses for *new* encryptions with
    /// the given KDF. Always written into v3+ headers at encrypt time.
    fn current_for_kdf(kdf_id: u8) -> Result<Self> {
        match kdf_id {
            KDF_ARGON2ID => Ok(Self {
                p1: ARGON2_MEMORY_KIB,
                p2: ARGON2_TIME_COST,
                p3: ARGON2_LANES,
            }),
            KDF_PBKDF2 => Ok(Self {
                p1: PBKDF2_ITERATIONS,
                p2: 0,
                p3: 0,
            }),
            other => bail!("Unknown KDF id: {other}"),
        }
    }

    /// The parameters a legacy (pre-v3) container of this KDF was always
    /// encrypted with, since v1/v2 didn't store them explicitly — they're
    /// exactly this build's compile-time constants for that KDF at the
    /// time v1/v2 support was written, and were never varied per-file.
    fn legacy_for_kdf(kdf_id: u8) -> Result<Self> {
        Self::current_for_kdf(kdf_id)
    }

    /// Sanity-bound params read off an untrusted header, before spending
    /// CPU/memory deriving a key with them. Without this an attacker who
    /// can hand this app a crafted "v3" file could set e.g. Argon2id
    /// memory to a value that exhausts RAM, or a PBKDF2 iteration count
    /// that hangs the process, before authentication ever gets checked.
    fn validate(self, kdf_id: u8) -> Result<Self> {
        match kdf_id {
            KDF_ARGON2ID => {
                if self.p1 == 0 || self.p1 > 4 * 1024 * 1024 {
                    bail!("Argon2id memory parameter out of allowed range");
                }
                if self.p2 == 0 || self.p2 > 64 {
                    bail!("Argon2id time-cost parameter out of allowed range");
                }
                if self.p3 == 0 || self.p3 > 64 {
                    bail!("Argon2id lanes parameter out of allowed range");
                }
            }
            KDF_PBKDF2 => {
                if self.p1 == 0 || self.p1 > 50_000_000 {
                    bail!("PBKDF2 iteration parameter out of allowed range");
                }
            }
            other => bail!("Unknown KDF id: {other}"),
        }
        Ok(self)
    }
}

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
///
/// NOTE on the `password: &str` parameter: `pwd_bytes` below is a fresh
/// `Zeroizing` copy of `password.as_bytes()`, so the copy this function
/// makes is wiped on return. The borrowed `&str` itself is not owned
/// here and outlives this call — this function has no way to zeroize
/// the caller's original buffer. That's fine as long as every caller
/// already holds its passphrase in a `Zeroizing<String>` (or zeroizes a
/// plain `String`/`egui` text field immediately after use, as this
/// app's UI code does everywhere it reads a passphrase) — the plaintext
/// then still gets wiped, just by the caller rather than by
/// `derive_key`. A caller that hands in a passphrase it never zeroizes
/// would leave that copy lingering regardless of anything this function
/// does.
fn derive_key(
    password: &str,
    salt: &[u8],
    kdf_id: u8,
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let char_count = password.chars().count();
    if char_count > MAX_PASSPHRASE_LEN {
        bail!(
            "Passphrase too long ({} chars). Maximum is {} characters.",
            char_count,
            MAX_PASSPHRASE_LEN
        );
    }
    let params = params.validate(kdf_id)?;
    let pwd_bytes = Zeroizing::new(password.as_bytes().to_vec());
    let mut key = Zeroizing::new([0u8; 32]);

    match kdf_id {
        KDF_ARGON2ID => {
            let argon2_params = Params::new(params.p1, params.p2, params.p3, Some(32))
                .map_err(|e| anyhow!("invalid Argon2id parameters: {e}"))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
            argon2
                .hash_password_into(&pwd_bytes, salt, key.as_mut())
                .map_err(|e| anyhow!("Argon2id key derivation failed: {e}"))?;
        }
        KDF_PBKDF2 => {
            pbkdf2_hmac::<Sha256>(&pwd_bytes, salt, params.p1, key.as_mut());
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

// U-01 fix: v3+ containers additionally fold the KDF params block into the
// AAD, so an attacker can't tamper with the header's stored Argon2id/PBKDF2
// parameters (e.g. downgrading memory/time cost, or inflating them into a
// DoS) without the AES-GCM tag failing to verify. v1/v2 have no params
// field at all, so they keep using the shorter `blob_aad` above unchanged.
fn blob_aad_v3(kdf_id: u8, version: u8, params: KdfParams) -> [u8; 6 + KdfParams::ENCODED_LEN] {
    let mut aad = [0u8; 6 + KdfParams::ENCODED_LEN];
    aad[0..4].copy_from_slice(BLOB_MAGIC);
    aad[4] = version;
    aad[5] = kdf_id;
    aad[6..].copy_from_slice(&params.to_bytes());
    aad
}

// ---------------------------------------------------------------------
// Envelope key hierarchy (master password -> KEK -> vault key -> per-entry)
// ---------------------------------------------------------------------
//
// Everything else in this file (`encrypt_blob`/`decrypt_blob`,
// `stream_encrypt_file`/`stream_decrypt_file`) derives one key straight
// from the passphrase and uses it directly as the AES-256-GCM key for
// the entire ciphertext — fine for a one-shot file, but the vault
// (`vault.rs`, a container the app keeps re-encrypting throughout its
// life as entries are added/edited/removed) benefits from an extra
// layer of indirection:
//
//   master password --KDF--> KEK --wraps--> vault key --HKDF, per id--> entry key
//
// * The **KEK** (key-encryption-key) is derived from the master
//   password exactly like every other key in this file (`derive_key`,
//   same Argon2id/PBKDF2 choice, same tunable params) — its only job is
//   to encrypt ("wrap") the vault key.
// * The **vault key** is 32 random bytes, generated once
//   (`generate_vault_key`) and never derived from anything — it *is*
//   the vault's actual key material. It's stored on disk only in
//   wrapped (KEK-encrypted) form.
// * The **entry key** for one specific `VaultEntry` is derived from the
//   vault key via a single-block HKDF-Expand keyed on that entry's own
//   stable id (`derive_entry_key`), so no two entries in the same vault
//   ever share a key, and an entry's key can't be computed without
//   knowing its id.
//
// What this buys, that a single-derived-key design doesn't:
// * **A leaked entry key doesn't reveal the vault key** (HKDF is a
//   one-way function), so a future feature that needs to hand out one
//   entry's key in isolation (e.g. a "share one credential" export)
//   wouldn't also be handing out the means to decrypt every other entry.
//   The reverse isn't true — a leaked vault key derives every entry
//   key — but that's true of any single "root" key in any hierarchy;
//   the guarantee this design adds is strictly one-directional
//   containment, not full per-entry compartmentalization.
// * **The primitives here support a cheap, re-wrap-only password
//   change** — `wrap_vault_key`/`unwrap_vault_key` operate on the vault
//   key alone, independently of any entry, so re-wrapping it under a
//   new KEK is one Argon2id/PBKDF2 run plus one small AES-GCM call,
//   regardless of vault size. **This is not yet exploited**, though: see
//   the honesty note on `vault::change_master_password` below — as
//   currently wired up, every `encrypt_vault` call (including the one
//   `change_master_password` makes) generates a brand-new vault key via
//   `generate_vault_key` and re-encrypts every entry, the same
//   whole-vault-every-save cost the flat single-derived-key design
//   this replaced always had. The format doesn't require that; the
//   call pattern just hasn't been narrowed to take advantage of it yet.
//   Flagged as a real, buildable follow-up, not a design flaw in what's
//   here — see AUDIT_PROGRESS.md's envelope-key-hierarchy entry.
//
// See `vault.rs`'s module-level docs for the on-disk container layout
// this supports (`VAULT_MAGIC`) and how `encrypt_vault`/`decrypt_vault`
// use the functions below.

/// Distinguishes the vault's own envelope container from the generic
/// small-file "blob" format (`BLOB_MAGIC`) above — the two are
/// unrelated on-disk layouts (this one has a wrapped vault key and a
/// list of independently-encrypted entries; `encrypt_blob`'s is one
/// AEAD call over one flat buffer), so giving the vault container its
/// own magic means a vault file can never be mistaken for (or accepted
/// by) the generic blob decrypt path, or vice versa, even before any
/// cryptographic check runs.
pub const VAULT_MAGIC: &[u8; 4] = b"UGV1";
pub const VAULT_ENVELOPE_VERSION: u8 = 1;

/// AAD for the vault-key-wrapping AEAD call: binds the wrap ciphertext
/// to the KDF choice/params and salt used to derive the KEK that
/// produced it, the same tamper-evidence `blob_aad_v3` gives the
/// small-file format (see U-01) — an attacker flipping a header byte
/// (say, downgrading the KDF params) makes the wrap ciphertext fail to
/// authenticate rather than silently changing what key protects it.
fn vault_wrap_aad(kdf_id: u8, params: KdfParams) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + 1 + 1 + KdfParams::ENCODED_LEN);
    aad.extend_from_slice(VAULT_MAGIC);
    aad.push(VAULT_ENVELOPE_VERSION);
    aad.push(kdf_id);
    aad.extend_from_slice(&params.to_bytes());
    aad
}

/// AAD for one entry's AEAD call: binds that entry's ciphertext to the
/// vault envelope format and to its own id, so an entry's sealed bytes
/// can't be silently moved to a different id (or a different vault
/// entirely — `VAULT_MAGIC` is folded in too) without the AES-GCM tag
/// failing to verify.
fn vault_entry_aad(entry_id: u64) -> [u8; 4 + 1 + 8] {
    let mut aad = [0u8; 4 + 1 + 8];
    aad[0..4].copy_from_slice(VAULT_MAGIC);
    aad[4] = VAULT_ENVELOPE_VERSION;
    aad[5..13].copy_from_slice(&entry_id.to_be_bytes());
    aad
}

/// Single-block HKDF-Expand (RFC 5869 §2.3) — valid whenever the caller
/// only needs one hash-length (32 bytes, for SHA-256) output: `T(1) =
/// HMAC-Hash(PRK, T(0) || info || 0x01)` with `T(0)` empty, and nothing
/// in this app ever asks `derive_entry_key` for more than 32 bytes.
/// Written by hand instead of pulling in the `hkdf` crate specifically
/// because it's this small and this narrowly used — `hmac`/`sha2` are
/// already dependencies (used by PBKDF2 above), so this adds no new
/// dependency at all, just ~6 lines using ones already present. This
/// deliberately does not implement the general multi-block Expand loop
/// (`T(2) = HMAC(PRK, T(1) || info || 0x02)`, ...): that loop would be
/// entirely untested dead code for every actual call site in this app.
fn hkdf_expand_one_block(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prk)
        .expect("HMAC-SHA256 accepts any key length, including exactly 32 bytes");
    mac.update(info);
    mac.update(&[0x01]);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Derive the AES-256 key for one specific `VaultEntry` from the vault
/// key — the "vault key -> per-entry" link of the hierarchy. `entry_id`
/// is that entry's own stable `u64` id (`VaultEntry::id`, chosen once
/// when the entry is created and never reused — see `vault.rs`), folded
/// into the HKDF `info` parameter so every entry in the same vault gets
/// an independent key, and so computing one entry's key requires
/// knowing which entry it's for.
pub fn derive_entry_key(vault_key: &[u8; 32], entry_id: u64) -> Zeroizing<[u8; 32]> {
    const INFO_LABEL: &[u8] = b"unigen-entry-v1:";
    let mut info = Vec::with_capacity(INFO_LABEL.len() + 8);
    info.extend_from_slice(INFO_LABEL);
    info.extend_from_slice(&entry_id.to_be_bytes());
    Zeroizing::new(hkdf_expand_one_block(vault_key, &info))
}

/// Fresh, random 32-byte vault key — call once when a vault is first
/// created; every subsequent open/save reuses the same vault key
/// (unwrapped via [`unwrap_vault_key`]), so entries never need
/// re-encrypting just because the master password changes.
pub fn generate_vault_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// The vault key, wrapped (AES-256-GCM-encrypted) under a KEK derived
/// from the master password — everything needed to unwrap it again
/// given the correct password, and nothing else. This is the on-disk
/// representation of the "master password -> KEK -> vault key" part of
/// the hierarchy; see [`encode`](Self::encode)/[`decode`](Self::decode)
/// for the exact byte layout `vault.rs` writes into the container
/// header.
pub struct WrappedVaultKey {
    pub kdf_id: u8,
    pub kdf_params: KdfParams,
    pub kek_salt: [u8; 16],
    wrap_nonce: [u8; 12],
    wrapped: Vec<u8>,
}

impl WrappedVaultKey {
    /// `kdf_id || kdf_params(12) || kek_salt(16) || wrap_nonce(12) ||
    /// wrapped_key_len(4, u32 BE) || wrapped_key_and_tag`. The length
    /// prefix on the last field is redundant today (AES-256-GCM over a
    /// fixed 32-byte plaintext always produces exactly 48 bytes: 32
    /// ciphertext + 16 tag) but costs 4 bytes to make `decode` robust
    /// against that assumption ever changing, the same defensive habit
    /// `stream_encrypt_file`'s chunk framing already uses for its own
    /// length-prefixed fields.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + KdfParams::ENCODED_LEN + 16 + 12 + 4 + self.wrapped.len());
        out.push(self.kdf_id);
        out.extend_from_slice(&self.kdf_params.to_bytes());
        out.extend_from_slice(&self.kek_salt);
        out.extend_from_slice(&self.wrap_nonce);
        out.extend_from_slice(&(self.wrapped.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.wrapped);
        out
    }

    /// Parse the layout `encode` writes from the front of `data`,
    /// returning the parsed header and how many bytes it consumed (so
    /// the caller — `vault.rs`'s container parser — knows where the
    /// entry list starts).
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        let fixed_len = 1 + KdfParams::ENCODED_LEN + 16 + 12 + 4;
        if data.len() < fixed_len {
            bail!("Invalid vault envelope header (too short)");
        }
        let kdf_id = data[0];
        let kdf_params = KdfParams::from_bytes(&data[1..1 + KdfParams::ENCODED_LEN])?
            .validate(kdf_id)?;
        let mut off = 1 + KdfParams::ENCODED_LEN;
        let mut kek_salt = [0u8; 16];
        kek_salt.copy_from_slice(&data[off..off + 16]);
        off += 16;
        let mut wrap_nonce = [0u8; 12];
        wrap_nonce.copy_from_slice(&data[off..off + 12]);
        off += 12;
        let wrapped_len =
            u32::from_be_bytes(data[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        if data.len() < off + wrapped_len {
            bail!("Invalid vault envelope header (truncated wrapped vault key)");
        }
        let wrapped = data[off..off + wrapped_len].to_vec();
        off += wrapped_len;
        Ok((
            Self {
                kdf_id,
                kdf_params,
                kek_salt,
                wrap_nonce,
                wrapped,
            },
            off,
        ))
    }
}

/// Wrap (encrypt) `vault_key` under a KEK derived from `master_password`.
/// Called every time `vault::encrypt_vault` runs (currently: on every
/// save, with a freshly-generated `vault_key` each time — see the
/// honesty note on `vault::change_master_password` about the
/// re-wrap-only fast path this function *could* support for password
/// changes specifically, which isn't wired up yet).
pub fn wrap_vault_key(
    master_password: &str,
    vault_key: &[u8; 32],
    kdf_id: u8,
) -> Result<WrappedVaultKey> {
    require_min_passphrase_len(master_password)?;
    let kdf_params = KdfParams::current_for_kdf(kdf_id)?;
    let mut kek_salt = [0u8; 16];
    let mut wrap_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut kek_salt);
    OsRng.fill_bytes(&mut wrap_nonce);
    let kek = derive_key(master_password, &kek_salt, kdf_id, kdf_params)?;
    let aad = vault_wrap_aad(kdf_id, kdf_params);
    let wrapped = aead_for_key(&kek)
        .encrypt(
            Nonce::from_slice(&wrap_nonce),
            Payload {
                msg: vault_key.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("failed to wrap vault key"))?;
    Ok(WrappedVaultKey {
        kdf_id,
        kdf_params,
        kek_salt,
        wrap_nonce,
        wrapped,
    })
}

/// Unwrap (decrypt) the vault key from a [`WrappedVaultKey`] using
/// `master_password`. Fails (wrong password, or a tampered/corrupted
/// header) exactly like every other decrypt entry point in this file —
/// an `Err` here is `vault::decrypt_vault`'s only signal, so it's
/// reported the same way as any other "wrong master password" case.
pub fn unwrap_vault_key(
    master_password: &str,
    wrapped: &WrappedVaultKey,
) -> Result<Zeroizing<[u8; 32]>> {
    let kek = derive_key(
        master_password,
        &wrapped.kek_salt,
        wrapped.kdf_id,
        wrapped.kdf_params,
    )?;
    let aad = vault_wrap_aad(wrapped.kdf_id, wrapped.kdf_params);
    let pt = aead_for_key(&kek)
        .decrypt(
            Nonce::from_slice(&wrapped.wrap_nonce),
            Payload {
                msg: &wrapped.wrapped,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("wrong master password, or vault key could not be unwrapped"))?;
    if pt.len() != 32 {
        bail!("unwrapped vault key has unexpected length ({} bytes)", pt.len());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&pt);
    Ok(key)
}

/// Encrypt one entry's already-serialized JSON payload under its own
/// derived entry key (see [`derive_entry_key`]). Returns `nonce(12) ||
/// ciphertext+tag` — `vault.rs` additionally length-prefixes this before
/// writing it into the container, since ciphertext length varies per
/// entry.
pub fn encrypt_entry_payload(vault_key: &[u8; 32], entry_id: u64, plaintext: &[u8]) -> Vec<u8> {
    let entry_key = derive_entry_key(vault_key, entry_id);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let aad = vault_entry_aad(entry_id);
    // AES-256-GCM only fails to encrypt on a key/nonce-length mismatch,
    // neither of which can happen here (both are fixed-size arrays) —
    // `expect` rather than propagating a `Result` keeps every call site
    // in `vault.rs` from having to handle an error case that can't
    // actually occur, the same reasoning `aead_for_key`'s other callers
    // already rely on implicitly.
    let ct = aead_for_key(&entry_key)
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("AES-256-GCM encryption with fixed-size key/nonce cannot fail");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt one entry's sealed payload (as produced by
/// [`encrypt_entry_payload`]) back to its serialized JSON, given the
/// vault key and the entry's id. Fails (bad key — i.e. a corrupted or
/// tampered vault key/entry — or a tampered/truncated `sealed` buffer)
/// the same way every other decrypt call in this file does: an opaque
/// `Err`, since AES-GCM authentication failure can't distinguish
/// "wrong key" from "tampered ciphertext" and shouldn't try to.
pub fn decrypt_entry_payload(
    vault_key: &[u8; 32],
    entry_id: u64,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 12 {
        bail!("Invalid vault entry (too short)");
    }
    let (nonce_bytes, ct) = sealed.split_at(12);
    let entry_key = derive_entry_key(vault_key, entry_id);
    let aad = vault_entry_aad(entry_id);
    let pt = aead_for_key(&entry_key)
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload { msg: ct, aad: &aad },
        )
        .map_err(|_| anyhow!("failed to decrypt vault entry {entry_id} (tampered or corrupted)"))?;
    Ok(Zeroizing::new(pt))
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

    let params = KdfParams::current_for_kdf(kdf_id)?;
    let key = derive_key(password, &salt, kdf_id, params)?;
    let cipher = aead_for_key(&key);
    let aad = blob_aad_v3(kdf_id, FORMAT_VERSION, params);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: data,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;

    let mut out = Vec::with_capacity(
        4 + 1 + 1 + KdfParams::ENCODED_LEN + 16 + 12 + ct.len(),
    );
    out.extend_from_slice(BLOB_MAGIC);
    out.push(FORMAT_VERSION);
    out.push(kdf_id);
    out.extend_from_slice(&params.to_bytes());
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
    // FORMAT_VERSION doc comment). v3 (U-01 fix) inserts a 12-byte KDF
    // params block between kdf_id and salt, so it's parsed separately.
    let kdf_id = combined[5];
    if version == 1 || version == 2 {
        if combined.len() < 4 + 1 + 1 + 16 + 12 {
            bail!("Invalid file format (too short)");
        }
        let salt = &combined[6..22];
        let nonce_bytes = &combined[22..34];
        let ct = &combined[34..];

        let params = KdfParams::legacy_for_kdf(kdf_id)?;
        let key = derive_key(password, salt, kdf_id, params)?;
        let cipher = aead_for_key(&key);
        let aad = blob_aad(kdf_id, version);
        let nonce = Nonce::from_slice(nonce_bytes);

        return cipher
            .decrypt(nonce, Payload { msg: ct, aad: &aad })
            .map_err(|_| {
                anyhow!("Decryption failed: wrong passphrase or corrupted/tampered file")
            });
    }
    if version != FORMAT_VERSION {
        bail!("Unsupported format version: {version}");
    }
    let header_len = 4 + 1 + 1 + KdfParams::ENCODED_LEN + 16 + 12;
    if combined.len() < header_len {
        bail!("Invalid file format (too short)");
    }
    let params_start = 6;
    let params = KdfParams::from_bytes(&combined[params_start..params_start + KdfParams::ENCODED_LEN])?;
    let salt_start = params_start + KdfParams::ENCODED_LEN;
    let salt = &combined[salt_start..salt_start + 16];
    let nonce_start = salt_start + 16;
    let nonce_bytes = &combined[nonce_start..nonce_start + 12];
    let ct = &combined[nonce_start + 12..];

    let key = derive_key(password, salt, kdf_id, params)?;
    let cipher = aead_for_key(&key);
    let aad = blob_aad_v3(kdf_id, version, params);
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

    let params = KdfParams::legacy_for_kdf(kdf_id)?;
    let key = derive_key(password, salt, kdf_id, params)?;
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

// U-01 fix: v3+ streaming containers fold the KDF params block into every
// chunk's AAD too (not just the blob format's), for the same tamper-proofing
// reason given at `blob_aad_v3`.
fn stream_chunk_aad_v3(
    kdf_id: u8,
    version: u8,
    params: KdfParams,
    counter: u64,
    is_final: bool,
) -> [u8; 15 + KdfParams::ENCODED_LEN] {
    let mut aad = [0u8; 15 + KdfParams::ENCODED_LEN];
    aad[0..4].copy_from_slice(STREAM_MAGIC);
    aad[4] = version;
    aad[5] = kdf_id;
    aad[6..14].copy_from_slice(&counter.to_be_bytes());
    aad[14] = if is_final { 1 } else { 0 };
    aad[15..].copy_from_slice(&params.to_bytes());
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

/// Create a new private temporary/output file.
///
/// On Unix the file is created with mode 0600 from the moment it exists, so
/// plaintext is never briefly exposed with the process umask's default mode.
/// `create_new(true)` also prevents a rare temporary-name collision from
/// truncating an unrelated file. On Windows the file inherits the ACL of its
/// containing directory; the important invariant there is that we never
/// overwrite an existing path during temporary-file creation.
pub fn create_private_file(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new().write(true).create_new(true).open(path)
    }
}

/// Write a file and force its contents to stable storage before it can be renamed.
/// The temporary file is private from creation time.
pub fn write_durable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = create_private_file(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

/// Atomically (best-effort) replace `dest` with `tmp`.
///
/// Atomically replace `dest` with `tmp` where the platform provides the
/// required primitive. On Windows this uses MoveFileExW with
/// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH. If that primitive
/// fails, return the OS error rather than deleting the existing destination.
/// A safe failure is preferable to a remove-then-rename data-loss window.
pub fn replace_file(tmp: &Path, dest: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

        extern "system" {
            fn MoveFileExW(
                lpexistingfilename: *const u16,
                lpnewfilename: *const u16,
                dwflags: u32,
            ) -> i32;
        }

        fn wide(p: &Path) -> Vec<u16> {
            p.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }

        let tmp_w = wide(tmp);
        let dest_w = wide(dest);
        let ok = unsafe {
            MoveFileExW(
                tmp_w.as_ptr(),
                dest_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error())
    }
    #[cfg(not(windows))]
    {
        fs::rename(tmp, dest)
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

    let params = KdfParams::current_for_kdf(kdf_id)?;
    let key = derive_key(password, &salt, kdf_id, params)?;
    let cipher = aead_for_key(&key);

    let total = fs::metadata(in_path)?.len();
    let tmp_path = unique_tmp_path(out_path);

    let result = (|| -> Result<()> {
        let fin = File::open(in_path).with_context(|| format!("opening {in_path:?}"))?;
        let mut reader = BufReader::with_capacity(STREAM_CHUNK_SIZE, fin);
        let fout = create_private_file(&tmp_path)
            .with_context(|| format!("creating private temporary file {tmp_path:?}"))?;
        let mut writer = BufWriter::with_capacity(STREAM_CHUNK_SIZE + 4096, fout);

        writer.write_all(STREAM_MAGIC)?;
        writer.write_all(&[FORMAT_VERSION, kdf_id])?;
        writer.write_all(&params.to_bytes())?;
        writer.write_all(&salt)?;
        writer.write_all(&base_nonce)?;

        // Wire format per chunk: [is_final:1][ct_len:4 BE][ciphertext...].
        // An explicit is_final byte (rather than "peek at the next read to
        // see if it's EOF", as the Python original did) makes the decoder
        // a simple straight-line loop with no lookahead/rewind bookkeeping.
        // MEMORY-RESIDUE fix: plaintext chunks read from disk are held in
        // `Zeroizing<Vec<u8>>` rather than a bare `Vec<u8>`. A bare `Vec`
        // dropped here (whether via the `chunk = next_chunk` reassignment
        // below, an early `?` return, or falling off the end of this
        // closure) is freed without its contents being wiped — for a
        // large file that's up to `STREAM_CHUNK_SIZE` (4 MiB) of plaintext
        // per in-flight buffer sitting unzeroized in freed heap memory.
        // `Zeroizing`'s `Drop` closes that on every one of those exit
        // paths, not just the happy path.
        let mut counter: u64 = 0;
        let mut done: u64 = 0;
        let mut chunk: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; STREAM_CHUNK_SIZE]);
        let mut chunk_len = read_full(&mut reader, &mut chunk)?;

        loop {
            let mut next_chunk: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; STREAM_CHUNK_SIZE]);
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
            let aad = stream_chunk_aad_v3(kdf_id, FORMAT_VERSION, params, counter, is_final);
            let ct = cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: &chunk[..chunk_len],
                        aad: &aad,
                    },
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
            replace_file(&tmp_path, out_path)
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
    if version != 1 && version != 2 && version != FORMAT_VERSION {
        bail!("Unsupported format version: {version}");
    }
    // v1 wrote an 8-byte base_nonce and truncated the per-chunk counter to
    // u32; v2/v3 write a 4-byte base_nonce and use the full u64 counter
    // (see FORMAT_VERSION doc comment). Read the size matching the version
    // so old, new, and current files all remain decryptable.
    let base_nonce_len: usize = if version == 1 { 8 } else { 4 };
    // v3 (U-01 fix) inserts a 12-byte KDF params block right after the
    // version/kdf_id header bytes; v1/v2 have no such field and always
    // used this build's legacy compile-time constants for that KDF.
    let params_len: usize = if version >= 3 { KdfParams::ENCODED_LEN } else { 0 };
    let params = if version >= 3 {
        let mut buf = [0u8; KdfParams::ENCODED_LEN];
        reader.read_exact(&mut buf)?;
        KdfParams::from_bytes(&buf)?
    } else {
        KdfParams::legacy_for_kdf(kdf_id)?
    };
    let mut salt = [0u8; 16];
    reader.read_exact(&mut salt)?;
    let mut base_nonce = [0u8; 8];
    reader.read_exact(&mut base_nonce[..base_nonce_len])?;

    let key = derive_key(password, &salt, kdf_id, params)?;
    let cipher = aead_for_key(&key);

    let tmp_path = out_path.map(unique_tmp_path);
    let result = (|| -> Result<()> {
        let mut writer = match &tmp_path {
            Some(p) => Some(BufWriter::with_capacity(
                STREAM_CHUNK_SIZE + 4096,
                create_private_file(p)?,
            )),
            None => None,
        };

        let mut counter: u64 = 0;
        // Header already consumed from `reader`: magic (4) + version/kdf (2)
        // + salt (16) + base_nonce (base_nonce_len). Count them so `done`
        // stays in the same units as `total` (encrypted file size).
        let mut done: u64 = 4 + 2 + params_len as u64 + 16 + base_nonce_len as u64;
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
            if !(16..=STREAM_CHUNK_SIZE + 64).contains(&ct_len) {
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
            let aad = if version >= 3 {
                stream_chunk_aad_v3(kdf_id, version, params, counter, is_final).to_vec()
            } else {
                stream_chunk_aad(kdf_id, version, counter, is_final).to_vec()
            };

            // MEMORY-RESIDUE fix: each decrypted chunk is plaintext file
            // content — wrap it so it's zeroized on drop at the end of
            // this loop iteration (or on an early `?` return from a
            // later chunk) instead of being freed as-is, same rationale
            // as the `chunk`/`next_chunk` buffers in `stream_encrypt_file`.
            let plain = Zeroizing::new(
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: &ct,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        anyhow!("Decryption failed: wrong passphrase or corrupted/tampered file")
                    })?,
            );

            if let Some(w) = writer.as_mut() {
                w.write_all(&plain)?;
            }
            if let Some(p) = on_progress.as_mut() {
                (p.callback)(done, total);
            }

            counter += 1;
            if is_final {
                // The final chunk must actually be the end of the stream.
                // Without this check, an attacker (or a corrupted copy)
                // could append extra chunk-framed bytes after a valid
                // final chunk; those bytes would silently be ignored,
                // even though the format is documented as detecting any
                // appended/truncated data. Confirm there's nothing left
                // to read.
                let mut trailing = [0u8; 1];
                match reader.read(&mut trailing) {
                    Ok(0) => {}
                    Ok(_) => bail!(
                        "Corrupted or tampered encrypted file: trailing data after final chunk"
                    ),
                    Err(e) => return Err(e.into()),
                }
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
                replace_file(tmp, out)?;
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

/// Verify that `encrypted_path` decrypts, under `password`, to exactly the
/// bytes of `original_path` — a true round-trip check, not just "did
/// decryption not error".
///
/// This decrypts to a temporary file (so arbitrarily large streamed files
/// don't need to be held in memory), then compares the decrypted output
/// against the original byte-for-byte in fixed-size chunks. The temporary
/// file is always removed before returning, whether verification succeeds
/// or fails.
///
/// Used by the "verify, then shred original" flow: shredding must never
/// proceed on the strength of "decryption succeeded" alone, since that
/// only proves the ciphertext was authenticated, not that its plaintext
/// actually matches the file about to be destroyed.
pub fn verify_stream_roundtrip(
    encrypted_path: &Path,
    original_path: &Path,
    password: &str,
    mut on_progress: Option<Progress<'_>>,
) -> Result<()> {
    let decrypted_tmp = unique_tmp_path(original_path);

    let decrypt_result = stream_decrypt_file(
        encrypted_path,
        Some(&decrypted_tmp),
        password,
        on_progress.take(),
    );

    let compare_result = decrypt_result.and_then(|()| {
        let orig_len = fs::metadata(original_path)?.len();
        let dec_len = fs::metadata(&decrypted_tmp)?.len();
        if orig_len != dec_len {
            bail!(
                "Verification failed: decrypted size ({dec_len}) does not \
                 match original size ({orig_len}) — original was NOT modified"
            );
        }

        // `Read::read` is permitted to return short reads even when more
        // data is available, so don't assume two independent readers stay
        // in lock-step; fill each buffer fully (or to EOF) before
        // comparing.
        fn fill(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut filled = 0;
            while filled < buf.len() {
                match r.read(&mut buf[filled..])? {
                    0 => break,
                    n => filled += n,
                }
            }
            Ok(filled)
        }

        let mut orig_reader =
            BufReader::with_capacity(STREAM_CHUNK_SIZE, File::open(original_path)?);
        let mut dec_reader =
            BufReader::with_capacity(STREAM_CHUNK_SIZE, File::open(&decrypted_tmp)?);
        let mut orig_buf = vec![0u8; STREAM_CHUNK_SIZE];
        let mut dec_buf = vec![0u8; STREAM_CHUNK_SIZE];

        loop {
            let n1 = fill(&mut orig_reader, &mut orig_buf)?;
            let n2 = fill(&mut dec_reader, &mut dec_buf)?;
            if n1 != n2 || orig_buf[..n1] != dec_buf[..n2] {
                bail!(
                    "Verification failed: decrypted content does not match \
                     the original byte-for-byte — original was NOT modified"
                );
            }
            if n1 == 0 {
                break;
            }
        }
        Ok(())
    });

    // Always clean up the decrypted scratch copy, regardless of outcome.
    let _ = fs::remove_file(&decrypted_tmp);

    compare_result
}

#[cfg(test)]
mod tests {
    use super::*;

    const PWD: &str = "correct horse battery staple";

    // --- Envelope key hierarchy: master password -> KEK -> vault key -> per-entry ---

    #[test]
    fn wrap_unwrap_vault_key_round_trips() {
        let vault_key = generate_vault_key();
        let wrapped = wrap_vault_key(PWD, &vault_key, KDF_ARGON2ID).unwrap();
        let recovered = unwrap_vault_key(PWD, &wrapped).unwrap();
        assert_eq!(*recovered, *vault_key);
    }

    #[test]
    fn wrap_unwrap_vault_key_round_trips_pbkdf2() {
        let vault_key = generate_vault_key();
        let wrapped = wrap_vault_key(PWD, &vault_key, KDF_PBKDF2).unwrap();
        let recovered = unwrap_vault_key(PWD, &wrapped).unwrap();
        assert_eq!(*recovered, *vault_key);
    }

    #[test]
    fn unwrap_vault_key_wrong_password_fails() {
        let vault_key = generate_vault_key();
        let wrapped = wrap_vault_key(PWD, &vault_key, KDF_ARGON2ID).unwrap();
        assert!(unwrap_vault_key("wrong password entirely", &wrapped).is_err());
    }

    #[test]
    fn wrapped_vault_key_encode_decode_round_trips() {
        let vault_key = generate_vault_key();
        let wrapped = wrap_vault_key(PWD, &vault_key, KDF_ARGON2ID).unwrap();
        let encoded = wrapped.encode();
        let (decoded, consumed) = WrappedVaultKey::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        // Re-unwrap through the decoded copy to confirm every field
        // survived the encode/decode trip, not just a subset.
        let recovered = unwrap_vault_key(PWD, &decoded).unwrap();
        assert_eq!(*recovered, *vault_key);
    }

    #[test]
    fn wrapped_vault_key_decode_rejects_truncated_input() {
        let vault_key = generate_vault_key();
        let wrapped = wrap_vault_key(PWD, &vault_key, KDF_ARGON2ID).unwrap();
        let encoded = wrapped.encode();
        // Cut off partway through the wrapped-key field itself, not just
        // the fixed-size header prefix.
        assert!(WrappedVaultKey::decode(&encoded[..encoded.len() - 5]).is_err());
        assert!(WrappedVaultKey::decode(&encoded[..4]).is_err());
        assert!(WrappedVaultKey::decode(&[]).is_err());
    }

    #[test]
    fn wrapped_vault_key_tampered_header_fails_to_unwrap() {
        // Flipping a byte anywhere in the AAD-bound header (here: the
        // KEK salt) must make unwrap fail closed — same tamper-evidence
        // guarantee `blob_aad_v3` gives the small-file format (U-01),
        // now extended to the vault-key-wrapping AEAD call.
        let vault_key = generate_vault_key();
        let mut wrapped = wrap_vault_key(PWD, &vault_key, KDF_ARGON2ID).unwrap();
        wrapped.kek_salt[0] ^= 0xFF;
        assert!(unwrap_vault_key(PWD, &wrapped).is_err());
    }

    #[test]
    fn derive_entry_key_is_deterministic_and_id_dependent() {
        let vault_key = generate_vault_key();
        let k1a = derive_entry_key(&vault_key, 42);
        let k1b = derive_entry_key(&vault_key, 42);
        let k2 = derive_entry_key(&vault_key, 43);
        assert_eq!(*k1a, *k1b, "same vault key + same id must derive the same entry key");
        assert_ne!(*k1a, *k2, "different ids under the same vault key must derive different keys");
    }

    #[test]
    fn derive_entry_key_differs_across_vault_keys() {
        let vk1 = generate_vault_key();
        let vk2 = generate_vault_key();
        assert_ne!(
            *derive_entry_key(&vk1, 1),
            *derive_entry_key(&vk2, 1),
            "the same entry id under two different vault keys must derive different entry keys"
        );
    }

    #[test]
    fn encrypt_decrypt_entry_payload_round_trips() {
        let vault_key = generate_vault_key();
        let plaintext = br#"{"id":7,"title":"example"}"#;
        let sealed = encrypt_entry_payload(&vault_key, 7, plaintext);
        let recovered = decrypt_entry_payload(&vault_key, 7, &sealed).unwrap();
        assert_eq!(&recovered[..], plaintext);
    }

    #[test]
    fn decrypt_entry_payload_wrong_entry_id_fails() {
        // The entry id is folded into the AAD (`vault_entry_aad`), so
        // decrypting under the *wrong* id for an otherwise-correct
        // ciphertext must fail — this is what stops a sealed entry from
        // being silently relabeled to a different id.
        let vault_key = generate_vault_key();
        let sealed = encrypt_entry_payload(&vault_key, 7, b"payload");
        assert!(decrypt_entry_payload(&vault_key, 8, &sealed).is_err());
    }

    #[test]
    fn decrypt_entry_payload_wrong_vault_key_fails() {
        let vk1 = generate_vault_key();
        let vk2 = generate_vault_key();
        let sealed = encrypt_entry_payload(&vk1, 7, b"payload");
        assert!(decrypt_entry_payload(&vk2, 7, &sealed).is_err());
    }

    #[test]
    fn decrypt_entry_payload_tampered_ciphertext_fails() {
        let vault_key = generate_vault_key();
        let mut sealed = encrypt_entry_payload(&vault_key, 7, b"payload");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(decrypt_entry_payload(&vault_key, 7, &sealed).is_err());
    }

    #[test]
    fn encrypt_entry_payload_uses_fresh_nonce_each_call() {
        // Same key, same id, same plaintext, called twice — ciphertexts
        // must differ (fresh random nonce each call), the same
        // nonce-uniqueness discipline every other AEAD call site in this
        // file already follows.
        let vault_key = generate_vault_key();
        let sealed1 = encrypt_entry_payload(&vault_key, 7, b"same payload");
        let sealed2 = encrypt_entry_payload(&vault_key, 7, b"same payload");
        assert_ne!(sealed1, sealed2);
        // Both still decrypt correctly despite differing on the wire.
        assert_eq!(&*decrypt_entry_payload(&vault_key, 7, &sealed1).unwrap(), b"same payload");
        assert_eq!(&*decrypt_entry_payload(&vault_key, 7, &sealed2).unwrap(), b"same payload");
    }

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
        // MAGIC(4) || VERSION(1) || kdf_id(1) || kdf_params(12) || salt(16)
        // || nonce(12) || ct(+tag)  -- the kdf_params block is the U-01 fix.
        let combined = encrypt_blob(PWD, b"x", KDF_ARGON2ID).unwrap();
        assert_eq!(&combined[0..4], BLOB_MAGIC);
        assert_eq!(combined[4], FORMAT_VERSION);
        assert_eq!(combined[5], KDF_ARGON2ID);
        let params = KdfParams::from_bytes(&combined[6..18]).unwrap();
        assert_eq!(params.p1, ARGON2_MEMORY_KIB);
        assert_eq!(params.p2, ARGON2_TIME_COST);
        assert_eq!(params.p3, ARGON2_LANES);
        assert!(combined.len() >= 4 + 1 + 1 + KdfParams::ENCODED_LEN + 16 + 12 + 1 + 16); // + tag
    }

    #[test]
    fn blob_v3_tampered_kdf_params_fails() {
        // U-01 regression test: the KDF params block is authenticated via
        // the AAD, so flipping a byte inside it must fail decryption
        // (rather than silently deriving with different, attacker-chosen
        // parameters).
        let mut combined = encrypt_blob(PWD, b"secret", KDF_ARGON2ID).unwrap();
        // Byte 6 is the first byte of the params block (kdf_params.p1's
        // high byte, i.e. part of the Argon2id memory-cost parameter).
        combined[6] ^= 0xFF;
        assert!(decrypt_blob(PWD, &combined).is_err());
    }

    #[test]
    fn blob_v3_roundtrips_with_pbkdf2() {
        let combined = encrypt_blob(PWD, b"pbkdf2 secret", KDF_PBKDF2).unwrap();
        let plain = decrypt_blob(PWD, &combined).unwrap();
        assert_eq!(plain, b"pbkdf2 secret");
        let params = KdfParams::from_bytes(&combined[6..18]).unwrap();
        assert_eq!(params.p1, PBKDF2_ITERATIONS);
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
        let key = derive_key(PWD, &salt, KDF_ARGON2ID, KdfParams::legacy_for_kdf(KDF_ARGON2ID).unwrap()).unwrap();
        let cipher = aead_for_key(&key);
        let old_version: u8 = 1;
        let aad = blob_aad(KDF_ARGON2ID, old_version);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: b"legacy-versioned data",
                    aad: &aad,
                },
            )
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
        let key = derive_key(PWD, &salt, KDF_PBKDF2, KdfParams::legacy_for_kdf(KDF_PBKDF2).unwrap()).unwrap();
        let cipher = aead_for_key(&key);
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: b"old app data",
                    aad: &[],
                },
            )
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
        let key = derive_key(PWD, &salt, KDF_PBKDF2, KdfParams::legacy_for_kdf(KDF_PBKDF2).unwrap()).unwrap();
        let cipher = aead_for_key(&key);
        let nonce = Nonce::from_slice(&iv);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: b"very old app data",
                    aad: &[],
                },
            )
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
        let dir = std::env::temp_dir().join(format!("unigen_test_{}_{}", std::process::id(), {
            let mut n = [0u8; 8];
            OsRng.fill_bytes(&mut n);
            hex::encode(n)
        }));
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
        let dir = std::env::temp_dir().join(format!("unigen_test2_{}_{}", std::process::id(), {
            let mut n = [0u8; 8];
            OsRng.fill_bytes(&mut n);
            hex::encode(n)
        }));
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
    fn stream_v3_tampered_kdf_params_fails() {
        // U-01 regression test, streaming-format side: same rationale as
        // blob_v3_tampered_kdf_params_fails.
        let dir = std::env::temp_dir().join(format!(
            "unigen_test_kdfparams_{}_{}",
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
        fs::write(&in_path, b"stream kdf params tamper test").unwrap();
        stream_encrypt_file(&in_path, &enc_path, PWD, KDF_ARGON2ID, None).unwrap();

        let mut bytes = fs::read(&enc_path).unwrap();
        // Header: MAGIC(4) + version/kdf_id(2) -> params block starts at 6.
        bytes[6] ^= 0xFF;
        fs::write(&enc_path, &bytes).unwrap();

        let result = stream_decrypt_file(&enc_path, None, PWD, None);
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
        let dir = std::env::temp_dir().join(format!("unigen_test3_{}", std::process::id()));
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
