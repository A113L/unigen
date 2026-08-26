//! Lightweight in-memory (not on-disk) encryption for secrets that sit in
//! RAM for a long time without being actively edited — the master
//! password held across a save, and every vault entry's password while
//! the vault is unlocked.
//!
//! `SecretString`/`SecretBytes` (see `secret.rs`) already guarantee those
//! buffers are never left as *unzeroized* stray copies. That closes the
//! "old allocation freed without wiping" gap, but it does nothing about
//! the *live*, in-use buffer itself: for as long as an entry's password
//! sits in `vault_entries` as a decrypted `SecretString`, it is plain
//! readable UTF-8 at a fixed heap address — recoverable by anything that
//! can read the process's memory (a core dump, a debugger attach, a
//! swapped-out page on a platform where `mlock` was refused, etc).
//!
//! This module closes that gap the same way KeePass/KeePassXC's
//! "protected memory" does: keep the value XOR'd with a stream-cipher
//! keystream at rest, and only decrypt it into a short-lived `SecretString`
//! at the moment it's actually needed (displayed, copied, or moved into an
//! edit buffer). The cipher is ChaCha20 (RFC 8439), used here purely as a
//! keystream generator — this is an *obfuscation-at-rest* layer against
//! passive memory inspection, not a replacement for the AES-256-GCM
//! envelope `crypto.rs` uses to protect the vault file on disk. The key
//! is process-local, generated once from the OS CSPRNG, and never
//! persisted anywhere.
//!
//! The key itself is the one piece of material that *does* need to stay
//! resident for the whole process lifetime, so it is `mlock`ed (best
//! effort, via `crate::mem_lock`, same as every other long-lived secret
//! buffer in this app) and zeroized if it's ever dropped.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key};
use rand::rngs::OsRng;
use rand::RngCore;
use std::alloc::{alloc, dealloc, Layout};
use std::ptr::NonNull;
use std::sync::OnceLock;
use zeroize::Zeroize;

const KEY_LEN: usize = 32;
/// ChaCha20's IV/nonce size (RFC 8439, 96-bit nonce).
pub const NONCE_LEN: usize = 12;

/// Holds the process-wide keystream key in a small heap allocation that
/// is `mlock`ed the same way `SecretBytes` locks a live passphrase
/// buffer, and zeroized on drop. There is exactly one of these for the
/// life of the process (see `key()` below); it is never serialized,
/// never written to disk, and never derived from user input — it exists
/// solely to key the in-RAM obfuscation layer, not to protect anything
/// that has to survive a restart.
struct MemKey {
    ptr: NonNull<u8>,
    locked: bool,
}

// SAFETY: `MemKey` owns its allocation exclusively; sharing the
// process-wide instance behind a `OnceLock<MemKey>` only ever hands out
// `&MemKey`, never mutable access after construction, so this matches
// the same Send/Sync reasoning as `SecretBytes`.
unsafe impl Send for MemKey {}
unsafe impl Sync for MemKey {}

impl MemKey {
    fn generate() -> Self {
        let layout = Layout::array::<u8>(KEY_LEN).expect("MemKey: layout");
        // SAFETY: `layout` has non-zero size, so `alloc` may be called.
        let raw = unsafe { alloc(layout) };
        let ptr = match NonNull::new(raw) {
            Some(p) => p,
            None => std::alloc::handle_alloc_error(layout),
        };
        // SAFETY: `ptr` is valid for `KEY_LEN` bytes, freshly allocated.
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr.as_ptr(), KEY_LEN) };
        OsRng.fill_bytes(slice);
        // Best-effort: keep the key out of swap for as long as the
        // process runs. Refusal (no primitive on this platform, or the
        // OS declining the request) is not fatal — same "best effort,
        // not a guarantee" contract as every other `mem_lock` call site.
        let locked = crate::mem_lock::lock(ptr.as_ptr(), KEY_LEN);
        Self { ptr, locked }
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `self.ptr` is valid for `KEY_LEN` bytes for the whole
        // lifetime of this struct (only ever freed in `Drop`).
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), KEY_LEN) }
    }
}

impl Drop for MemKey {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` describes this struct's own `KEY_LEN`-byte
        // allocation, made in `generate` above.
        let slice = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), KEY_LEN) };
        slice.zeroize();
        if self.locked {
            crate::mem_lock::unlock(self.ptr.as_ptr(), KEY_LEN);
        }
        let layout = Layout::array::<u8>(KEY_LEN).expect("MemKey: layout");
        // SAFETY: matches the layout used to allocate `self.ptr`.
        unsafe { dealloc(self.ptr.as_ptr(), layout) };
    }
}

static MEM_KEY: OnceLock<MemKey> = OnceLock::new();

fn key() -> &'static MemKey {
    MEM_KEY.get_or_init(MemKey::generate)
}

/// A fresh random nonce for a single `LockedSecret`. Every sealed value
/// gets its own nonce (generated here, stored alongside the ciphertext —
/// see `secret::LockedSecret`), so reusing the single process-wide key
/// across many secrets never reuses a (key, nonce) pair.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// XOR `buf` in place with the ChaCha20 keystream for `nonce` under the
/// process-wide key. Symmetric: calling this a second time with the same
/// nonce on the result reverses it, exactly like the KeePass-style
/// "protect/unprotect" toggle this module is modeled on. Empty `buf` is a
/// no-op (no need to touch the cipher for a zero-length secret).
pub fn apply_keystream(nonce: &[u8; NONCE_LEN], buf: &mut [u8]) {
    if buf.is_empty() {
        return;
    }
    // `Key::try_from` (rather than the deprecated `Key::from_slice`) —
    // panics via `.expect` on a length mismatch, which can't happen here
    // since `MemKey` always allocates exactly `KEY_LEN` (32) bytes.
    let key = Key::try_from(key().as_slice()).expect("MemKey: key is always KEY_LEN bytes");
    let mut cipher = ChaCha20::new(&key, nonce.into());
    cipher.apply_keystream(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keystream_is_involutive() {
        let nonce = random_nonce();
        let original = b"hunter2 correct horse battery staple".to_vec();
        let mut buf = original.clone();
        apply_keystream(&nonce, &mut buf);
        assert_ne!(buf, original, "should not be a no-op");
        apply_keystream(&nonce, &mut buf);
        assert_eq!(buf, original, "applying twice must round-trip");
    }

    #[test]
    fn different_nonces_give_different_ciphertext() {
        let plain = b"same plaintext".to_vec();
        let mut a = plain.clone();
        let mut b = plain.clone();
        apply_keystream(&random_nonce(), &mut a);
        apply_keystream(&random_nonce(), &mut b);
        assert_ne!(a, b, "distinct nonces must not collide by chance");
    }

    #[test]
    fn empty_buffer_is_a_no_op() {
        let nonce = random_nonce();
        let mut buf: Vec<u8> = Vec::new();
        apply_keystream(&nonce, &mut buf);
        assert!(buf.is_empty());
    }
}
