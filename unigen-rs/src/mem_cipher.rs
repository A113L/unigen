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
    // `Key` (a `GenericArray<u8, U32>`) only converts from a *fixed-size*
    // `&[u8; 32]`, not an arbitrary `&[u8]` — so go through `try_into` to
    // get there. `.expect` never fires: `MemKey` always allocates exactly
    // `KEY_LEN` (32) bytes.
    let key_arr: &[u8; KEY_LEN] = key()
        .as_slice()
        .try_into()
        .expect("MemKey: key is always KEY_LEN bytes");
    let key: &Key = key_arr.into();
    let mut cipher = ChaCha20::new(key, nonce.into());
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

    // ---- Concurrency / race tests -------------------------------------
    //
    // `MEM_KEY` (a `OnceLock<MemKey>`) is the one piece of genuinely
    // shared, cross-thread state in this module: every call to
    // `apply_keystream`, from whichever thread, reads through the same
    // lazily-initialized global. The property that actually matters is
    // "every thread ends up using the exact same key, and concurrent
    // access never corrupts a buffer" — `OnceLock` is documented to
    // guarantee the former, but that guarantee is worth pinning down with
    // an actual concurrent test rather than trusting the doc comment
    // alone, especially since a future refactor could swap `OnceLock` for
    // something with weaker guarantees without an obvious compile error.

    #[test]
    fn concurrent_key_init_is_consistent_across_threads() {
        // Many threads all race to be the one that initializes `MEM_KEY`
        // (via `Barrier`, to maximize the odds they actually overlap on
        // the first call rather than running one-at-a-time). If two
        // threads ever ended up using *different* keys — the failure mode
        // a buggy lazy-init would produce — the same (nonce, plaintext)
        // pair would encrypt to different ciphertext depending on which
        // thread ran it.
        const N: usize = 32;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));
        let nonce = [7u8; NONCE_LEN];
        let plaintext = b"same plaintext, encrypted from many threads at once".to_vec();

        let handles: Vec<_> = (0..N)
            .map(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                let mut buf = plaintext.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    apply_keystream(&nonce, &mut buf);
                    buf
                })
            })
            .collect();

        let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for r in &results {
            assert_ne!(r, &plaintext, "keystream must have changed the buffer");
            assert_eq!(
                r, &results[0],
                "every thread must derive ciphertext from the same process-wide key"
            );
        }
    }

    #[test]
    fn concurrent_seal_unseal_round_trips_correctly_per_thread() {
        // Each thread works on its own buffer with its own random nonce,
        // all hammering `apply_keystream` (and therefore the shared
        // `MEM_KEY`) at the same time. A data race corrupting the key's
        // backing allocation, or a torn/interleaved read of it, would show
        // up here as a thread's own round-trip failing to recover its own
        // plaintext.
        const N: usize = 32;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(N));

        let handles: Vec<_> = (0..N)
            .map(|i| {
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let nonce = random_nonce();
                    let original = format!("secret-for-thread-{i}").into_bytes();
                    let mut buf = original.clone();
                    barrier.wait();
                    apply_keystream(&nonce, &mut buf); // seal
                    assert_ne!(buf, original, "thread {i}: seal must change the buffer");
                    apply_keystream(&nonce, &mut buf); // unseal
                    assert_eq!(buf, original, "thread {i}: unseal must recover the plaintext");
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }
}
