//! `SecretString`: a UTF-8 string type whose backing buffer is never
//! relocated (grown, shrunk, or cloned) without the *old* buffer being
//! explicitly zeroized before it's handed back to the allocator.
//!
//! This closes the gap documented on `impl Zeroize for VaultEntry` in
//! `vault.rs`: `zeroize::Zeroizing<T>` (used everywhere else in this app)
//! only wipes memory when the *outer wrapper itself* is dropped. It does
//! nothing about the copies a plain `String`/`Vec<u8>` leaves behind
//! *during its own lifetime* whenever it reallocates — `push`/`push_str`
//! crossing capacity, or `.clone()` — because `String`'s growth goes
//! through the global allocator's `realloc`/`alloc`+copy, and the old
//! buffer is simply freed, not overwritten. Freed memory isn't zeroed by
//! the allocator; it just sits there, readable, until something else
//! happens to reuse that address range.
//!
//! `SecretString` (built on `SecretBytes`) fixes this by owning every
//! relocation itself: `grow_to` is the *only* place backing memory ever
//! moves, and it always zeroizes the vacated buffer before freeing it.
//! `Drop` zeroizes the final buffer the same way. There is no path to a
//! bigger/different allocation that skips the wipe, because nothing in
//! this type ever calls `String`'s or `Vec`'s own growth/clone — only
//! this module's controlled ones.

use std::alloc::{alloc, dealloc, Layout};
use std::fmt;
use std::ops::Deref;
use std::ptr::{self, NonNull};
use std::str;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

/// Raw growable byte buffer with wipe-before-relocate/free semantics.
/// Not `pub` outside this module — `SecretString` is the intended public
/// surface, and it's the layer that maintains the UTF-8 invariant.
struct SecretBytes {
    ptr: NonNull<u8>,
    len: usize,
    cap: usize,
}

// SAFETY: `SecretBytes` owns its buffer exclusively (no aliasing), same
// as `Vec<u8>`, so it's Send/Sync under the same conditions `Vec<u8>` is.
unsafe impl Send for SecretBytes {}
unsafe impl Sync for SecretBytes {}

impl SecretBytes {
    fn new() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            cap: 0,
        }
    }

    fn with_capacity(cap: usize) -> Self {
        let mut s = Self::new();
        if cap > 0 {
            s.grow_to(cap);
        }
        s
    }

    fn layout(cap: usize) -> Layout {
        Layout::array::<u8>(cap).expect("SecretBytes: capacity overflow")
    }

    /// Ensure capacity is at least `new_cap`. If growth is needed, this
    /// allocates a fresh buffer, copies the existing bytes into it,
    /// zeroizes the *entire* old buffer (not just the `len` bytes that
    /// were live — capacity beyond `len` can still hold stale bytes left
    /// by an earlier in-place zeroize/shrink), and frees the old buffer.
    /// This one function is the only relocation path in the whole type,
    /// which is what makes the "always zeroize before free" guarantee
    /// total rather than best-effort.
    fn grow_to(&mut self, new_cap: usize) {
        if new_cap <= self.cap {
            return;
        }
        let new_cap = new_cap.max(self.cap.saturating_mul(2)).max(8);
        let new_layout = Self::layout(new_cap);
        // SAFETY: new_layout has non-zero size (new_cap >= 8), so `alloc`
        // is safe to call per its contract.
        let new_ptr = unsafe { alloc(new_layout) };
        let new_ptr = match NonNull::new(new_ptr) {
            Some(p) => p,
            None => std::alloc::handle_alloc_error(new_layout),
        };
        if self.len > 0 {
            // SAFETY: `self.ptr` is valid for `self.len` bytes (invariant
            // of this type), `new_ptr` is valid for `new_cap >= self.len`
            // bytes, and the two allocations never overlap.
            unsafe {
                ptr::copy_nonoverlapping(self.ptr.as_ptr(), new_ptr.as_ptr(), self.len);
            }
        }
        if self.cap > 0 {
            // SAFETY: `self.ptr` is valid for `self.cap` bytes.
            let old_slice =
                unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.cap) };
            old_slice.zeroize();
            // SAFETY: `self.ptr`/`self.cap` describe the allocation this
            // struct made with `Self::layout(self.cap)`, and we're done
            // with it (contents already wiped above).
            unsafe { dealloc(self.ptr.as_ptr(), Self::layout(self.cap)) };
        }
        self.ptr = new_ptr;
        self.cap = new_cap;
    }

    fn push_slice(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let needed = self.len + data.len();
        if needed > self.cap {
            self.grow_to(needed);
        }
        // SAFETY: `grow_to` above guarantees `self.cap >= needed`, so
        // `[self.len, self.len + data.len())` is in bounds of `self.ptr`.
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.as_ptr().add(self.len), data.len());
        }
        self.len += data.len();
    }

    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            &[]
        } else {
            // SAFETY: `self.ptr` is valid for `self.len` bytes.
            unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
        }
    }

    /// Zeroize the live (`len`) bytes in place — no relocation, so this
    /// doesn't touch the allocator at all. Used for "clear this out
    /// before overwriting/replacing" call sites that don't need the
    /// backing allocation itself freed yet.
    fn zeroize_in_place(&mut self) {
        if self.len > 0 {
            // SAFETY: `self.ptr` is valid for `self.len` bytes.
            let live = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) };
            live.zeroize();
        }
        self.len = 0;
    }

    fn clone_secret(&self) -> Self {
        let mut new = Self::with_capacity(self.len);
        new.push_slice(self.as_slice());
        new
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        if self.cap > 0 {
            // SAFETY: same as in `grow_to` — `self.ptr`/`self.cap`
            // describe this struct's live allocation.
            let slice = unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.cap) };
            slice.zeroize();
            unsafe { dealloc(self.ptr.as_ptr(), Self::layout(self.cap)) };
        }
    }
}

/// A `String`-like type for secrets (vault entry fields, passphrases)
/// that guarantees no stale unzeroized copy is ever left behind by its
/// *own* internal reallocation — see the module docs above. Every public
/// constructor and mutator goes through `SecretBytes`, so this guarantee
/// holds regardless of how the value is built up or replaced.
pub struct SecretString {
    bytes: SecretBytes,
}

impl SecretString {
    pub fn new() -> Self {
        Self {
            bytes: SecretBytes::new(),
        }
    }

    /// Copy `s` into a freshly-owned `SecretString`. Does not consume or
    /// zero `s` itself — the caller still owns that buffer and is
    /// responsible for it, same as building a `String` from a `&str`.
    pub fn from_str(s: &str) -> Self {
        let mut bytes = SecretBytes::with_capacity(s.len());
        bytes.push_slice(s.as_bytes());
        Self { bytes }
    }

    /// Append more text. Any capacity growth this triggers goes through
    /// `SecretBytes::grow_to`, which zeroizes the vacated buffer before
    /// it's freed — this is the exact `push_str`-crosses-capacity case
    /// that was the documented gap for plain `String` fields.
    pub fn push_str(&mut self, s: &str) {
        self.bytes.push_slice(s.as_bytes());
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: every byte ever written into `self.bytes` came from a
        // `&str`/`String`/`SecretString` (all guaranteed valid UTF-8),
        // and `push_slice`/`grow_to` never split a multi-byte codepoint
        // or otherwise touch the encoded bytes, so the buffer is valid
        // UTF-8 for its entire `len`.
        unsafe { str::from_utf8_unchecked(self.bytes.as_slice()) }
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.len == 0
    }

    pub fn len(&self) -> usize {
        self.bytes.len
    }

    /// Zeroize the current contents in place (used at call sites that
    /// used to call `.zeroize()` on a plain `String` field right before
    /// overwriting or dropping it). Explicit — most callers can now rely
    /// on `Drop`/relocation handling this automatically, but keeping this
    /// available preserves the "zero the old value before it's replaced"
    /// pattern used elsewhere in this app for defense in depth.
    pub fn clear(&mut self) {
        self.bytes.zeroize_in_place();
    }
}

impl Default for SecretString {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone_secret(),
        }
    }
}

impl Deref for SecretString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString(REDACTED, len={})", self.len())
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for SecretString {}

impl PartialEq<&str> for SecretString {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl Zeroize for SecretString {
    fn zeroize(&mut self) {
        self.bytes.zeroize_in_place();
    }
}

/// Consumes an owned `String`. The bytes are copied into the new
/// `SecretString`'s controlled buffer, and the *source* `String`'s
/// buffer is then explicitly zeroized before it's dropped — otherwise
/// the caller handing over a `String` (e.g. loading CSV-imported rows,
/// or an edit-pane buffer's `.to_string()`) would itself be exactly the
/// unzeroized-stray-copy problem this type exists to avoid, just moved
/// one call site earlier.
impl From<String> for SecretString {
    fn from(s: String) -> Self {
        let mut owned = s;
        let out = Self::from_str(owned.as_str());
        // SAFETY: we're about to zero every byte and never read `owned`
        // as text again — `String`'s `Drop` doesn't validate UTF-8, so
        // leaving it zero-filled is fine.
        unsafe { owned.as_bytes_mut() }.zeroize();
        out
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::from_str(s)
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Deserialize into a plain `String` first (serde/JSON parsing
        // itself is outside this type's control), then immediately fold
        // it into a `SecretString` via `From<String>`, which zeroizes
        // that intermediate buffer once its contents are copied over.
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::from(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = SecretString::from_str("hello world");
        assert_eq!(s.as_str(), "hello world");
        assert_eq!(s, "hello world");
    }

    #[test]
    fn push_str_crossing_capacity_preserves_content() {
        let mut s = SecretString::new();
        for _ in 0..100 {
            s.push_str("ab");
        }
        assert_eq!(s.len(), 200);
        assert!(s.as_str().chars().all(|c| c == 'a' || c == 'b'));
    }

    #[test]
    fn clone_is_independent() {
        let a = SecretString::from_str("secret");
        let mut b = a.clone();
        b.push_str("!");
        assert_eq!(a.as_str(), "secret");
        assert_eq!(b.as_str(), "secret!");
    }

    #[test]
    fn clear_zeroizes_and_empties() {
        let mut s = SecretString::from_str("wipeme");
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.as_str(), "");
    }

    #[test]
    fn from_string_zeroizes_source() {
        let source = String::from("topsecret");
        let ptr = source.as_ptr();
        let len = source.len();
        let _secret = SecretString::from(source);
        // SAFETY: the `String` was consumed by `From`, which zeroized
        // its buffer before dropping it; the allocation itself may or
        // may not have been freed depending on allocator behavior, but
        // reading it back here is only for test verification of the
        // zeroize step, in the same process, before anything else could
        // plausibly reuse it.
        let leftover = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(leftover.iter().all(|&b| b == 0));
    }

    #[test]
    fn serde_round_trip() {
        let s = SecretString::from_str("hunter2");
        let json = serde_json::to_string(&s).unwrap();
        let back: SecretString = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), "hunter2");
    }
}
