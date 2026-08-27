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
use std::ops::{Deref, Range};
use std::ptr::{self, NonNull};
use std::str;

use egui::TextBuffer;
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

    /// Insert `data` at byte offset `at` (0 <= at <= len). Grows through
    /// `grow_to` (which zeroizes any vacated old buffer) if needed, then
    /// shifts the existing tail right with an overlap-safe `ptr::copy`
    /// (not `copy_nonoverlapping` — source and destination *do* overlap
    /// here) to make room before writing the new bytes in place. This is
    /// the in-place equivalent of `push_slice` for non-append positions,
    /// used by `TextBuffer::insert_text` so mid-string edits (e.g. the
    /// cursor isn't at the end of a password field) never fall back to a
    /// plain `String`/`Vec` insert that would leave a stray unzeroized
    /// copy behind on reallocation.
    fn insert_slice(&mut self, at: usize, data: &[u8]) {
        debug_assert!(at <= self.len);
        if data.is_empty() {
            return;
        }
        let old_len = self.len;
        let needed = old_len + data.len();
        if needed > self.cap {
            self.grow_to(needed);
        }
        // SAFETY: `grow_to` guarantees `self.cap >= needed`. `at <=
        // old_len <= self.cap`, and `old_len - at` bytes are being moved
        // to `[at + data.len(), needed)`, which is in bounds. The source
        // and destination ranges can overlap (when `data.len() <
        // old_len - at`), so this must be `ptr::copy`, not
        // `copy_nonoverlapping`.
        unsafe {
            let base = self.ptr.as_ptr();
            ptr::copy(base.add(at), base.add(at + data.len()), old_len - at);
            ptr::copy_nonoverlapping(data.as_ptr(), base.add(at), data.len());
        }
        self.len = needed;
    }

    /// Remove the byte range `[start, end)` (0 <= start <= end <= len),
    /// shifting the tail left over the gap. Critically, this also
    /// zeroizes the now-vacated bytes at the tail end of the live
    /// region — after the shift they sit past the new `len` but are
    /// still inside `cap`, i.e. exactly the "capacity beyond len can
    /// still hold stale bytes" case the module docs warn about. Without
    /// this, backspacing characters out of a password field would leave
    /// deleted plaintext readable in the buffer's slack space for the
    /// rest of the buffer's life (survives until the next `grow_to` or
    /// `Drop`), which defeats the point of a wipe-on-relocate type.
    fn delete_byte_range(&mut self, range: Range<usize>) {
        let Range { start, end } = range;
        debug_assert!(start <= end && end <= self.len);
        if start >= end {
            return;
        }
        let tail_len = self.len - end;
        // SAFETY: `start`, `end`, `tail_len` are all within `[0,
        // self.len] <= self.cap`, as established by the caller's
        // byte-index derivation from a valid char range over
        // `as_str()`. Overlapping shift uses `ptr::copy`.
        unsafe {
            let base = self.ptr.as_ptr();
            ptr::copy(base.add(end), base.add(start), tail_len);
            let vacated_start = start + tail_len;
            let vacated_len = self.len - vacated_start;
            if vacated_len > 0 {
                let vacated =
                    std::slice::from_raw_parts_mut(base.add(vacated_start), vacated_len);
                vacated.zeroize();
            }
        }
        self.len -= end - start;
    }

    /// Raw pointer/capacity of the live backing buffer, for callers that
    /// need to `mlock()` it directly (Linux-only best-effort swap
    /// exclusion — see `SecretString::mlock_best_effort`). Not exposed
    /// more broadly since holding onto this past the next mutation
    /// (which may relocate the buffer via `grow_to`) is unsafe.
    #[cfg(target_os = "linux")]
    fn as_ptr_cap(&self) -> (*const u8, usize) {
        (self.ptr.as_ptr(), self.cap)
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

    /// Number of `char`s (not bytes) in the string. Used by
    /// `secure_text_edit`'s cursor-position math, which — like
    /// `egui::TextBuffer` — addresses positions in characters, not
    /// bytes.
    pub fn len_chars(&self) -> usize {
        self.as_str().chars().count()
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

    /// Byte offset of the `char_index`-th character (like
    /// `str::char_indices`, clamped to `len()` if `char_index` is past
    /// the end — matches the behavior `egui::TextBuffer` implementations
    /// are expected to have for cursor/selection positions).
    pub(crate) fn byte_index_from_char_index(&self, char_index: usize) -> usize {
        self.as_str()
            .char_indices()
            .nth(char_index)
            .map(|(bi, _)| bi)
            .unwrap_or(self.bytes.len)
    }

    /// Insert `text` at byte offset `byte_idx` (0 <= byte_idx <= len(),
    /// and must land on a char boundary). Goes through
    /// `SecretBytes::insert_slice`, so any growth this triggers zeroizes
    /// the vacated old buffer the same as every other mutator here.
    pub fn insert_str(&mut self, byte_idx: usize, text: &str) {
        self.bytes.insert_slice(byte_idx, text.as_bytes());
    }

    /// Delete the byte range `[start, end)` (must land on char
    /// boundaries). The vacated tail bytes are zeroized in place by
    /// `SecretBytes::delete_byte_range` — deleted characters (e.g. from
    /// backspacing while editing a password field) don't linger as
    /// readable slack-space bytes.
    pub fn delete_byte_range(&mut self, range: Range<usize>) {
        self.bytes.delete_byte_range(range);
    }

    /// Best-effort: ask the Linux kernel to keep this buffer's *current*
    /// allocation out of swap (`mlock(2)`). Returns `false` if the kernel
    /// refuses (e.g. `RLIMIT_MEMLOCK` exceeded) — callers must treat that
    /// as informational, not fatal, same as every other mlock use in this
    /// app.
    ///
    /// Unlike locking a one-off clone handed to a background thread (the
    /// existing pattern for the passphrase actually used in a crypto
    /// operation), this locks the *live* field a UI text box writes into
    /// — the buffer that exists, unencrypted, for the entire time the
    /// user is looking at / typing into that field, which is the longest
    /// exposure window for a passphrase in this app. Callers should
    /// re-invoke this after every edit: a `grow_to` relocation moves the
    /// buffer to a new allocation that the previous `mlock()` call no
    /// longer covers (the kernel doesn't follow it), so there's a small
    /// window right after growth, until this is called again, where the
    /// buffer isn't locked. This is the same "not a guarantee, only
    /// shrinks the exposure window" caveat this app already documents
    /// for `mlock` everywhere else.
    #[cfg(target_os = "linux")]
    pub fn mlock_best_effort(&self) -> bool {
        extern "C" {
            fn mlock(addr: *const std::ffi::c_void, len: usize) -> i32;
        }
        let (ptr, cap) = self.bytes.as_ptr_cap();
        if cap == 0 {
            return true;
        }
        // SAFETY: `ptr` is valid for `cap` bytes for as long as `self`
        // isn't mutated (this call is synchronous and doesn't retain
        // `ptr`), per `SecretBytes`'s own invariants.
        unsafe { mlock(ptr as *const std::ffi::c_void, cap) == 0 }
    }
}

/// Lets `SecretString` be used directly as the backing buffer for an
/// `egui::TextEdit` (`ui.add(TextEdit::singleline(&mut some_secret_string))`).
///
/// This is the fix for the gap documented in the module docs: without
/// this impl, any password/secret field editable in the UI had to be a
/// plain `String` (or `Zeroizing<String>`, which only wipes on final
/// `Drop`) because that's the only thing `TextEdit` can write into.
/// Every keystroke into such a field went through `String`'s own
/// `insert`/`remove`, which reallocates via the global allocator and
/// frees the old buffer *unzeroized* — exactly the residual-plaintext
/// problem this module exists to close, except happening continuously
/// while the user types, for the single longest-lived, most sensitive
/// buffer in the app (the passphrase actually being typed).
///
/// With this impl, `TextEdit`'s insert/delete calls route through
/// `SecretBytes::insert_slice`/`delete_byte_range`, which zeroize
/// vacated-on-grow and vacated-on-delete bytes respectively. The one
/// unavoidable gap is `take()`: its trait signature returns an owned
/// `String` (used internally by egui for cut/paste), which necessarily
/// copies the text out into a normal, non-wiped buffer for that
/// operation. That's an egui API constraint, not something this impl
/// can close — same residual risk as the existing system-clipboard
/// caveat noted elsewhere in this app.
impl TextBuffer for SecretString {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        SecretString::as_str(self)
    }

    fn insert_text(&mut self, text: &str, char_index: usize) -> usize {
        if text.is_empty() {
            return 0;
        }
        let byte_idx = self.byte_index_from_char_index(char_index);
        self.insert_str(byte_idx, text);
        text.chars().count()
    }

    fn delete_char_range(&mut self, char_range: Range<usize>) {
        let start = self.byte_index_from_char_index(char_range.start);
        let end = self.byte_index_from_char_index(char_range.end);
        self.delete_byte_range(start..end);
    }

    fn byte_index_from_char_index(&self, char_index: usize) -> usize {
        SecretString::byte_index_from_char_index(self, char_index)
    }

    fn clear(&mut self) {
        SecretString::clear(self);
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
        // Zero the *entire* backing allocation, not just the `len()`
        // live bytes. `owned.as_bytes_mut()` only covers `[0, len)`;
        // if `owned`'s capacity is larger than its length (e.g. it grew
        // via `push`/`push_str` at some earlier point and still holds
        // that larger allocation), the slack bytes in `[len, capacity)`
        // are never touched by a `len`-only zeroize and go straight to
        // `dealloc` with the original plaintext intact. This is the
        // same "capacity beyond len can still hold stale bytes" case
        // `SecretBytes::grow_to` guards against — this impl needs the
        // same guarantee.
        let cap = owned.capacity();
        // SAFETY: `owned.as_mut_vec()` gives access to the `Vec<u8>`
        // backing this `String`; that `Vec` is valid for `cap` bytes
        // (its own allocation invariant), and we're about to zero all
        // of it and never read `owned` as text again — `String`'s
        // `Drop` doesn't validate UTF-8, so leaving it zero-filled is
        // fine.
        unsafe {
            let ptr = owned.as_mut_vec().as_mut_ptr();
            std::slice::from_raw_parts_mut(ptr, cap).zeroize();
        }
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
    fn text_buffer_insert_at_cursor_positions() {
        // Simulates typing "helo", moving cursor back one, then typing
        // "l" to fix it to "hello" — the mid-string insert path that a
        // plain `String` handles fine functionally, but that this type
        // must additionally handle without leaking stale bytes.
        let mut s = SecretString::new();
        assert_eq!(s.insert_text("helo", 0), 4);
        assert_eq!(s.as_str(), "helo");
        assert_eq!(s.insert_text("l", 3), 1);
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn text_buffer_delete_char_range_zeroizes_vacated_tail() {
        let mut s = SecretString::from_str("hello world");
        // Delete "hello " (chars 0..6), leaving "world".
        s.delete_char_range(0..6);
        assert_eq!(s.as_str(), "world");
        // The vacated tail (old bytes 5..11, now past the new len=5)
        // must be zeroized, not just logically truncated — inspect the
        // raw allocation directly to confirm no stale plaintext remains
        // in the slack space between len and cap.
        let live_len = s.bytes.len;
        let cap = s.bytes.cap;
        let raw = unsafe { std::slice::from_raw_parts(s.bytes.ptr.as_ptr(), cap) };
        assert_eq!(&raw[..live_len], b"world");
        assert!(
            raw[live_len..].iter().all(|&b| b == 0),
            "deleted bytes must be zeroized, found: {:?}",
            &raw[live_len..]
        );
    }

    #[test]
    fn text_buffer_multibyte_char_boundaries() {
        let mut s = SecretString::from_str("héllo");
        // 'é' is 2 bytes; make sure char-index-based insert/delete don't
        // split it.
        assert_eq!(s.as_str(), "héllo");
        s.delete_char_range(1..2); // remove just 'é'
        assert_eq!(s.as_str(), "hllo");
    }

    #[test]
    fn serde_round_trip() {
        let s = SecretString::from_str("hunter2");
        let json = serde_json::to_string(&s).unwrap();
        let back: SecretString = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), "hunter2");
    }
}
