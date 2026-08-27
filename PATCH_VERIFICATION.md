# Release Verification — What We Checked

## Test: Does a password really disappear from memory after the field is cleared? (2026-08-27)

We tested this on a live example:

1. Typed a unique test password into the app
2. Cleared the field
3. Took a snapshot of the running program's memory
4. Searched that snapshot for the password

**Result: the password was not found.** ✅

This confirms two things:

- When a password field is cleared, the data is actually **overwritten**, not just hidden — so it can't be recovered later (e.g. by a debugger, or from a crash file) as readable text.
- The earlier fix to the password-entry box — which stopped it from silently keeping a hidden "undo history" of everything typed — is working correctly. There's no leftover copy of a cleared password lurking in memory.

---

## App framework updates

- Updated to the latest version of the UI framework (`eframe`/`egui` 0.28)
- A few small internal adjustments to keep up with framework changes (these don't affect how the app looks or behaves)

## Carried-over security fixes (already in place before this release)

- Verifying a file before permanently deleting it is done in a safe, step-by-step way that can't be tricked by a corrupted or truncated file
- Decrypting a file rejects anything that was tampered with or has extra data appended after the "real" ending
- On Windows, replacing a file happens through the safest available method so a crash mid-write can't leave a corrupted file behind

---

## Version 2.0.4: Stronger protection for the password vault

Previously, each saved entry in the password vault (title, username, password, notes) sat together in one big list in memory. The problem: whenever the app added, removed, or resized that list, entries could get shuffled around in memory — and the old, no-longer-used memory locations weren't reliably cleared. That could leave stray copies of sensitive data sitting in memory longer than necessary.

**What changed:**

- Each vault entry now lives at a single, fixed spot in memory for its whole lifetime. Adding or removing entries from the list no longer moves the entries themselves around — so this specific type of "leftover copy" is no longer possible for the vault entry itself.
- The app now reserves some spare room in the vault list ahead of time (space for 64 entries), so normal everyday use won't trigger this kind of memory shuffling at all.
- Added tests to confirm: saving/loading works correctly, wrong passwords are rejected, spare room is reserved as expected, and bulk-importing entries assigns each one a unique ID.

**Known limitation (not fixed yet):** each individual piece of text inside an entry (like the password itself) still had its own separate weak spot — if that specific piece of text grew or was copied, *it* could still leave a stray copy behind, independently of the entry as a whole. Fixing that would need a different kind of storage specifically designed for secrets — which is exactly what the next version added.

---

## Version 2.0.5: Closing the last gap — a dedicated "secret" data type

This directly fixes the limitation called out in 2.0.4 above.

- Built a new, purpose-made way of storing sensitive text (like passwords) that guarantees: any time that text needs to grow or be copied, the *old* copy is always wiped clean before it's let go. Nothing gets left behind.
- Every sensitive field in a vault entry (title, username, password, URL, notes) now uses this new, safer storage method instead of ordinary text storage.
- Saving and loading vault files still works exactly the same way as before — this change is invisible from the outside; it only affects how things are protected in memory while the app is running.
- When plain, ordinary text is handed over to this safer storage (for example, when importing entries from a CSV file), the original ordinary copy is wiped clean too — so the sensitive data isn't just moved to a safer home while leaving a copy of itself behind at its old address.
- All the existing "clear this before overwriting it" safety habits elsewhere in the app still work exactly as before, layered on top of this new automatic protection.
- Added a full set of tests to confirm the new storage behaves correctly and safely in every situation: normal use, growing text, copying, clearing, and saving/loading.

This fully closes the gap identified in the previous version — no dedicated tool or extra engineering effort beyond building this one new safe-storage type was needed.

---
