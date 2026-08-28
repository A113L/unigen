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

## Version 2.0.8: Locking memory, encrypting passwords in RAM, and a safer save path

### Passwords in the vault are now encrypted while the app is running, not just scrambled

Previously (as of 2.0.5), a saved password sat in memory as plain readable text the whole time the vault was unlocked, just protected from leaving stray copies behind. Now, each vault password is kept **encrypted in memory** at all times, and is only decrypted for the brief moment it's actually needed (showing it on screen, editing it, or copying it to the clipboard) — immediately after which it's put back in its encrypted form. This is the same technique used by other well-known password managers. It's an extra layer of protection against someone inspecting the app's memory (e.g. via a crash dump or debugger); it doesn't change how the vault file itself is encrypted on disk, which is unchanged and still as strong as before.

We also fixed a subtle gap: if a piece of protected text needed to grow while it was locked in memory, the new, larger copy wasn't being re-protected — meaning that protection could silently lapse after further typing. That's now fixed.

### Extra protection against a "peeping" process, on every platform

The app now applies several operating-system-level defenses, on Windows and Mac as well as Linux, that make it harder for another program (or a crash report) to peek at its memory:
- Turns off automatic crash dumps/core dumps
- Restricts which other processes are allowed to attach a debugger to it
- On Windows specifically, also blocks a couple of known code-injection techniques

As before, if the operating system refuses one of these protections for some reason, the app simply continues without it rather than failing.

### New optional feature: staying unlocked after auto-lock, without retyping your password (Windows only)

Windows users can now opt in to a setting where, after the vault auto-locks from inactivity, clicking "Unlock" doesn't require retyping the master password. This works by having Windows itself (via a feature called DPAPI, tied to your Windows user account) securely remember it for you — the password is never stored as plain readable text while waiting to be reused. Locking manually, changing your master password, or switching to a different vault file all immediately erase this remembered password. The setting doesn't exist on Mac or Linux.

### Fixed: vault could sometimes fail to reopen after auto-lock, even with the correct password

This was a real bug, more noticeable in larger vaults (several hundred entries). Previously, when saving the vault, the app wrote the new encrypted file to disk and trusted that a successful write meant the file was actually saved correctly — but that's not always a safe assumption. Occasionally, something could go wrong between "the app finished writing" and "the file is fully, correctly saved," and the vault wouldn't be noticed as broken until the next time it tried to reopen — which, because of auto-lock, could be soon after.

**What changed:** before replacing your real vault file with the newly saved version, the app now double-checks its own work — it decrypts the new file twice (once right after saving, once again after reading it back off disk) and confirms both match. If anything looks wrong, the save is stopped immediately with a clear error, and your existing, working vault file is left completely untouched.

### Fixed: unhelpful error messages

If unlocking or saving the vault failed, the app used to show a generic error that didn't distinguish "wrong password" from other problems (like the save-path issue above, or a corrupted file). Error messages now show the full, specific reason for the failure.

### Also fixed
- A crash that could happen when clicking into a password field, caused by a mismatch in some internal tracking of which field was focused
- Password fields displayed an oversized dot for each character; switched to the standard, smaller bullet character

---
