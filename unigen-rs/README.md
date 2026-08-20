# UNIGEN

<h3>Every byte of a secret has a lifecycle, and that lifecycle ends in zeros, not hope.</h3>

UNIGEN is a Unicode password generator and local file-encryption utility:
it generates high-entropy passwords from configurable Unicode character
sets (Latin, Cyrillic, Greek, CJK & Kana, Simplified Chinese, symbols, and
more), and encrypts/decrypts/securely shreds files with a passphrase using
AES-256-GCM.

The app is written in Rust (egui) and ships as a single native binary —
with no dependency on an interpreter or runtime for any other language.

## Why Rust

Reliably wiping a passphrase from memory once it's no longer needed
requires a language that gives full control over the lifetime and layout
of bytes in memory. Rust provides that:

- **Owned, movable byte buffers** (`Vec<u8>`, `String`) whose exact
  lifetime and layout the program controls.
- The [`zeroize`](https://docs.rs/zeroize) crate provides `Zeroizing<T>`,
  a wrapper that guarantees its contents are overwritten on drop —
  including on early return and on `?`-propagated errors. It's used for
  every derived key and every raw passphrase buffer passed into a KDF in
  `src/crypto.rs`.
- The one place this guarantee doesn't fully reach is the on-screen
  passphrase entry field: `egui` has no secure-string-backed text widget,
  so that field is a plain `String`. The app minimizes the exposure
  window instead of pretending the problem away: the field is explicitly
  zeroed (not just cleared) on an inactivity timeout and unconditionally
  on window close — see `zeroize_string()` in `src/main.rs` and the
  "Clear passphrase after Ns of inactivity" setting.

## Features

- **Password generator** — pick any combination of Latin (standard +
  extended), Cyrillic, Greek, CJK & Kana, Simplified Chinese, math/currency
  symbols, and box-drawing characters; set length and how many passwords to
  generate at once. Entropy is calculated and rated (Very weak → Very
  strong) from the active character pool and length.
- **Clipboard auto-clear** — copy a generated password with one click; the
  clipboard is automatically wiped after a configurable delay (default
  20s), and only if it still contains exactly what this app put there.
- **File encryption** — AES-256-GCM with a passphrase-derived key, KDF
  choice of **Argon2id** (default — 64 MiB memory, 3 passes, 4 lanes, the
  OWASP interactive-use baseline) or PBKDF2-HMAC-SHA256 (legacy
  compatibility, 600,000 iterations). Large files (>20 MiB) are streamed
  in 4 MiB chunks instead of loaded into memory whole.
- **File decryption** — reads this app's own container format (see
  [Container formats](#container-formats) below).
- **Verify-then-shred encryption** — optionally, after encrypting a file,
  the app decrypts the result back and byte-compares it to the original
  before securely overwriting and deleting the plaintext original. If
  verification fails, the original is left in place and nothing is
  deleted.
- **Manual secure shred** — multi-pass overwrite (random data, then zeros)
  followed by deletion, for any file you point it at.
- **In-memory decrypted password-file editor** — open a small `.enc` text
  file (a saved password list), decrypt it straight into memory, search it
  by substring (e.g. "which line is the password for example.com on?"),
  edit it, and save it back re-encrypted — all without the decrypted
  content ever touching disk as plaintext. The buffer is zeroized on
  close, on save, and on app exit.
- **Passphrase auto-clear** — both the Encrypt and Decrypt passphrase
  fields are zeroized after a configurable period of inactivity (5–600s),
  independent of the clipboard auto-clear timer.
- **Linux swap-exclusion (best-effort)** — optional `mlock()` on the
  passphrase before encryption; not guaranteed on every kernel/filesystem
  configuration.
- **Dark/light theme**, resizable window, CJK/Kana glyph rendering via an
  optional local fallback font (see
  [Fonts](#fonts-for-cjk--kana--other-non-latin-scripts)).

## Building

Requires a reasonably recent Rust toolchain (stable, 2021 edition — install
from https://rustup.rs if you don't have it, or update with
`rustup update` if you already do). Some transitive dependencies now
require Cargo's `edition2024` support, which isn't available on older
distro-packaged toolchains (e.g. Ubuntu's apt `cargo` 1.75) — if
`cargo build` fails with an `edition2024` error, update via `rustup`
rather than the system package manager.

Build on a machine with internet access (crates.io fetch required):

```bash
cd unigen-rs
cargo build --release
# binary at target/release/unigen (or unigen.exe on Windows)
cargo run --release   # to build & launch directly
```

### Linux prerequisites

`eframe`/`egui`'s default backend needs the usual GUI dev headers:

```bash
sudo apt install libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
    libxcb-xfixes0-dev libxkbcommon-dev libssl-dev
```

(Package names are for Debian/Ubuntu; adjust for your distro — Fedora:
`gtk3-devel`, `libxcb-devel`, `libxkbcommon-devel`.)

### Windows / macOS

No extra system packages needed beyond a working MSVC (Windows) or Xcode
command-line tools (macOS) toolchain — `cargo build --release` is enough.

## Usage

### Password Generator tab

1. Tick the character sets you want in the pool.
2. Set password length and how many to generate.
3. Click **Generate**. Each result shows its estimated entropy and rating.
4. **Copy** puts one password on the clipboard (auto-clears after the
   configured delay); **Save to File** writes the whole list to a plaintext
   file, after which you're offered a one-click **Encrypt & Shred** to
   protect that file with a passphrase and securely delete the plaintext
   original once the encrypted copy is verified.

### File Protector tab

- **Encrypt File** — pick a file, choose a KDF (Argon2id recommended),
  enter a passphrase (min 8 characters), optionally enable
  verify-then-shred-original, then **Encrypt**. Files over 20 MiB are
  streamed automatically.
- **Decrypt File** — pick a `.enc` file, enter its passphrase, **Decrypt &
  Save**.
- **Manual Secure Shred** — pick any file, confirm, and it's multi-pass
  overwritten then deleted. See the caveat below about SSDs.
- **Password File Editor** (bottom of the tab) — **Open .enc file to
  edit…**, enter the passphrase once, and the decrypted text appears in an
  editable box. Type in the **Search** field to filter down to just the
  matching lines (e.g. a domain name) instead of scrolling the whole file;
  clear the search to go back to full editing. **Save (re-encrypt)** writes
  the edited content back over the original file (atomically — see
  [Write safety](#write-safety--tmp-file-handling)); **Close** discards the
  in-memory buffer (with confirmation if there are unsaved changes) and
  zeroizes it.

### A note on SSDs and secure shredding

Multi-pass overwrite reliably destroys data on traditional spinning disks.
On SSDs, and on copy-on-write or journaling filesystems (e.g. btrfs, ZFS,
APFS), wear leveling and snapshots mean old data may still be recoverable
at the hardware level even after a "successful" overwrite. Use full-disk
encryption or a vendor secure-erase tool for guarantees on that hardware —
this app's shred feature is defense-in-depth, not a substitute for that.

## Security model

### Encryption

- **Cipher**: AES-256-GCM (authenticated encryption — tampering with
  ciphertext is detected, not just decryption failing on wrong key).
- **Key derivation**: Argon2id by default (64 MiB memory, 3 passes, 4
  lanes) or PBKDF2-HMAC-SHA256 (600,000 iterations) if selected. A random
  16-byte salt is generated per encryption.
- **AAD binding**: every AES-GCM call binds `MAGIC || FORMAT_VERSION ||
  kdf_id` as additional authenticated data (and, for streamed files, the
  per-chunk counter and final-chunk flag too), so a ciphertext produced for
  one format/KDF/chunk position can't be silently reinterpreted as another.
- **Nonces**: a fresh random 96-bit nonce per encryption (per chunk, for
  streamed files) — never reused for a given key.

### Passphrase handling

Covered in detail above — see [Why Rust](#why-rust). Short version:
derived keys and raw passphrase bytes passed into KDFs are wrapped in
`zeroize::Zeroizing` and guaranteed-wiped on drop; the on-screen entry
field is a plain `String` (no toolkit alternative exists) but is
explicitly zeroized on inactivity timeout and on close.

### Write safety / `.tmp` file handling

Every file this app writes — encrypted output, decrypted output, the
re-encrypted password file from the editor — is first written to a
uniquely-named temp file: `<intended-name>.<unix-nanoseconds>.<random-64-
bit-hex>.unigen-tmp`, written as a sibling of the real output path, fsynced,
and only `rename()`d over the destination once the write fully succeeds
(see `crypto::unique_tmp_path`). A hard kill mid-write can at worst leave
one identifiably-named orphan file behind; it can never collide with or
overwrite some unrelated file already in that directory, and it can never
leave a corrupted "finished" file in the destination's place.

The app also asks for confirmation before closing if an encrypt/decrypt/
shred job is still running, rather than silently killing it.

### Container formats

```
Small-file blob (this app, "UGR1"):
  MAGIC(4="UGR1") + FORMAT_VERSION(1) + kdf_id(1) + salt(16) + nonce(12) + ciphertext
  AAD = MAGIC || FORMAT_VERSION || kdf_id
  On disk: base64-encoded text (allows copy/paste of small encrypted blobs)

Streaming format (this app, "UGRS"):
  MAGIC(4="UGRS") + per-4MiB-chunk: nonce(12) + ciphertext + tag
  AAD per chunk = MAGIC || chunk_index || is_final_chunk
```

Decryption also accepts, for backward compatibility with files produced by
an earlier version of this tool that was written in Python:

```
Legacy, post-Argon2id era ("UG2"):
  MAGIC(4=b"UG2\0") + kdf_id(1) + salt(16) + iv(12) + ciphertext   (AAD=None)

Legacy, pre-Argon2id era (no magic):
  salt(16) + iv(12) + ciphertext   (always PBKDF2, AAD=None)
```

This app **only ever writes** its own `UGR1`/`UGRS` formats — the legacy
formats are read-only compatibility, not something new files use, because
fixing the missing-AAD issue in those formats properly required a
wire-format change (there's no way to add AAD binding to an
already-written `AAD=None` ciphertext).

## Fonts for CJK/Kana & other non-Latin scripts

`egui`'s bundled `default_fonts` (Ubuntu-Light + a Latin/emoji fallback)
has no glyphs for Han, Hiragana, or Katakana — so passwords generated from
the "CJK & Kana" or "Simplified Chinese" character sets are correct data,
but render as tofu boxes (▯) without an extra font.

At startup, the app recursively scans an `assets/fonts/` folder (next to
the executable for a packaged build, or the crate root for `cargo run`)
and registers any font it finds as a **glyph fallback** — tried only for
characters the default font can't render, so Latin/Cyrillic/Greek keep
using the crisp bundled font. It understands the usual Google Fonts
download layout (e.g.
`assets/fonts/Noto_Sans_JP/static/NotoSansJP-Regular.ttf`), picks the
Regular weight per family, and deduplicates by family so the same font
showing up twice in nested folders is only loaded once. If the folder is
empty or missing, this is a silent no-op — nothing else about the app
depends on it.

To fix CJK/Kana rendering, download **Noto Sans JP** (covers Kana + common
Han) and/or **Noto Sans SC** (fuller Simplified Chinese coverage) from
Google Fonts and drop the folder into `assets/fonts/` next to the binary —
see `assets/fonts/README.md` for exact links and layout. No recompilation
needed.

## Project layout

```
unigen-rs/
├── Cargo.toml
├── README.md
├── assets/
│   └── fonts/
│       └── README.md   — what font(s) to add, and why
└── src/
    ├── main.rs      — eframe/egui GUI, background job orchestration,
    │                   password-file editor, font loading
    ├── crypto.rs    — KDFs, AEAD blob/streaming container formats
    ├── charsets.rs  — password generator character sets & entropy math
    └── shred.rs     — secure multi-pass file shredding
```
