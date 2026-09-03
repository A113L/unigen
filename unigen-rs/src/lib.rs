//! UNIGEN library crate.
//!
//! This crate exists so the security-critical modules (`crypto`, `vault`,
//! `secret`, `mem_cipher`, `dpapi`, `shred`, `mem_lock`,
//! `process_isolation`, `charsets`, `secure_text_edit`) can be linked and
//! tested *without* pulling in `eframe`'s windowing/OpenGL runtime, which
//! Miri can't execute (FFI/syscalls it doesn't model) and which `cargo
//! fuzz`/ASan builds have no reason to touch either.
//!
//! `src/main.rs` is now a thin binary: it declares only the GUI-only
//! `theme` module and the `UnigenApp` eframe::App impl inline, and pulls
//! everything else in via `use unigen::{crypto, vault, ...}`.
//!
//! IMPORTANT: this is a *refactor*, not a behavior change. Every `mod`
//! declaration below is exactly the same module, at exactly the same
//! path, that used to be declared directly in `main.rs`. No module's
//! internal code changed as part of this split — only where the `mod`
//! keyword lives.
//!
//! `egui` (the immediate-mode UI *library*, used here only for the
//! `egui::TextBuffer` trait impl on `SecretString` in `secret.rs`) is a
//! plain dependency of this lib crate and compiles fine under
//! Miri/ASan/fuzz — it does no windowing/OS calls itself. `eframe` (which
//! *does* open windows, create a GL context, etc.) is intentionally never
//! imported anywhere in this crate; it's used exclusively by `main.rs`.

pub mod charsets;
pub mod crypto;
pub mod dpapi;
pub mod mem_cipher;
pub mod mem_lock;
pub mod process_isolation;
pub mod secret;
pub mod secure_text_edit;
pub mod shred;
pub mod vault;
