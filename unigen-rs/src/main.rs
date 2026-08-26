//! UNIGEN — Unicode Password Utility (Rust Edition)
//!
//! Rust/egui rewrite of the original Tkinter application. See README.md for
//! the list of behavioural changes made during the port (new container
//! format with AAD, unique per-run temp file names, real passphrase
//! zeroization).

mod secure_alloc;
mod charsets;
mod crypto;
mod secret;
mod shred;
mod vault;

use charsets::{
    all_charsets, build_pool, calculate_entropy, estimate_passphrase_entropy, rate_entropy, CharSet,
};
use eframe::egui;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};
use secret::SecretString;
use vault::VaultEntry;
use zeroize::{Zeroize, Zeroizing};

/// Exact hex palette from the Python original's `THEMES` dict, so the two
/// versions render identically rather than falling back to egui's stock
/// dark/light visuals.
mod theme {
    use eframe::egui::Color32;

    /// text_secondary/text_faint aren't wired into egui's global `Visuals`
    /// in `apply()` below — egui has no direct Visuals slot for them.
    /// success/danger/warning are used directly at call sites that need a
    /// rating color (e.g. the entropy-rating label) rather than through
    /// Visuals, so all three stay in this struct as the single source of
    /// truth matching the Python `THEMES` dict.
    #[allow(dead_code)]
    pub struct Palette {
        pub bg: Color32,
        pub surface: Color32,
        pub surface_alt: Color32,
        pub border: Color32,
        pub input_bg: Color32,
        pub text: Color32,
        pub text_secondary: Color32,
        pub text_faint: Color32,
        pub accent: Color32,
        pub accent_hover: Color32,
        pub success: Color32,
        pub danger: Color32,
        pub warning: Color32,
        pub button_bg: Color32,
    }

    pub const DARK: Palette = Palette {
        bg: Color32::from_rgb(0x0b, 0x0d, 0x13),
        surface: Color32::from_rgb(0x12, 0x15, 0x1d),
        surface_alt: Color32::from_rgb(0x17, 0x1b, 0x26),
        border: Color32::from_rgb(0x23, 0x28, 0x38),
        input_bg: Color32::from_rgb(0x1b, 0x21, 0x30),
        text: Color32::from_rgb(0xe8, 0xeb, 0xf2),
        text_secondary: Color32::from_rgb(0x8b, 0x93, 0xa5),
        text_faint: Color32::from_rgb(0x5b, 0x64, 0x78),
        accent: Color32::from_rgb(0xf5, 0xa6, 0x23),
        accent_hover: Color32::from_rgb(0xd8, 0x8f, 0x14),
        success: Color32::from_rgb(0x2d, 0xd4, 0xbf),
        danger: Color32::from_rgb(0xf0, 0x57, 0x6b),
        warning: Color32::from_rgb(0xf5, 0xa6, 0x23),
        button_bg: Color32::from_rgb(0x23, 0x28, 0x38),
    };

    pub const LIGHT: Palette = Palette {
        bg: Color32::from_rgb(0xf4, 0xf5, 0xf7),
        surface: Color32::from_rgb(0xff, 0xff, 0xff),
        surface_alt: Color32::from_rgb(0xee, 0xf0, 0xf4),
        border: Color32::from_rgb(0xdd, 0xe1, 0xe8),
        input_bg: Color32::from_rgb(0xee, 0xf0, 0xf4),
        text: Color32::from_rgb(0x12, 0x15, 0x1d),
        text_secondary: Color32::from_rgb(0x5b, 0x64, 0x78),
        text_faint: Color32::from_rgb(0x8b, 0x93, 0xa5),
        accent: Color32::from_rgb(0xb4, 0x74, 0x0e),
        accent_hover: Color32::from_rgb(0x96, 0x60, 0x0b),
        success: Color32::from_rgb(0x0d, 0x94, 0x88),
        danger: Color32::from_rgb(0xdc, 0x26, 0x26),
        warning: Color32::from_rgb(0xb4, 0x74, 0x0e),
        button_bg: Color32::from_rgb(0xdd, 0xe1, 0xe8),
    };

    /// Apply the palette to egui's global Visuals so every default-styled
    /// widget (panels, buttons, inputs, separators) picks it up, matching
    /// how the Python version recolors every ttk/tk widget via its theme
    /// dict rather than special-casing three accent colors.
    pub fn apply(ctx: &eframe::egui::Context, dark: bool) {
        let p = if dark { &DARK } else { &LIGHT };
        let mut visuals = if dark {
            eframe::egui::Visuals::dark()
        } else {
            eframe::egui::Visuals::light()
        };
        visuals.override_text_color = Some(p.text);
        visuals.panel_fill = p.bg;
        visuals.window_fill = p.surface;
        visuals.faint_bg_color = p.surface_alt;
        visuals.extreme_bg_color = p.input_bg;
        visuals.widgets.noninteractive.bg_fill = p.surface;
        visuals.widgets.noninteractive.bg_stroke.color = p.border;
        visuals.widgets.inactive.bg_fill = p.button_bg;
        visuals.widgets.hovered.bg_fill = p.accent_hover;
        visuals.widgets.active.bg_fill = p.accent;
        visuals.selection.bg_fill = p.accent;
        visuals.hyperlink_color = p.accent;
        ctx.set_visuals(visuals);
    }
}

fn main() -> eframe::Result<()> {
    // MEMORY-RESIDUE fix: ask the kernel not to write a core dump for this
    // process. Without this, a crash (segfault, panic-induced abort, an
    // operator running `kill -SEGV`/`gcore` against the PID, etc.) can
    // leave a coredump file on disk containing every secret currently
    // live in memory — decrypted vault entries, the passphrase actually
    // being typed, decrypted editor content — completely bypassing every
    // `Zeroize`/`SecretString` protection in this app, since none of
    // that runs during an abnormal process termination. `PR_SET_DUMPABLE`
    // is Linux-only and best-effort (a debugger with `ptrace` capability
    // can still attach and read process memory directly; this only closes
    // the "crash leaves a readable file behind" case, and only on Linux).
    #[cfg(target_os = "linux")]
    disable_core_dumps();

    // Mirror the Python original: size the window relative to the screen
    // (capped to a sane range) and center it, instead of a fixed size.
    // A more compact default now that the scroll area properly fills its
    // space (see auto_shrink fix above) rather than needing extra window
    // height to avoid feeling cramped. Still resizable/centered, with a
    // min size that keeps both tabs usable without overflow.
    // Taller than before to make room for the in-app decrypted password
    // editor at the bottom of the File Protector tab without cramping the
    // Encrypt/Decrypt columns above it.
    let (win_w, win_h) = (940.0_f32, 760.0_f32);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([win_w, win_h])
            .with_min_inner_size([860.0, 680.0]),
        centered: true,
        // Reverted to the glow (OpenGL) backend after the wgpu backend
        // proved unreliable on virtual-GPU driver stacks seen in VMs:
        // wgpu's GL fallback choked on shader translation on VirtualBox's
        // Mesa/SVGA3D driver, and pinning to DX12 hit a known wgpu 0.19.x
        // bug (upstream issue gfx-rs/wgpu#5225/#5294) where DX12 surface
        // creation panics instead of erroring out cleanly when no usable
        // DX12 adapter/surface is available. glow at least runs
        // end-to-end on this driver stack, even if imperfectly — see the
        // multisampling/vsync notes below for mitigations, and the
        // project README for context on why this doesn't affect real
        // (non-virtualized) Windows machines.
        renderer: eframe::Renderer::Glow,
        // Disabling multisampling avoids an MSAA resolve path that some
        // buggy/virtual GL drivers (e.g. VirtualBox's Mesa/SVGA3D) mis-
        // render as warped/garbled glyph edges. egui's text is already
        // anti-aliased via its own coverage-based rasterizer, so hardware
        // MSAA isn't needed for readable text.
        multisampling: 0,
        // Depth/stencil buffers are unused by egui's 2D immediate-mode
        // rendering; requesting them is one more thing a shaky driver can
        // get wrong.
        depth_buffer: 0,
        stencil_buffer: 0,
        // Avoid vsync-related presentation-timing quirks (occasionally
        // seen as tearing or stale/partial frames) on virtualized display
        // adapters that don't implement swap-interval correctly.
        vsync: false,
        ..Default::default()
    };
    eframe::run_native(
        "UNIGEN — Unicode Password Utility",
        options,
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx, true);
            load_custom_fonts(&cc.egui_ctx);
            Ok(Box::new(UnigenApp::new()))
        }),
    )
}

/// egui's `default_fonts` feature ships Ubuntu-Light plus a Latin/emoji
/// fallback — it has no Han/Hiragana/Katakana glyphs, so the "CJK & Kana"
/// charset renders as tofu boxes even though the correct code points are
/// generated. This recursively scans an `assets/fonts` folder (next to the
/// executable for a packaged build, or the crate root for `cargo run`) —
/// so it finds fonts however deep they're nested, e.g. Google Fonts' usual
/// `assets/fonts/Noto_Sans_JP/static/NotoSansJP-Regular.ttf` layout — and
/// registers one Regular-weight file per family as a glyph-fallback font:
/// tried only for characters the default font can't render, so Latin/
/// Cyrillic/Greek keep using the crisp bundled font. Variable-font files
/// and non-Regular weights (Bold/Light/Black/...) are skipped so a Google
/// Fonts download with 9+ weight files per family doesn't balloon startup
/// time or memory for what's only ever used as a fallback. If no fonts are
/// found this is a silent no-op — see assets/fonts/README.md.
fn load_custom_fonts(ctx: &eframe::egui::Context) {
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("assets/fonts"));
        }
    }
    candidates.push(PathBuf::from("assets/fonts"));
    candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/fonts"));

    let Some(fonts_dir) = candidates.into_iter().find(|d| d.is_dir()) else {
        return;
    };

    // Walk the whole tree (there's no depth limit on how Google Fonts zips
    // nest things — see the Noto_Sans_JP/static/*.ttf and the doubled-up
    // Noto_Sans_JP,Noto_Sans_SC/Noto_Sans_JP/static/*.ttf layouts) instead
    // of only reading the top level.
    let mut all_files = Vec::new();
    let mut stack = vec![fonts_dir];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                all_files.push(path);
            }
        }
    }

    // Prefer a "-Regular.ttf"/"-Regular.otf" per family (dedup by the part
    // of the filename before "-Regular", so the same family showing up
    // twice under a nested/duplicated folder only gets loaded once). Fall
    // back to any font file at all only if no "Regular" weight is found
    // anywhere, so a differently-named single-file font still works.
    let is_font_ext = |p: &std::path::Path| {
        p.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("ttf") || e.eq_ignore_ascii_case("otf"))
            .unwrap_or(false)
    };

    let mut chosen: Vec<(String, PathBuf)> = Vec::new();
    let mut seen_family = HashSet::new();
    for path in all_files.iter().filter(|p| is_font_ext(p)) {
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(family) = stem
            .strip_suffix("-Regular")
            .or_else(|| stem.strip_suffix("-regular"))
        {
            if seen_family.insert(family.to_string()) {
                chosen.push((family.to_string(), path.clone()));
            }
        }
    }
    if chosen.is_empty() {
        // Nothing tagged "Regular" anywhere — fall back to any font files
        // found (e.g. a bare NotoSansJP-VariableFont_wght.ttf with no
        // static/ folder), one per distinct file name so we don't still
        // pull in unrelated duplicates.
        for path in all_files.into_iter().filter(|p| is_font_ext(p)) {
            let key = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if seen_family.insert(key.clone()) {
                chosen.push((key, path));
            }
        }
    }

    let mut fonts = egui::FontDefinitions::default();
    let mut loaded_any = false;
    for (family_key, path) in chosen {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        fonts
            .font_data
            .insert(family_key.clone(), egui::FontData::from_owned(bytes));
        // Push to the *end* of both families' fallback lists so the
        // default font is always tried first and this only fills in
        // glyphs (e.g. CJK/Kana) that the default font is missing.
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .push(family_key.clone());
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .push(family_key);
        loaded_any = true;
    }
    if loaded_any {
        ctx.set_fonts(fonts);
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Generator,
    FileProtector,
    Vault,
}

/// Messages sent from a background worker thread back to the UI thread.
enum JobMsg {
    Progress(f32, String),
    /// Sent by `run_encrypt_job`'s small-file (in-memory blob) path when
    /// it needs the user to pick a save location. Carries a suggested
    /// default filename and a one-shot reply channel; the job thread
    /// blocks on `reply_rx.recv()` after sending this, so it costs
    /// nothing extra to wait — see the comment at the send site in
    /// `run_encrypt_job` for the full rationale.
    NeedSavePath(String, Sender<Option<PathBuf>>),
    Done(Result<String, String>),
}

/// What to do once a `spawn_dialog`-launched native file dialog reports
/// back which path (if any) the user picked. See `spawn_dialog`'s doc
/// comment for why this exists: the underlying `rfd::FileDialog` call
/// must never run directly on the UI thread.
enum PendingPick {
    OpenVault,
    NewVault,
    ImportCsv,
    EncryptSelectFile,
    /// Streaming-encrypt output path. Carries everything `start_encrypt`
    /// had already gathered before the dialog was spawned, since none of
    /// it can be re-read from `self` once the dialog closes (the button
    /// click that triggered this may be several frames in the past by
    /// then, and e.g. `self.enc_pwd` could have auto-cleared).
    EncryptSaveOutput {
        in_path: PathBuf,
        pwd: Zeroizing<String>,
        kdf_id: u8,
        shred_after: bool,
    },
    DecryptSelectFile,
    /// Decrypt output path, same rationale as `EncryptSaveOutput`.
    DecryptSaveOutput {
        in_path: PathBuf,
        pwd: Zeroizing<String>,
        is_streaming: bool,
    },
    ShredSelectFile,
    EditorSelectFile,
    SaveGeneratedPasswords,
    /// The `run_encrypt_job` background thread (small-file/in-memory
    /// blob path) is blocked waiting to know where to save. Once the
    /// dialog resolves, the chosen path (or `None` if cancelled) is
    /// forwarded to it over this one-shot reply channel so it can
    /// finish — see `JobMsg::NeedSavePath`.
    EncryptSmallFileSavePath(Sender<Option<PathBuf>>),
}

struct BackgroundJob {
    rx: Receiver<JobMsg>,
    last_status: String,
    progress: Option<f32>,
}

struct UnigenApp {
    tab: Tab,
    dark_mode: bool,

    // ---- Generator tab ----
    charsets: Vec<CharSet>,
    charset_enabled: Vec<bool>,
    length: u32,
    count: u32,
    generated: Vec<Zeroizing<String>>,
    gen_status: String,
    last_saved_password_path: Option<PathBuf>,
    encrypt_shred_prompt_open: bool,
    // SECURITY (memory-residue fix): every UI-editable secret field in
    // this struct is `SecretString`, not `String`/`Zeroizing<String>`.
    // `SecretString` implements `egui::TextBuffer` (see secret.rs), so
    // `TextEdit` writes directly into its wipe-on-relocate buffer —
    // closing the gap where a plain `String` field reallocates on every
    // keystroke and leaves the old, unzeroized buffer for the allocator
    // to hand out again. `Zeroizing<String>` only wiped on final Drop;
    // it never covered the copies made *while the user was still
    // typing*, which is exactly the longest-lived, most sensitive
    // window for a passphrase.
    encrypt_shred_pwd: SecretString,

    // ---- Clipboard / auto-clear ----
    clipboard: Option<arboard::Clipboard>,
    autoclear_enabled: bool,
    autoclear_seconds: u32,
    autoclear_deadline: Option<Instant>,
    autoclear_expected: Option<String>,
    clip_status: String,

    // ---- File Protector: Encrypt ----
    kdf_choice: u8,
    enc_file: Option<PathBuf>,
    enc_pwd: SecretString,
    enc_pwd_last_edit: Instant,
    enc_pwd_autoclear: bool,
    shred_after: bool,
    enc_status: String,
    /// Linux-only: best-effort attempt to advise the OS to exclude
    /// decrypted/plaintext temp buffers from swap (mirrors the Python
    /// `linux_try_exclusion` setting; same "best effort, not a guarantee"
    /// caveat applies — see crypto::try_mlock equivalents).
    linux_try_exclusion: bool,

    // ---- File Protector: Decrypt ----
    dec_file: Option<PathBuf>,
    dec_pwd: SecretString,
    dec_pwd_last_edit: Instant,
    dec_pwd_autoclear: bool,
    dec_status: String,

    // ---- File Protector: Manual shred ----
    shred_target: Option<PathBuf>,
    shred_confirm_open: bool,
    shred_status: String,

    // ---- File Protector: in-memory decrypted editor ----
    /// Editor is a strictly in-memory view: the decrypted plaintext is
    /// never written to disk, only ever kept in `editor_content` and
    /// zeroized (not just cleared) the moment the editor is closed, the
    /// content is re-encrypted, or the app exits.
    editor_open: bool,
    editor_source: Option<PathBuf>,
    editor_content: SecretString,
    editor_original_content: SecretString,
    editor_pwd: SecretString,
    editor_kdf: u8,
    /// KDF read from the opened file's own header (`None` for legacy
    /// Python-format files, which have no discoverable KDF marker other
    /// than "always PBKDF2" / a magic-tagged byte). Used to show the user
    /// whether hitting Save will change the file's KDF from what it
    /// currently has on disk.
    editor_source_kdf: Option<u8>,
    editor_search: String,
    editor_status: String,
    editor_confirm_close: bool,
    /// Passphrase prompt shown before decrypting into the editor.
    editor_open_prompt: bool,
    editor_open_target: Option<PathBuf>,
    editor_open_pwd: SecretString,
    editor_open_error: String,

    // ---- Vault (password manager) ----
    /// Path to the vault's encrypted file on disk (persisted across
    /// runs like other path fields; `None` until the user picks/creates
    /// one from the vault tab's "Open/Create vault..." button).
    vault_path: Option<PathBuf>,
    vault_unlocked: bool,
    /// Master password input, before unlock. Held in `Zeroizing<String>`
    /// from the moment it's typed (rather than a plain `String` that's
    /// only zeroized manually after use) so there's no window where a
    /// `Vec`/`String` reallocation elsewhere could copy the plaintext to
    /// a new heap address before the manual zeroize ever runs; `Drop`
    /// guarantees the wipe even on an early-return path that forgets to
    /// call it explicitly.
    vault_master_pwd: SecretString,
    /// Decrypted entries, only populated while unlocked. Wrapped so the
    /// whole list — including every entry's password/notes strings via
    /// `VaultEntry`'s manual `Zeroize` impl — is scrubbed the moment it's
    /// replaced or the app drops it (e.g. on lock or exit).
    ///
    /// Each entry is individually `Box`ed: growing/shrinking this `Vec`
    /// then only ever moves 8-byte pointers, never `VaultEntry` contents,
    /// closing the stray-unzeroized-copy gap a plain `Vec<VaultEntry>`
    /// had on resize. See the note on `impl Zeroize for VaultEntry` in
    /// `vault.rs` for the full explanation and its remaining caveat.
    vault_entries: Zeroizing<Vec<Box<VaultEntry>>>,
    vault_kdf: u8,
    vault_status: String,
    vault_dirty: bool,
    vault_search: String,
    /// Id of the entry currently shown in the edit pane, if any.
    vault_selected: Option<u64>,
    /// Scratch buffers for the edit pane; copied into the real entry on
    /// explicit "Save entry" so partial edits can be discarded on cancel.
    /// `Zeroizing<String>` from creation (not just zeroized manually
    /// before being overwritten/cleared) for the same reason as
    /// `vault_master_pwd` above — `vault_edit_password` in particular
    /// holds a plaintext credential for as long as the entry is open.
    vault_edit_title: SecretString,
    vault_edit_username: SecretString,
    vault_edit_password: SecretString,
    vault_edit_url: SecretString,
    vault_edit_notes: SecretString,
    vault_reveal_password: bool,
    vault_confirm_delete: Option<u64>,
    /// Auto-lock: mirrors the existing passphrase inactivity-clear
    /// pattern, but locks (re-encrypts and drops plaintext entries from
    /// memory) instead of just clearing a text field.
    vault_last_activity: Instant,
    vault_autolock_seconds: u32,

    // ---- Vault: change master password ----
    vault_change_pwd_open: bool,
    vault_change_pwd_current: SecretString,
    vault_change_pwd_new: SecretString,
    vault_change_pwd_confirm: SecretString,
    vault_change_pwd_error: String,

    // ---- Vault: CSV import ----
    vault_import_open: bool,
    vault_import_source: vault::CsvSource,
    vault_import_status: String,

    // ---- Background job tracking ----
    busy_ops: HashSet<&'static str>,
    encrypt_job: Option<BackgroundJob>,
    decrypt_job: Option<BackgroundJob>,
    shred_job: Option<BackgroundJob>,
    /// A native file dialog currently running on a background thread
    /// (see `spawn_dialog`'s doc comment), and what to do with the
    /// chosen path once it reports back.
    pending_pick: Option<(Receiver<Option<PathBuf>>, PendingPick)>,

    pwd_autoclear_seconds: u32,

    show_close_confirm: bool,
}

impl UnigenApp {
    fn new() -> Self {
        let sets = all_charsets();
        let enabled: Vec<bool> = sets.iter().map(|s| s.enabled_by_default).collect();
        Self {
            tab: Tab::Generator,
            dark_mode: true,
            charsets: sets,
            charset_enabled: enabled,
            length: 20,
            count: 3,
            generated: Vec::new(),
            gen_status: String::new(),
            last_saved_password_path: None,
            encrypt_shred_prompt_open: false,
            encrypt_shred_pwd: SecretString::new(),
            clipboard: arboard::Clipboard::new().ok(),
            autoclear_enabled: true,
            autoclear_seconds: 20,
            autoclear_deadline: None,
            autoclear_expected: None,
            clip_status: String::new(),
            kdf_choice: crypto::DEFAULT_KDF, // Argon2id first / default, per updated guidance
            enc_file: None,
            enc_pwd: SecretString::new(),
            enc_pwd_last_edit: Instant::now(),
            enc_pwd_autoclear: true,
            shred_after: true,
            enc_status: String::new(),
            linux_try_exclusion: false,
            dec_file: None,
            dec_pwd: SecretString::new(),
            dec_pwd_last_edit: Instant::now(),
            dec_pwd_autoclear: true,
            dec_status: String::new(),
            shred_target: None,
            shred_confirm_open: false,
            shred_status: String::new(),
            editor_open: false,
            editor_source: None,
            editor_content: SecretString::new(),
            editor_original_content: SecretString::new(),
            editor_pwd: SecretString::new(),
            editor_kdf: crypto::DEFAULT_KDF,
            editor_source_kdf: None,
            editor_search: String::new(),
            editor_status: String::new(),
            editor_confirm_close: false,
            editor_open_prompt: false,
            editor_open_target: None,
            editor_open_pwd: SecretString::new(),
            editor_open_error: String::new(),
            vault_path: None,
            vault_unlocked: false,
            vault_master_pwd: SecretString::new(),
            vault_entries: Zeroizing::new(Vec::new()),
            vault_kdf: crypto::DEFAULT_KDF,
            vault_status: String::new(),
            vault_dirty: false,
            vault_search: String::new(),
            vault_selected: None,
            vault_edit_title: SecretString::new(),
            vault_edit_username: SecretString::new(),
            vault_edit_password: SecretString::new(),
            vault_edit_url: SecretString::new(),
            vault_edit_notes: SecretString::new(),
            vault_reveal_password: false,
            vault_confirm_delete: None,
            vault_last_activity: Instant::now(),
            vault_autolock_seconds: 120,
            vault_change_pwd_open: false,
            vault_change_pwd_current: SecretString::new(),
            vault_change_pwd_new: SecretString::new(),
            vault_change_pwd_confirm: SecretString::new(),
            vault_change_pwd_error: String::new(),
            vault_import_open: false,
            vault_import_source: vault::CsvSource::Generic,
            vault_import_status: String::new(),
            busy_ops: HashSet::new(),
            encrypt_job: None,
            decrypt_job: None,
            shred_job: None,
            pending_pick: None,
            pwd_autoclear_seconds: 30,
            show_close_confirm: false,
        }
    }

    fn palette(&self) -> &'static theme::Palette {
        if self.dark_mode {
            &theme::DARK
        } else {
            &theme::LIGHT
        }
    }

    fn active_pool(&self) -> Vec<char> {
        build_pool(&self.charset_enabled, &self.charsets)
    }

    /// Copies `text` to the clipboard and unconditionally schedules an
    /// auto-clear — used for single-password/single-line copies (the
    /// generated-password list and the editor's search results), where the
    /// copied value is sensitive enough that it should always be cleared
    /// regardless of the general `autoclear_enabled` toggle.
    ///
    /// BUG FIX: this used to hard-code a 20s clear delay, ignoring the
    /// user's configured `autoclear_seconds` (e.g. setting the slider to
    /// 60s had no effect on these particular "Copy" buttons, only on
    /// "Copy All"). It now uses the same configured duration as
    /// `copy_to_clipboard` — "always clears" and "clears using the
    /// configured delay" are independent choices, and only the former is
    /// intentional here.
    fn copy_to_clipboard_20s(&mut self, text: &str) {
        if let Some(cb) = self.clipboard.as_mut() {
            if cb.set_text(text.to_string()).is_ok() {
                self.autoclear_deadline =
                    Some(Instant::now() + Duration::from_secs(self.autoclear_seconds as u64));
                self.autoclear_expected = Some(text.to_string());
                self.editor_status = format!(
                    "Copied line. Clipboard clears in {}s.",
                    self.autoclear_seconds
                );
                return;
            }
        }
        self.editor_status = "Copy failed: no clipboard access.".to_string();
    }

    fn copy_to_clipboard(&mut self, text: &str) {
        if let Some(cb) = self.clipboard.as_mut() {
            if cb.set_text(text.to_string()).is_ok() {
                self.clip_status = if self.autoclear_enabled {
                    self.autoclear_deadline =
                        Some(Instant::now() + Duration::from_secs(self.autoclear_seconds as u64));
                    self.autoclear_expected = Some(text.to_string());
                    format!("Copied. Auto-clears in {}s.", self.autoclear_seconds)
                } else {
                    self.autoclear_deadline = None;
                    self.autoclear_expected = None;
                    "Copied.".to_string()
                };
                return;
            }
        }
        self.clip_status = "Copy failed: no clipboard access.".to_string();
    }

    // ---- Vault (password manager) ----

    fn vault_touch(&mut self) {
        self.vault_last_activity = Instant::now();
    }

    fn tick_vault_autolock(&mut self) {
        if self.vault_unlocked
            && self.vault_autolock_seconds > 0
            && self.vault_last_activity.elapsed()
                >= Duration::from_secs(self.vault_autolock_seconds as u64)
        {
            self.lock_vault(true);
            self.vault_status = "Vault auto-locked after inactivity.".to_string();
        }
    }

    /// Unlock (or create) the vault at `self.vault_path` using
    /// `self.vault_master_pwd`. Leaves the master-password field zeroized
    /// either way, matching how every other passphrase field in this app
    /// is handled once it's been consumed.
    fn unlock_vault(&mut self) {
        let Some(path) = self.vault_path.clone() else {
            self.vault_status = "Choose a vault file first.".to_string();
            return;
        };
        let mut pwd = std::mem::take(&mut self.vault_master_pwd);
        let is_new = !path.exists();
        let result = vault::open_or_create(&path, &pwd);
        pwd.zeroize();
        match result {
            Ok(entries) => {
                self.vault_entries = Zeroizing::new(entries);
                self.vault_unlocked = true;
                self.vault_dirty = false;
                self.vault_selected = None;
                self.vault_status = if is_new {
                    "New vault created. It's saved once you add and save an entry.".to_string()
                } else {
                    format!("Vault unlocked ({} entries).", self.vault_entries.len())
                };
                self.vault_touch();
            }
            Err(e) => {
                self.vault_status = format!("Unlock failed: {e}");
            }
        }
    }

    /// Save the current in-memory entries back to disk, re-encrypting
    /// with the same master password used to unlock. Requires the vault
    /// to still be unlocked; callers should prompt for the master
    /// password again if it's ever needed for a from-scratch save.
    fn save_vault_with(&mut self, master_password: &str) {
        let Some(path) = self.vault_path.clone() else {
            self.vault_status = "No vault file selected.".to_string();
            return;
        };
        match vault::write_vault_file(&path, master_password, &self.vault_entries, self.vault_kdf)
        {
            Ok(()) => {
                self.vault_dirty = false;
                self.vault_status = format!("Saved ({} entries).", self.vault_entries.len());
            }
            Err(e) => {
                self.vault_status = format!("Save failed: {e}");
            }
        }
    }

    /// Lock the vault: drop decrypted entries (zeroizing them) and clear
    /// the edit pane. If `warn_if_dirty` and there are unsaved changes,
    /// locking still proceeds — losing an unsaved edit on an inactivity
    /// timeout is preferable to leaving plaintext credentials sitting in
    /// memory indefinitely — but the status line says so.
    fn lock_vault(&mut self, warn_if_dirty: bool) {
        if !self.vault_unlocked {
            return;
        }
        let had_unsaved = self.vault_dirty;
        self.vault_entries = Zeroizing::new(Vec::new());
        self.vault_unlocked = false;
        self.vault_dirty = false;
        self.vault_selected = None;
        self.clear_vault_edit_buffers();
        self.close_change_pwd_dialog();
        self.vault_import_open = false;
        self.vault_import_status.clear();
        if warn_if_dirty && had_unsaved {
            self.vault_status = "Locked. Unsaved changes were discarded.".to_string();
        }
    }

    fn clear_vault_edit_buffers(&mut self) {
        self.vault_edit_title.zeroize();
        self.vault_edit_username.zeroize();
        self.vault_edit_password.zeroize();
        self.vault_edit_url.zeroize();
        self.vault_edit_notes.zeroize();
        self.vault_reveal_password = false;
    }

    fn vault_select(&mut self, id: u64) {
        if let Some(e) = self.vault_entries.iter().find(|e| e.id == id) {
            self.vault_edit_title = e.title.clone();
            self.vault_edit_username = e.username.clone();
            self.vault_edit_password = e.password.clone();
            self.vault_edit_url = e.url.clone();
            self.vault_edit_notes = e.notes.clone();
            self.vault_selected = Some(id);
            self.vault_reveal_password = false;
        }
    }

    fn vault_new_entry(&mut self) {
        self.clear_vault_edit_buffers();
        self.vault_selected = None;
        self.vault_edit_title = SecretString::from_str("New entry");
    }

    /// Commit the edit-pane buffers into `vault_entries`: updates the
    /// selected entry in place, or appends a new one if nothing was
    /// selected. Does not write to disk — call `save_vault_with` (which
    /// prompts for the master password if needed) to persist.
    fn vault_commit_edit(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Some(id) = self.vault_selected {
            if let Some(e) = self.vault_entries.iter_mut().find(|e| e.id == id) {
                // Zeroize the old field contents before overwriting them.
                // A plain assignment (`e.password = ...`) drops the old
                // `String` without wiping its heap buffer first, leaving
                // the previous plaintext password sitting unzeroized in
                // freed memory. Same class of gap documented on `impl
                // Zeroize for VaultEntry` above (Vec growth/shift), just
                // triggered here by a single-field replace instead.
                e.title.zeroize();
                e.username.zeroize();
                e.password.zeroize();
                e.url.zeroize();
                e.notes.zeroize();
                // `SecretString::from_str` copies directly from the
                // edit-pane buffer's `&str` view into a fresh
                // `SecretString`-controlled allocation — no intermediate
                // plain `String` is created as a stray unzeroized copy
                // along the way.
                e.title = SecretString::from_str(self.vault_edit_title.as_str());
                e.username = SecretString::from_str(self.vault_edit_username.as_str());
                e.password = SecretString::from_str(self.vault_edit_password.as_str());
                e.url = SecretString::from_str(self.vault_edit_url.as_str());
                e.notes = SecretString::from_str(self.vault_edit_notes.as_str());
                e.updated_at = now;
            }
        } else {
            let mut id = now;
            while self.vault_entries.iter().any(|e| e.id == id) {
                id += 1;
            }
            self.vault_entries.push(Box::new(VaultEntry {
                id,
                title: SecretString::from_str(self.vault_edit_title.as_str()),
                username: SecretString::from_str(self.vault_edit_username.as_str()),
                password: SecretString::from_str(self.vault_edit_password.as_str()),
                url: SecretString::from_str(self.vault_edit_url.as_str()),
                notes: SecretString::from_str(self.vault_edit_notes.as_str()),
                created_at: now,
                updated_at: now,
            }));
            self.vault_selected = Some(id);
        }
        self.vault_dirty = true;
        self.vault_status = "Entry updated (not yet saved to disk).".to_string();
        self.vault_touch();
    }

    fn vault_delete_entry(&mut self, id: u64) {
        if let Some(pos) = self.vault_entries.iter().position(|e| e.id == id) {
            let mut removed = self.vault_entries.remove(pos);
            removed.zeroize();
        }
        if self.vault_selected == Some(id) {
            self.vault_selected = None;
            self.clear_vault_edit_buffers();
        }
        self.vault_dirty = true;
        self.vault_status = "Entry deleted (not yet saved to disk).".to_string();
        self.vault_touch();
    }

    /// Verify `current_password` actually unlocks the vault currently on
    /// disk, then re-encrypt the in-memory entries under
    /// `self.vault_change_pwd_new` and write them out. Requires the file
    /// to already exist (there's nothing to "change" for a brand-new,
    /// never-saved vault — just set the master password via Unlock).
    fn change_master_password(&mut self) {
        let Some(path) = self.vault_path.clone() else {
            self.vault_change_pwd_error = "No vault file selected.".to_string();
            return;
        };
        if !path.exists() {
            self.vault_change_pwd_error =
                "Vault hasn't been saved to disk yet — save it first.".to_string();
            return;
        }
        if self.vault_change_pwd_new.chars().count() < 8 {
            self.vault_change_pwd_error =
                "New password must be at least 8 characters.".to_string();
            return;
        }
        if self.vault_change_pwd_new != self.vault_change_pwd_confirm {
            self.vault_change_pwd_error = "New password and confirmation don't match.".to_string();
            return;
        }

        // Re-verify the *current* password against the file on disk
        // (not just "the vault happens to be unlocked right now") so a
        // stale unlock from long ago can't be used to silently change
        // the password to something the user didn't intend, and so a
        // typo in the current-password field is caught here rather than
        // producing a vault re-encrypted under the wrong assumption.
        let mut current = std::mem::take(&mut self.vault_change_pwd_current);
        let verify = vault::read_vault_file(&path).and_then(|combined| {
            vault::decrypt_vault(&current, &combined)
        });
        current.zeroize();

        if verify.is_err() {
            self.vault_change_pwd_error = "Current password is incorrect.".to_string();
            return;
        }

        let mut new_pwd = std::mem::take(&mut self.vault_change_pwd_new);
        let result =
            vault::change_master_password(&path, &self.vault_entries, &new_pwd, self.vault_kdf);
        new_pwd.zeroize();
        self.vault_change_pwd_confirm.zeroize();

        match result {
            Ok(()) => {
                self.vault_dirty = false;
                self.vault_change_pwd_open = false;
                self.vault_change_pwd_error.clear();
                self.vault_status = "Master password changed.".to_string();
                self.vault_touch();
            }
            Err(e) => {
                self.vault_change_pwd_error = format!("Failed to save with new password: {e}");
            }
        }
    }

    fn close_change_pwd_dialog(&mut self) {
        self.vault_change_pwd_current.zeroize();
        self.vault_change_pwd_new.zeroize();
        self.vault_change_pwd_confirm.zeroize();
        self.vault_change_pwd_error.clear();
        self.vault_change_pwd_open = false;
    }

    /// Import entries from a CSV file exported by another password
    /// manager, appending them to the current in-memory vault. Does not
    /// save to disk on its own — imported entries show up as unsaved
    /// changes like any other edit, so the user gets a chance to review
    /// before committing them.
    fn run_csv_import(&mut self, path: PathBuf) {
        let mut contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                self.vault_import_status = format!("Couldn't read file: {e}");
                return;
            }
        };
        let parsed = vault::parse_csv(&contents, self.vault_import_source);
        // The whole exported file — every plaintext password it
        // contains — has now either been copied into `rows` (parse
        // succeeded) or is no longer needed (parse failed). Either way
        // this buffer should not linger un-zeroized in memory for the
        // rest of the session.
        zeroize_string(&mut contents);
        match parsed {
            Ok(rows) => {
                if rows.is_empty() {
                    self.vault_import_status = "No rows found to import.".to_string();
                    return;
                }
                let n = vault::append_imported(&mut self.vault_entries, rows);
                self.vault_dirty = true;
                self.vault_import_status = format!(
                    "Imported {n} entries. Review them below, then save the vault to disk."
                );
                self.vault_status = format!("Imported {n} entries (not yet saved to disk).");
                self.vault_touch();
            }
            Err(e) => {
                self.vault_import_status = format!("Import failed: {e}");
            }
        }
    }

    fn ui_vault_tab(&mut self, ui: &mut egui::Ui) {
        let pal = self.palette();

        ui.horizontal(|ui| {
            let label = self
                .vault_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "No vault file selected".to_string());
            ui.label(label);
            // Two distinct actions rather than one "Open/Create" button
            // backed by save_file(): a save dialog triggers the OS's
            // native "this file already exists — overwrite it?" prompt
            // the moment you pick an existing vault, even though opening
            // an existing vault is a pure read here — the app doesn't
            // touch the file until Unlock is pressed. pick_file() opens
            // an existing file with no such warning; save_file() is kept
            // only for the "create a new, not-yet-existing vault" case.
            if ui
                .add_enabled(self.pending_pick.is_none(), egui::Button::new("Open existing vault…"))
                .clicked()
            {
                self.spawn_dialog(PendingPick::OpenVault, || {
                    rfd::FileDialog::new()
                        .add_filter("UNIGEN vault", &["uvault", "enc"])
                        .pick_file()
                });
            }
            if ui
                .add_enabled(self.pending_pick.is_none(), egui::Button::new("New vault…"))
                .clicked()
            {
                self.spawn_dialog(PendingPick::NewVault, || {
                    rfd::FileDialog::new()
                        .add_filter("UNIGEN vault", &["uvault", "enc"])
                        .set_file_name("vault.uvault")
                        .save_file()
                });
            }
        });

        if !self.vault_status.is_empty() {
            ui.small(&self.vault_status);
        }

        ui.horizontal(|ui| {
            ui.label("Auto-lock vault after");
            // Same field as the control on the Password Generator tab
            // (kept there alongside the other auto-clear timers) — also
            // surfaced here since this is the more obvious place to look
            // for it while actually using the vault. 0 disables it.
            ui.add(egui::DragValue::new(&mut self.vault_autolock_seconds).range(0..=3600));
            ui.label("seconds of inactivity (0 = never)");
        });
        // Auto-lock (and every other in-memory-only protection in this
        // app) only runs while the process is scheduled and executing
        // normally. Sleep/hibernate can write the *entire* RAM contents
        // — decrypted vault entries included — to disk (the hiberfile on
        // Windows, swap on Linux/macOS) with no chance for auto-lock's
        // timer-driven check to fire first. This is a real residual gap,
        // not something the app can close from userspace, so it's
        // surfaced here rather than left silent.
        ui.small(
            "Note: locking the screen doesn't stop the OS from suspending/hibernating in the \
             background. If the machine sleeps or hibernates while the vault is unlocked, \
             decrypted entries may be written to disk as part of that (not something this app \
             can prevent) until the vault is manually locked or the auto-lock timer above fires.",
        );

        ui.separator();

        if !self.vault_unlocked {
            ui.label("Enter the master password to unlock (or create) this vault:");
            ui.horizontal(|ui| {
                let resp = ui.add(egui::TextEdit::singleline(&mut self.vault_master_pwd).password(true));
                #[cfg(target_os = "linux")]
                if resp.changed() && self.linux_try_exclusion {
                    self.vault_master_pwd.mlock_best_effort();
                }
                // `resp` is only consumed above, and that whole branch is
                // Linux-only (`mlock()` isn't a Linux-portable syscall);
                // on other targets this keeps the variable "used" without
                // pretending there's a non-Linux equivalent action to
                // take on change.
                #[cfg(not(target_os = "linux"))]
                let _ = &resp;
                let can_go = self.vault_path.is_some() && !self.vault_master_pwd.is_empty();
                if ui
                    .add_enabled(can_go, egui::Button::new("Unlock"))
                    .clicked()
                {
                    self.unlock_vault();
                }
            });
            return;
        }

        ui.horizontal(|ui| {
            if self.vault_dirty {
                ui.colored_label(pal.warning, "Unsaved changes");
            }
            if ui.button("Lock").clicked() {
                self.lock_vault(true);
            }
            if ui.button("Change master password…").clicked() {
                self.vault_change_pwd_open = true;
            }
            if ui.button("Import from CSV…").clicked() {
                self.vault_import_open = true;
                self.vault_import_status.clear();
            }
        });

        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Search:");
            ui.text_edit_singleline(&mut self.vault_search);
            if ui.button("+ New entry").clicked() {
                self.vault_new_entry();
                self.vault_touch();
            }
        });

        ui.columns(2, |cols| {
            let query = self.vault_search.to_lowercase();
            let mut ids: Vec<u64> = self
                .vault_entries
                .iter()
                .filter(|e| {
                    query.is_empty()
                        || e.title.to_lowercase().contains(&query)
                        || e.username.to_lowercase().contains(&query)
                        || e.url.to_lowercase().contains(&query)
                })
                .map(|e| e.id)
                .collect();
            ids.sort_by_key(|id| {
                self.vault_entries
                    .iter()
                    .find(|e| e.id == *id)
                    .map(|e| e.title.to_lowercase())
                    .unwrap_or_default()
            });

            egui::ScrollArea::vertical()
                .id_source("vault_list")
                .show(&mut cols[0], |ui| {
                    for id in &ids {
                        let entry = self.vault_entries.iter().find(|e| e.id == *id);
                        let Some(entry) = entry else { continue };
                        let title = if entry.title.is_empty() {
                            "(untitled)".to_string()
                        } else {
                            // Plain `String` here is fine: this is a
                            // transient UI label handed to egui, not a
                            // vault-managed copy of the field.
                            entry.title.as_str().to_string()
                        };
                        let selected = self.vault_selected == Some(*id);
                        if ui.selectable_label(selected, title).clicked() {
                            self.vault_select(*id);
                            self.vault_touch();
                        }
                    }
                    if ids.is_empty() {
                        ui.small("No entries yet.");
                    }
                });

            let ui = &mut cols[1];
            ui.label("Title");
            ui.text_edit_singleline(&mut self.vault_edit_title);
            ui.label("Username");
            let user_resp = ui.text_edit_singleline(&mut self.vault_edit_username);
            let mut user_copy: Option<SecretString> = None;
            user_resp.context_menu(|ui| {
                if ui.button("Copy").clicked() {
                    user_copy = Some(self.vault_edit_username.clone());
                    ui.close_menu();
                }
            });
            if let Some(v) = user_copy {
                self.copy_to_clipboard(&v);
            }
            ui.label("Password");
            ui.horizontal(|ui| {
                let pwd_field_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.vault_edit_password)
                        .password(!self.vault_reveal_password),
                );
                // Right-click "Copy" as an alternative to the "Copy" button / Ctrl+C.
                // Deliberately calls the same `copy_to_clipboard` used by the button
                // (respects the auto-clear toggle/timer) rather than doing a raw
                // clipboard write, so the field stays masked when hidden and the
                // auto-clear guarantee still applies regardless of how the copy
                // was triggered.
                let mut ctx_copy: Option<SecretString> = None;
                pwd_field_resp.context_menu(|ui| {
                    if ui.button("Copy").clicked() {
                        ctx_copy = Some(self.vault_edit_password.clone());
                        ui.close_menu();
                    }
                });
                if let Some(pwd) = ctx_copy {
                    self.copy_to_clipboard(&pwd);
                }
                if ui
                    .button(if self.vault_reveal_password {
                        "Hide"
                    } else {
                        "Show"
                    })
                    .clicked()
                {
                    self.vault_reveal_password = !self.vault_reveal_password;
                }
                if ui.button("Copy").clicked() {
                    let pwd = self.vault_edit_password.clone();
                    self.copy_to_clipboard(&pwd);
                }
                if ui.button("Generate").clicked() {
                    let pool = build_pool(&self.charset_enabled, &self.charsets);
                    if !pool.is_empty() {
                        // `generate_password` returns `Zeroizing<String>`,
                        // which wipes on its own drop at the end of this
                        // scope — `SecretString::from_str` copies from it
                        // (via deref-to-`&str`) into the field's own
                        // controlled buffer without needing an
                        // intermediate owned `String`.
                        let generated = generate_password(self.length as usize, &pool);
                        self.vault_edit_password = SecretString::from_str(&generated);
                    }
                }
            });
            ui.label("URL");
            let url_resp = ui.text_edit_singleline(&mut self.vault_edit_url);
            let mut url_copy: Option<SecretString> = None;
            url_resp.context_menu(|ui| {
                if ui.button("Copy").clicked() {
                    url_copy = Some(self.vault_edit_url.clone());
                    ui.close_menu();
                }
            });
            if let Some(v) = url_copy {
                self.copy_to_clipboard(&v);
            }
            ui.label("Notes");
            let notes_resp =
                ui.add(egui::TextEdit::multiline(&mut self.vault_edit_notes).desired_rows(4));
            let mut notes_copy: Option<SecretString> = None;
            notes_resp.context_menu(|ui| {
                if ui.button("Copy").clicked() {
                    notes_copy = Some(self.vault_edit_notes.clone());
                    ui.close_menu();
                }
            });
            if let Some(v) = notes_copy {
                self.copy_to_clipboard(&v);
            }

            ui.horizontal(|ui| {
                let has_title = !self.vault_edit_title.trim().is_empty();
                if ui
                    .add_enabled(has_title, egui::Button::new("Save entry"))
                    .clicked()
                {
                    self.vault_commit_edit();
                }
                if let Some(id) = self.vault_selected {
                    if ui.button("Delete entry").clicked() {
                        self.vault_confirm_delete = Some(id);
                    }
                }
            });

        });

        if self.vault_dirty {
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Master password to save:");
                let resp = ui.add(egui::TextEdit::singleline(&mut self.vault_master_pwd).password(true));
                #[cfg(target_os = "linux")]
                if resp.changed() && self.linux_try_exclusion {
                    self.vault_master_pwd.mlock_best_effort();
                }
                // `resp` is only consumed above, and that whole branch is
                // Linux-only (`mlock()` isn't a Linux-portable syscall);
                // on other targets this keeps the variable "used" without
                // pretending there's a non-Linux equivalent action to
                // take on change.
                #[cfg(not(target_os = "linux"))]
                let _ = &resp;
                if ui.button("Save vault").clicked() {
                    let mut pwd = std::mem::take(&mut self.vault_master_pwd);
                    self.save_vault_with(&pwd);
                    pwd.zeroize();
                }
            });
        }

        if let Some(id) = self.vault_confirm_delete {
            egui::Window::new("Delete entry?")
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.label("This removes the entry from the in-memory vault. Save the vault afterwards to make it permanent.");
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.vault_confirm_delete = None;
                        }
                        if ui.button("Delete").clicked() {
                            self.vault_delete_entry(id);
                            self.vault_confirm_delete = None;
                        }
                    });
                });
        }

        if self.vault_change_pwd_open {
            egui::Window::new("Change master password")
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.label("Current master password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_change_pwd_current)
                            .password(true),
                    );
                    ui.label("New master password (min 8 characters):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_change_pwd_new).password(true),
                    );
                    ui.label("Confirm new master password:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.vault_change_pwd_confirm)
                            .password(true),
                    );
                    if !self.vault_change_pwd_error.is_empty() {
                        ui.colored_label(pal.danger, &self.vault_change_pwd_error);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.close_change_pwd_dialog();
                        }
                        let can_go = !self.vault_change_pwd_current.is_empty()
                            && self.vault_change_pwd_new.chars().count() >= 8
                            && !self.vault_change_pwd_confirm.is_empty();
                        if ui
                            .add_enabled(can_go, egui::Button::new("Change password"))
                            .clicked()
                        {
                            self.change_master_password();
                        }
                    });
                });
        }

        if self.vault_import_open {
            egui::Window::new("Import from CSV")
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.label("Source format:");
                    egui::ComboBox::from_id_source("vault_import_source")
                        .selected_text(self.vault_import_source.label())
                        .show_ui(ui, |ui| {
                            for src in vault::CsvSource::ALL {
                                ui.selectable_value(
                                    &mut self.vault_import_source,
                                    src,
                                    src.label(),
                                );
                            }
                        });
                    ui.add_space(6.0);
                    ui.small(
                        "The plaintext CSV file only exists on disk until you delete it — \
                         most password managers don't shred their own exports, so consider \
                         deleting the file yourself afterwards (Manual Shred, in File Protector, \
                         does this securely).",
                    );
                    ui.add_space(6.0);
                    if !self.vault_import_status.is_empty() {
                        ui.label(&self.vault_import_status);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Close").clicked() {
                            self.vault_import_open = false;
                            self.vault_import_status.clear();
                        }
                        if ui
                            .add_enabled(self.pending_pick.is_none(), egui::Button::new("Choose CSV file…"))
                            .clicked()
                        {
                            self.spawn_dialog(PendingPick::ImportCsv, || {
                                rfd::FileDialog::new().add_filter("CSV", &["csv"]).pick_file()
                            });
                        }
                    });
                });
        }
    }

    /// One-click: encrypt the saved plaintext password list with a
    /// passphrase, verify the encrypted file decrypts back to the exact
    /// original bytes, and only then securely shred the plaintext
    /// original. Mirrors the Python original's
    /// `encrypt_and_shred_password_file` (including "don't delete the
    /// plaintext unless the encrypted copy verifies").
    fn run_encrypt_and_shred_password_file(&mut self) {
        let path = match self.last_saved_password_path.clone() {
            Some(p) if p.exists() => p,
            _ => {
                self.gen_status =
                    "No saved password file to encrypt — save the list first.".to_string();
                self.encrypt_shred_pwd.clear();
                return;
            }
        };

        let pwd = Zeroizing::new(self.encrypt_shred_pwd.as_str().to_string());
        let result = (|| -> anyhow::Result<String> {
            crypto::check_blob_file_size(&path)?;
            let original_identity = shred::file_identity(&path)?;
            let original_data = Zeroizing::new(std::fs::read(&path)?);
            let combined = crypto::encrypt_blob(&pwd, &original_data, crypto::DEFAULT_KDF)?;

            let enc_path = {
                let mut s = path.clone().into_os_string();
                s.push(".enc");
                PathBuf::from(s)
            };
            let tmp = crypto::unique_tmp_path(&enc_path);
            let text = crypto::encode_blob_text(&combined);
            crypto::write_durable(&tmp, text.as_bytes())?;
            if let Err(e) = crypto::replace_file(&tmp, &enc_path) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e.into());
            }
            crypto::restrict_permissions(&enc_path);

            // Verify before destroying the plaintext.
            let check_contents = std::fs::read(&enc_path)?;
            let check_combined = crypto::decode_blob_text(&check_contents);
            let decrypted_back = crypto::decrypt_blob_compat(&pwd, &check_combined)?;
            if decrypted_back.as_slice() != original_data.as_slice() {
                anyhow::bail!("Verification failed — the encrypted file did not round-trip; original was NOT deleted.");
            }

            match shred::shred_file_if_identity(&path, original_identity, 3) {
                Ok(_) => Ok(format!("Encrypted to: {enc_path:?}\nOriginal plaintext securely shredded: {path:?}\n\n{}", shred::SSD_SHRED_CAVEAT)),
                Err(e) => anyhow::bail!(
                    "Encrypted to: {enc_path:?}, but secure overwrite of the original failed and it was left in place: {e}"
                ),
            }
        })();

        self.encrypt_shred_pwd.clear();
        match result {
            Ok(msg) => {
                self.gen_status = msg;
                self.last_saved_password_path = None;
            }
            Err(e) => self.gen_status = format!("Error: {e}"),
        }
    }

    fn clear_clipboard(&mut self) {
        self.autoclear_deadline = None;
        self.autoclear_expected = None;
        if let Some(cb) = self.clipboard.as_mut() {
            let _ = cb.set_text(String::new());
        }
        self.clip_status = "Clipboard cleared.".to_string();
    }

    fn tick_autoclear(&mut self) {
        if let Some(deadline) = self.autoclear_deadline {
            if Instant::now() >= deadline {
                // Only clear if the clipboard still holds what we put
                // there (best-effort — arboard's read-back is a plain
                // text compare, same idea as the Python original).
                let still_ours = self
                    .clipboard
                    .as_mut()
                    .and_then(|cb| cb.get_text().ok())
                    .map(|cur| Some(cur) == self.autoclear_expected)
                    .unwrap_or(true);
                if still_ours {
                    if let Some(cb) = self.clipboard.as_mut() {
                        let _ = cb.set_text(String::new());
                    }
                    self.clip_status = "Clipboard auto-cleared (timeout).".to_string();
                }
                self.autoclear_deadline = None;
                self.autoclear_expected = None;
            }
        }
    }

    fn tick_pwd_autoclear(&mut self) {
        let secs = Duration::from_secs(self.pwd_autoclear_seconds as u64);
        if self.enc_pwd_autoclear
            && !self.enc_pwd.is_empty()
            && self.enc_pwd_last_edit.elapsed() > secs
        {
            self.enc_pwd.clear();
            self.enc_status = format!(
                "Passphrase cleared from memory after {}s of inactivity.",
                self.pwd_autoclear_seconds
            );
        }
        if self.dec_pwd_autoclear
            && !self.dec_pwd.is_empty()
            && self.dec_pwd_last_edit.elapsed() > secs
        {
            self.dec_pwd.clear();
            self.dec_status = format!(
                "Passphrase cleared from memory after {}s of inactivity.",
                self.pwd_autoclear_seconds
            );
        }
    }

    fn start_encrypt(&mut self) {
        let Some(in_path) = self.enc_file.clone() else {
            return;
        };
        if self.enc_pwd.chars().count() < crypto::MIN_PASSPHRASE_LEN {
            self.enc_status = format!(
                "Passphrase must be at least {} characters.",
                crypto::MIN_PASSPHRASE_LEN
            );
            return;
        }
        if self.busy_ops.contains("encrypt") || self.pending_pick.is_some() {
            return;
        }

        let size = std::fs::metadata(&in_path).map(|m| m.len()).unwrap_or(0);
        let streaming = size > crypto::STREAM_SIZE_THRESHOLD;

        let pwd = Zeroizing::new(self.enc_pwd.as_str().to_string());
        let kdf_id = self.kdf_choice;
        let shred_after = self.shred_after;
        #[cfg(target_os = "linux")]
        if self.linux_try_exclusion && !try_mlock_str(&pwd) {
            self.enc_status =
                "Warning: mlock() failed; passphrase remains subject to normal VM paging."
                    .to_string();
        }

        if streaming {
            // Large files need a save-target chosen up front (see
            // `spawn_dialog`'s doc comment for why this can't be a
            // direct, blocking `rfd::FileDialog` call here). Everything
            // `run_encrypt_job` needs is stashed in the `PendingPick`
            // variant and picked back up in `poll_pending_pick` once the
            // dialog reports a result.
            let default_name = format!(
                "{}.enc",
                in_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default()
            );
            self.spawn_dialog(
                PendingPick::EncryptSaveOutput {
                    in_path,
                    pwd,
                    kdf_id,
                    shred_after,
                },
                move || {
                    rfd::FileDialog::new()
                        .set_title("Save encrypted file (large file — streamed)")
                        .set_file_name(&default_name)
                        .add_filter("Encrypted files", &["enc"])
                        .save_file()
                },
            );
            return;
        }

        // Small files stay in-memory; no save dialog needed up front, so
        // this path is unaffected by the dialog-threading concern above.
        self.busy_ops.insert("encrypt");
        let (tx, rx) = channel();
        self.encrypt_job = Some(BackgroundJob {
            rx,
            last_status: "Starting…".into(),
            progress: None,
        });
        std::thread::spawn(move || {
            run_encrypt_job(in_path, None, pwd, kdf_id, shred_after, tx);
        });
    }

    fn start_decrypt(&mut self) {
        let Some(in_path) = self.dec_file.clone() else {
            return;
        };
        if self.dec_pwd.is_empty() {
            self.dec_status = "Enter the passphrase.".to_string();
            return;
        }
        if self.busy_ops.contains("decrypt") || self.pending_pick.is_some() {
            return;
        }

        // Only read the first 4 bytes to detect the streaming-format magic
        // instead of loading the whole file into memory (which could be
        // many gigabytes for streaming-encrypted files).
        let is_streaming = std::fs::File::open(&in_path)
            .and_then(|mut f| {
                let mut magic = [0u8; 4];
                std::io::Read::read_exact(&mut f, &mut magic)?;
                Ok(magic == *crypto::STREAM_MAGIC)
            })
            .unwrap_or(false);

        let default_name = in_path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "decrypted".to_string());
        let pwd = Zeroizing::new(self.dec_pwd.as_str().to_string());
        self.spawn_dialog(
            PendingPick::DecryptSaveOutput {
                in_path,
                pwd,
                is_streaming,
            },
            move || {
                rfd::FileDialog::new()
                    .set_title("Save decrypted file")
                    .set_file_name(&default_name)
                    .save_file()
            },
        );
    }

    fn start_shred(&mut self) {
        let Some(path) = self.shred_target.clone() else {
            return;
        };
        if self.busy_ops.contains("shred") {
            return;
        }
        self.busy_ops.insert("shred");
        let (tx, rx) = channel();
        self.shred_job = Some(BackgroundJob {
            rx,
            last_status: "Shredding…".into(),
            progress: None,
        });
        std::thread::spawn(move || {
            let result = shred::shred_file(&path, 3, false);
            let msg = match result {
                Ok(shred::ShredOutcome::Secure) => Ok("File securely shredded.".to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(JobMsg::Done(msg));
        });
    }

    /// Decrypts `path` with `pwd` straight into `self.editor_content` —
    /// never touches disk with plaintext. Small text files only (password
    /// lists), so this runs synchronously rather than on a background
    /// thread; Argon2id adds at most a fraction of a second.
    fn open_editor_decrypt(&mut self, path: PathBuf, pwd: SecretString) {
        let result = (|| -> anyhow::Result<(String, Option<u8>, bool)> {
            crypto::check_blob_file_size(&path)?;
            let file_contents = std::fs::read(&path)?;
            if &file_contents[..file_contents.len().min(4)] == crypto::STREAM_MAGIC {
                anyhow::bail!(
                    "This is a large streaming-encrypted file, not a small text file — \
                     use \"Decrypt & Save\" above instead of the editor."
                );
            }
            let combined = crypto::decode_blob_text(&file_contents);
            let plain = Zeroizing::new(crypto::decrypt_blob_compat(&pwd, &combined)?);
            let text = String::from_utf8(plain.as_slice().to_vec()).map_err(|_| {
                anyhow::anyhow!("Decrypted content isn't valid UTF-8 text — not editable here.")
            })?;
            Ok((
                text,
                crypto::peek_kdf_id(&combined),
                crypto::is_legacy_no_aad_format(&combined),
            ))
        })();

        match result {
            Ok((text, source_kdf, legacy_no_aad)) => {
                self.editor_source = Some(path);
                // `SecretString::from(String)` copies into the controlled
                // buffer and zeroizes the source `String` afterward, so
                // neither the `.clone()` below nor `text` itself is left
                // as a stray unzeroized plaintext copy on the heap.
                self.editor_content = SecretString::from(text.clone());
                self.editor_original_content = SecretString::from(text);
                self.editor_pwd = pwd;
                self.editor_source_kdf = source_kdf;
                // Default the "will save as" KDF to whatever the file was
                // already using, so hitting Save without touching the KDF
                // selector preserves it rather than silently upgrading (or
                // downgrading) the file's KDF. Falls back to the app
                // default only when the source KDF couldn't be determined
                // (legacy no-magic format).
                self.editor_kdf = source_kdf.unwrap_or(crypto::DEFAULT_KDF);
                self.editor_open = true;
                self.editor_search.clear();
                self.editor_status = if legacy_no_aad {
                    "Note: this file is in the legacy container format, which doesn't bind \
                     an AAD to its ciphertext. Saving here will re-encrypt it into the \
                     current AAD-bound format."
                        .to_string()
                } else {
                    String::new()
                };
                self.editor_open_prompt = false;
                self.editor_open_target = None;
                self.editor_open_pwd.clear();
                self.editor_open_error.clear();
            }
            Err(e) => {
                self.editor_open_pwd.clear();
                self.editor_open_error = format!("Error: {e}");
            }
        }
    }

    /// Re-encrypts the edited content back over the original file: write to
    /// a uniquely-named temp file, verify it decrypts back to exactly the
    /// content we just encrypted (same "don't trust it until it round-trips"
    /// pattern used by `run_encrypt_and_shred_password_file`), and only then
    /// atomically rename over the target — so a crash mid-write, or a
    /// silently-bad encryption, can never leave the on-disk file corrupted
    /// or replaced with something that doesn't actually decrypt.
    fn save_editor(&mut self) {
        let Some(path) = self.editor_source.clone() else {
            return;
        };
        let expected = self.editor_content.clone();
        let result = (|| -> anyhow::Result<()> {
            let combined =
                crypto::encrypt_blob(&self.editor_pwd, expected.as_bytes(), self.editor_kdf)?;

            // Verify round-trip BEFORE touching the real file: decrypt the
            // freshly-produced ciphertext with the same passphrase and
            // confirm it matches exactly what we intended to save.
            let verify = Zeroizing::new(
                crypto::decrypt_blob(&self.editor_pwd, &combined).map_err(|e| {
                    anyhow::anyhow!(
                        "Verification failed after encrypting — original file left untouched: {e}"
                    )
                })?,
            );
            if verify.as_slice() != expected.as_bytes() {
                anyhow::bail!(
                    "Verification failed — the re-encrypted content did not round-trip; \
                     original file left untouched."
                );
            }

            let text = crypto::encode_blob_text(&combined);
            let tmp = crypto::unique_tmp_path(&path);
            crypto::write_durable(&tmp, text.as_bytes())?;
            if let Err(e) = crypto::replace_file(&tmp, &path) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e.into());
            }
            crypto::restrict_permissions(&path);
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.editor_original_content = self.editor_content.clone();
                self.editor_source_kdf = Some(self.editor_kdf);
                self.editor_status = format!(
                    "Saved & re-encrypted ({}): {path:?}",
                    crypto::kdf_name(self.editor_kdf)
                );
            }
            Err(e) => self.editor_status = format!("Error saving: {e}"),
        }
    }

    /// Zeroizes and closes the editor. This is the only exit path from the
    /// editor (Save doesn't close it, Close/Discard does, and app-exit
    /// calls this too) so decrypted plaintext never lingers in memory
    /// longer than the editor stays open.
    fn close_editor(&mut self) {
        self.editor_content.clear();
        self.editor_original_content.clear();
        self.editor_pwd.clear();
        self.editor_search.clear();
        self.editor_status.clear();
        self.editor_source = None;
        self.editor_source_kdf = None;
        self.editor_open = false;
        self.editor_confirm_close = false;
        // A line copied from the search view may still be sitting on the
        // clipboard with its auto-clear timer not yet elapsed — closing
        // the editor shouldn't leave a decrypted passphrase reachable
        // indefinitely just because the user didn't wait it out. Clearing
        // here also cancels the pending timer (clear_clipboard resets
        // autoclear_deadline/expected), so tick_autoclear won't later fire
        // on whatever unrelated thing may be on the clipboard by then.
        self.clear_clipboard();
    }

    /// Runs a native file/save dialog on a dedicated background thread
    /// instead of calling `rfd::FileDialog` directly from inside an
    /// `egui`/`eframe` UI callback.
    ///
    /// On Linux, `rfd`'s blocking `pick_file()`/`save_file()` pumps its
    /// own (GTK, or portal-backed) event loop to show the dialog and
    /// wait for a result. Calling that *from inside* `update()` — i.e.
    /// from the same thread that's driving `winit`'s event loop — means
    /// two event loops are competing for the same thread: `winit` is
    /// blocked waiting for `update()` to return, while the dialog's own
    /// loop can end up waiting on window-manager/compositor events that
    /// only `winit`'s loop would normally pump. Depending on the desktop
    /// environment this deadlocks outright (no dialog ever appears, the
    /// whole app just hangs) rather than merely glitching — which is
    /// exactly the "every Browse/Open/Save button freezes the app"
    /// symptom this fixes. Running the dialog on its own OS thread lets
    /// `winit`'s loop keep pumping on the main thread while the dialog
    /// runs independently; the result comes back over `mpsc` and is
    /// picked up by `poll_pending_pick` on a later frame, the same
    /// pattern already used for the encrypt/decrypt/shred background
    /// jobs elsewhere in this file.
    ///
    /// Only one dialog is tracked at a time (`self.pending_pick`); UI
    /// code should guard the triggering button with
    /// `self.pending_pick.is_none()` so a second click can't spawn a
    /// second native dialog while one is already open.
    fn spawn_dialog(
        &mut self,
        kind: PendingPick,
        dialog: impl FnOnce() -> Option<PathBuf> + Send + 'static,
    ) {
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let _ = tx.send(dialog());
        });
        self.pending_pick = Some((rx, kind));
    }

    /// Checks whether a dialog spawned by `spawn_dialog` has reported
    /// back yet, and if so, runs whatever follow-up action was pending
    /// for it. Called every frame from `poll_jobs`.
    /// Called when a `spawn_dialog` worker thread disappears without
    /// sending a result (see the `Disconnected` arm in
    /// `poll_pending_pick`). Surfaces a status message on whichever tab
    /// owns `kind` instead of leaving the user staring at a button that
    /// just silently does nothing.
    fn report_dialog_failure(&mut self, kind: PendingPick) {
        const MSG: &str = "Couldn't open the file dialog. Please try again.";
        match kind {
            PendingPick::OpenVault | PendingPick::NewVault => {
                self.vault_status = MSG.to_string();
            }
            PendingPick::ImportCsv => {
                self.vault_status = MSG.to_string();
            }
            PendingPick::EncryptSelectFile | PendingPick::EncryptSaveOutput { .. } => {
                self.enc_status = MSG.to_string();
            }
            PendingPick::DecryptSelectFile | PendingPick::DecryptSaveOutput { .. } => {
                self.dec_status = MSG.to_string();
            }
            PendingPick::ShredSelectFile => {
                self.shred_status = MSG.to_string();
            }
            PendingPick::EditorSelectFile => {
                self.editor_status = MSG.to_string();
            }
            PendingPick::SaveGeneratedPasswords => {
                self.gen_status = MSG.to_string();
            }
            PendingPick::EncryptSmallFileSavePath(reply) => {
                // The background encrypt job is blocked on this reply
                // channel; tell it to bail out cleanly rather than hang
                // forever waiting for a save path that will never come.
                let _ = reply.send(None);
            }
        }
    }

    fn poll_pending_pick(&mut self) {
        let Some((rx, _)) = &self.pending_pick else {
            return;
        };
        let path = match rx.try_recv() {
            Ok(path) => path,
            // Dialog thread hasn't reported back yet — keep waiting,
            // buttons stay disabled via `pending_pick.is_some()` until
            // next frame.
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            // The dialog thread is gone without ever sending a result
            // (e.g. it panicked — no working GTK/portal backend, a
            // `rfd` failure, etc). If we treat this the same as "still
            // waiting" (as a bare `Err(_) => return` does), `pending_pick`
            // is never cleared and, since every Open/Browse/New button is
            // gated on `pending_pick.is_none()`, the *entire app's* file
            // buttons go permanently dead after this single failure —
            // this is the bug behind the "buttons to open files don't
            // work" report. Clear the pending pick and surface it so the
            // UI recovers instead of silently locking up.
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                let (_, kind) = self.pending_pick.take().expect("checked Some above");
                self.report_dialog_failure(kind);
                return;
            }
        };
        let (_, kind) = self.pending_pick.take().expect("checked Some above");
        match kind {
            PendingPick::OpenVault => {
                if let Some(path) = path {
                    self.lock_vault(true);
                    self.vault_path = Some(path);
                }
            }
            PendingPick::NewVault => {
                if let Some(path) = path {
                    self.lock_vault(true);
                    self.vault_path = Some(path);
                }
            }
            PendingPick::ImportCsv => {
                if let Some(path) = path {
                    self.run_csv_import(path);
                }
            }
            PendingPick::EncryptSelectFile => {
                if let Some(path) = path {
                    self.enc_file = Some(path);
                }
            }
            PendingPick::EncryptSaveOutput {
                in_path,
                pwd,
                kdf_id,
                shred_after,
            } => {
                let Some(out_path) = path else {
                    self.enc_status = "Cancelled.".to_string();
                    return;
                };
                // `mlock()` on `pwd` (if enabled) already happened back
                // in `start_encrypt`, right after this `Zeroizing<String>`
                // was created — no need to repeat it here.
                self.busy_ops.insert("encrypt");
                let (tx, rx) = channel();
                self.encrypt_job = Some(BackgroundJob {
                    rx,
                    last_status: "Starting…".into(),
                    progress: None,
                });
                std::thread::spawn(move || {
                    run_encrypt_job(in_path, Some(out_path), pwd, kdf_id, shred_after, tx);
                });
            }
            PendingPick::DecryptSelectFile => {
                if let Some(path) = path {
                    self.dec_file = Some(path);
                }
            }
            PendingPick::DecryptSaveOutput {
                in_path,
                pwd,
                is_streaming,
            } => {
                let Some(out_path) = path else {
                    self.dec_status = "Cancelled.".to_string();
                    return;
                };
                self.busy_ops.insert("decrypt");
                let (tx, rx) = channel();
                self.decrypt_job = Some(BackgroundJob {
                    rx,
                    last_status: "Starting…".into(),
                    progress: None,
                });
                std::thread::spawn(move || {
                    run_decrypt_job(in_path, out_path, pwd, is_streaming, tx);
                });
            }
            PendingPick::ShredSelectFile => {
                if let Some(path) = path {
                    // `pick_file()` can still return a directory on some
                    // platforms/window managers even though it requests
                    // a file picker.
                    if path.is_dir() {
                        self.shred_target = None;
                        self.shred_status =
                            "That's a folder, not a file — please pick a single file to shred."
                                .to_string();
                    } else {
                        self.shred_status.clear();
                        self.shred_target = Some(path);
                    }
                }
            }
            PendingPick::EditorSelectFile => {
                if let Some(path) = path {
                    self.editor_open_target = Some(path);
                    self.editor_open_error.clear();
                    self.editor_open_prompt = true;
                }
            }
            PendingPick::EncryptSmallFileSavePath(reply) => {
                // Forward whatever was chosen (or `None` if cancelled)
                // back to the waiting `run_encrypt_job` thread. If it's
                // gone already (e.g. the job errored out some other way
                // first) the send just fails silently — nothing to do.
                let _ = reply.send(path);
            }
            PendingPick::SaveGeneratedPasswords => {
                let Some(path) = path else {
                    return;
                };
                let content = Zeroizing::new(
                    self.generated
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
                let tmp = crypto::unique_tmp_path(&path);
                let ok = crypto::write_durable(&tmp, content.as_bytes())
                    .and_then(|_| crypto::replace_file(&tmp, &path))
                    .is_ok();
                if !ok {
                    let _ = std::fs::remove_file(&tmp);
                }
                self.gen_status = if ok {
                    crypto::restrict_permissions(&path);
                    self.last_saved_password_path = Some(path.clone());
                    format!("Saved to: {path:?}")
                } else {
                    "Save failed.".to_string()
                };
            }
        }
    }

    fn poll_jobs(&mut self, ctx: &egui::Context) {
        self.poll_pending_pick();
        if let Some(job) = self.encrypt_job.as_mut() {
            let mut finished = None;
            let mut need_save_path = None;
            while let Ok(msg) = job.rx.try_recv() {
                match msg {
                    JobMsg::Progress(p, s) => {
                        job.progress = Some(p);
                        job.last_status = s;
                    }
                    JobMsg::NeedSavePath(default_name, reply) => {
                        // Just stash this — can't call `self.spawn_dialog`
                        // (needs `&mut self`) while `job` (borrowed from
                        // `self.encrypt_job`) is still alive. Handled just
                        // below, once this `if let` block (and `job`'s
                        // borrow with it) has ended.
                        need_save_path = Some((default_name, reply));
                    }
                    JobMsg::Done(res) => finished = Some(res),
                }
            }
            if let Some(res) = finished {
                self.busy_ops.remove("encrypt");
                self.enc_status = match res {
                    Ok(s) => s,
                    Err(e) => format!("Error: {e}"),
                };
                self.encrypt_job = None;
            }
            if let Some((default_name, reply)) = need_save_path {
                self.spawn_dialog(PendingPick::EncryptSmallFileSavePath(reply), move || {
                    rfd::FileDialog::new()
                        .set_title("Save encrypted file")
                        .set_file_name(default_name)
                        .add_filter("Encrypted files", &["enc"])
                        .save_file()
                });
            }
        }
        if let Some(job) = self.decrypt_job.as_mut() {
            let mut finished = None;
            while let Ok(msg) = job.rx.try_recv() {
                match msg {
                    JobMsg::Progress(p, s) => {
                        job.progress = Some(p);
                        job.last_status = s;
                    }
                    // `run_decrypt_job` never sends this — only the
                    // small-file branch of `run_encrypt_job` does — but
                    // `JobMsg` is shared across all three job kinds, so
                    // the match still has to be exhaustive here.
                    JobMsg::NeedSavePath(_, reply) => {
                        let _ = reply.send(None);
                    }
                    JobMsg::Done(res) => finished = Some(res),
                }
            }
            if let Some(res) = finished {
                self.busy_ops.remove("decrypt");
                self.dec_status = match res {
                    Ok(s) => s,
                    Err(e) => format!("Error: {e}"),
                };
                self.decrypt_job = None;
            }
        }
        if let Some(job) = self.shred_job.as_mut() {
            let mut finished = None;
            while let Ok(msg) = job.rx.try_recv() {
                match msg {
                    JobMsg::Progress(p, s) => {
                        job.progress = Some(p);
                        job.last_status = s;
                    }
                    // Same rationale as the `decrypt_job` loop above:
                    // `run_shred_job` never actually sends this variant.
                    JobMsg::NeedSavePath(_, reply) => {
                        let _ = reply.send(None);
                    }
                    JobMsg::Done(res) => finished = Some(res),
                }
            }
            if let Some(res) = finished {
                self.busy_ops.remove("shred");
                self.shred_status = match res {
                    Ok(s) => {
                        self.shred_target = None;
                        s
                    }
                    Err(e) => format!("Error: {e}"),
                };
                self.shred_job = None;
            }
        }
        let autoclear_pending = self.autoclear_deadline.is_some()
            || (self.enc_pwd_autoclear && !self.enc_pwd.is_empty())
            || (self.dec_pwd_autoclear && !self.dec_pwd.is_empty());
        // Vault auto-lock relies on this same repaint mechanism to check
        // its timer — without it, an idle window with no other pending
        // timer would never re-run `update()`, and `tick_vault_autolock`
        // would never fire until the next real user interaction. That
        // would leave an unlocked vault decrypted in memory indefinitely
        // while the app sits idle, defeating the point of auto-lock.
        let vault_autolock_pending = self.vault_unlocked && self.vault_autolock_seconds > 0;
        if !self.busy_ops.is_empty()
            || autoclear_pending
            || vault_autolock_pending
            || self.pending_pick.is_some()
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}

/// Best-effort: tell the Linux kernel this process should never produce a
/// core dump (`prctl(PR_SET_DUMPABLE, 0)`), so a crash can't leave a file
/// on disk containing whatever secrets happened to be live in memory at
/// the time. Silently does nothing if the kernel refuses the request —
/// there's no user-facing consequence to react to either way, since this
/// only affects post-crash forensics, not normal operation. Also lowers
/// `RLIMIT_CORE` to 0 as a second, independent line of defense: even a
/// child process or a future code path that re-enables dumpable (e.g. via
/// `PR_SET_DUMPABLE` after a `setuid`-style transition, which the kernel
/// does automatically and which this app doesn't do, but which some
/// libraries can trigger) still can't write a dump if the size limit is
/// zero.
#[cfg(target_os = "linux")]
fn disable_core_dumps() {
    const PR_SET_DUMPABLE: i32 = 4;
    extern "C" {
        fn prctl(option: i32, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> i32;
    }
    // SAFETY: `prctl` with `PR_SET_DUMPABLE` only reads its integer
    // arguments; no pointers are passed, and a nonzero return (failure)
    // is intentionally ignored since this is best-effort.
    unsafe {
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    #[repr(C)]
    struct RLimit {
        cur: u64,
        max: u64,
    }
    const RLIMIT_CORE: i32 = 4;
    extern "C" {
        fn setrlimit(resource: i32, rlim: *const RLimit) -> i32;
    }
    let limit = RLimit { cur: 0, max: 0 };
    // SAFETY: `limit` is a valid, initialized `RLimit` for the duration
    // of this call; `setrlimit` does not retain the pointer afterward.
    unsafe {
        setrlimit(RLIMIT_CORE, &limit);
    }
}

/// Best-effort: ask the Linux kernel to keep `s`'s backing memory out of
/// swap for as long as this process holds the lock (mirrors the Python
/// original's `try_mlock`, which does the same via ctypes). Returns false
/// when the kernel refuses the lock; callers must treat it as best-effort.
#[cfg(target_os = "linux")]
fn try_mlock_str(s: &str) -> bool {
    extern "C" {
        fn mlock(addr: *const std::ffi::c_void, len: usize) -> i32;
    }
    if s.is_empty() {
        return true;
    }
    unsafe { mlock(s.as_ptr() as *const std::ffi::c_void, s.len()) == 0 }
}

fn zeroize_string(s: &mut String) {
    // Route through a Vec<u8> so the actual byte-wiping happens inside the
    // `zeroize` crate (which does it correctly, with a volatile write the
    // optimizer can't elide) instead of via a hand-rolled `unsafe` block
    // here. `String::into_bytes`/`String::from_utf8` are safe, zero-copy
    // (no realloc) conversions, so this has the same performance and the
    // same wipe-the-existing-buffer-in-place semantics as before — just
    // without `unsafe` in this crate's own code.
    let mut bytes = std::mem::take(s).into_bytes();
    bytes.zeroize();
    // `bytes` is now all zero, which is valid (empty) UTF-8 content-wise
    // only if it's empty; we don't want zero-filled "garbage" text to
    // reappear, so drop the zeroed capacity entirely and leave `s` empty.
    drop(bytes);
    *s = String::new();
}

fn run_encrypt_job(
    in_path: PathBuf,
    out_path: Option<PathBuf>,
    // HIGH fix: this used to be a plain `String`. It's a *clone* of the
    // UI-field passphrase moved into a background thread; the UI field
    // itself gets zeroed via `zeroize_string`, but this clone previously
    // just dropped as an ordinary String when the thread finished,
    // leaving the passphrase bytes sitting in freed heap memory. Wrapping
    // it in `Zeroizing<String>` guarantees the wipe on every return path
    // (success, error, or panic-unwind), matching what `crypto.rs`
    // already does internally.
    pwd: Zeroizing<String>,
    kdf_id: u8,
    shred_after: bool,
    tx: Sender<JobMsg>,
) {
    let result = (|| -> Result<String, String> {
        let size = std::fs::metadata(&in_path)
            .map_err(|e| e.to_string())?
            .len();

        if let Some(out) = &out_path {
            // Capture the exact source identity before encryption. The later
            // verify->shred step will refuse to touch a replacement file.
            let source_identity = shred::file_identity(&in_path).map_err(|e| e.to_string())?;
            // Streaming path (large files).
            let tx_prog = tx.clone();
            let cb = crypto::Progress {
                callback: Box::new(move |done, total| {
                    let pct = if total > 0 {
                        done as f32 / total as f32
                    } else {
                        0.0
                    };
                    let _ = tx_prog.send(JobMsg::Progress(
                        pct,
                        format!("Encrypting… {:.0}%", pct * 100.0),
                    ));
                }),
            };
            crypto::stream_encrypt_file(&in_path, out, &pwd, kdf_id, Some(cb))
                .map_err(|e| e.to_string())?;

            if shred_after {
                let tx_verify = tx.clone();
                let cb = crypto::Progress {
                    callback: Box::new(move |done, total| {
                        let pct = if total > 0 {
                            done as f32 / total as f32
                        } else {
                            0.0
                        };
                        let _ = tx_verify.send(JobMsg::Progress(
                            pct,
                            format!("Verifying before shred… {:.0}%", pct * 100.0),
                        ));
                    }),
                };
                crypto::verify_stream_roundtrip(out, &in_path, &pwd, Some(cb))
                    .map_err(|e| format!("Encrypted, but post-encrypt verification failed: {e}"))?;
                let _ = tx.send(JobMsg::Progress(1.0, "Shredding original…".to_string()));
                match shred::shred_file_if_identity(&in_path, source_identity, 3) {
                    Ok(shred::ShredOutcome::Secure) => Ok(format!(
                        "Encrypted (streamed, {}) to {:?}. Original securely shredded. {}",
                        crypto::kdf_name(kdf_id),
                        out,
                        shred::SSD_SHRED_CAVEAT
                    )),
                    Err(e) => Ok(format!(
                        "Encrypted to {out:?}, but shredding the original failed: {e}"
                    )),
                }
            } else {
                Ok(format!(
                    "Encrypted (streamed, {}). Saved: {:?}",
                    crypto::kdf_name(kdf_id),
                    out
                ))
            }
        } else {
            // Small-file, in-memory blob path.
            crypto::check_blob_file_size(&in_path).map_err(|e| e.to_string())?;
            let source_identity = shred::file_identity(&in_path).map_err(|e| e.to_string())?;
            let data = Zeroizing::new(std::fs::read(&in_path).map_err(|e| e.to_string())?);
            let combined = crypto::encrypt_blob(&pwd, &data, kdf_id).map_err(|e| e.to_string())?;

            // Verify round-trip before offering to shred.
            let verify =
                Zeroizing::new(crypto::decrypt_blob(&pwd, &combined).map_err(|e| e.to_string())?);
            if verify.as_slice() != data.as_slice() {
                return Err("Verification failed — original was NOT modified.".to_string());
            }

            let default_out = {
                let mut s = in_path.clone().into_os_string();
                s.push(".enc");
                PathBuf::from(s)
            };
            let default_name = default_out
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "encrypted.enc".to_string());
            // Ask the main/UI thread to run the save-file dialog instead
            // of calling `rfd::FileDialog` directly here. This thread
            // isn't the UI thread, so it wouldn't hit the winit-vs-
            // dialog-event-loop deadlock other call sites in this file
            // had — but GTK (the backend `rfd` normally uses on Linux)
            // isn't thread-safe and isn't generally supported outside
            // the thread that initialized it (which, given `eframe`
            // brings up its window on the main thread, is the main
            // thread). Routing the actual dialog call back through
            // `spawn_dialog` — which always launches it from a thread
            // spawned off the main thread, consistently — avoids that.
            // Blocking on `reply_rx.recv()` here costs nothing: this
            // thread has no other work to do until it knows the save
            // path anyway, and the UI thread stays fully responsive
            // (the dialog itself runs on yet another thread; this one
            // just waits on a channel).
            let (reply_tx, reply_rx) = channel();
            if tx
                .send(JobMsg::NeedSavePath(default_name, reply_tx))
                .is_err()
            {
                // UI side is gone (app closing) — nothing left to do.
                return Ok("Cancelled.".to_string());
            }
            let save_path = reply_rx.recv().ok().flatten();
            let Some(save_path) = save_path else {
                return Ok("Cancelled (encryption result was discarded).".to_string());
            };

            let tmp = crypto::unique_tmp_path(&save_path);
            let text = crypto::encode_blob_text(&combined);
            crypto::write_durable(&tmp, text.as_bytes()).map_err(|e| e.to_string())?;
            if let Err(e) = crypto::replace_file(&tmp, &save_path) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e.to_string());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = std::fs::metadata(&save_path) {
                    let mut p = m.permissions();
                    p.set_mode(0o600);
                    let _ = std::fs::set_permissions(&save_path, p);
                }
            }

            // Note: even if the original file was empty (size == 0), we
            // still fall through to the shred_after logic below so that an
            // explicit "shred the original" request is honored regardless
            // of file size. shred::shred_file handles empty files safely
            // (it skips the overwrite passes and just deletes).
            let _ = size;

            if shred_after {
                match shred::shred_file_if_identity(&in_path, source_identity, 3) {
                    Ok(shred::ShredOutcome::Secure) => Ok(format!(
                        "Encrypted ({}) to {save_path:?}. Original securely shredded. {}",
                        crypto::kdf_name(kdf_id),
                        shred::SSD_SHRED_CAVEAT
                    )),
                    Err(e) => Ok(format!(
                        "Encrypted to {save_path:?}, but shredding the original failed: {e}"
                    )),
                }
            } else {
                Ok(format!(
                    "Encrypted ({}). Saved: {save_path:?}",
                    crypto::kdf_name(kdf_id)
                ))
            }
        }
    })();

    let _ = tx.send(JobMsg::Done(result));
}

fn run_decrypt_job(
    in_path: PathBuf,
    out_path: PathBuf,
    // HIGH fix: see the matching comment on `run_encrypt_job` — same
    // never-zeroized-clone issue, same fix.
    pwd: Zeroizing<String>,
    is_streaming: bool,
    tx: Sender<JobMsg>,
) {
    let result = (|| -> Result<String, String> {
        if is_streaming {
            let tx_prog = tx.clone();
            let cb = crypto::Progress {
                callback: Box::new(move |done, total| {
                    let pct = if total > 0 {
                        done as f32 / total as f32
                    } else {
                        0.0
                    };
                    let _ = tx_prog.send(JobMsg::Progress(
                        pct,
                        format!("Decrypting… {:.0}%", pct * 100.0),
                    ));
                }),
            };
            crypto::stream_decrypt_file(&in_path, Some(&out_path), &pwd, Some(cb))
                .map_err(|e| e.to_string())?;
        } else {
            crypto::check_blob_file_size(&in_path).map_err(|e| e.to_string())?;
            let file_contents = std::fs::read(&in_path).map_err(|e| e.to_string())?;
            let combined = crypto::decode_blob_text(&file_contents);
            let plain = Zeroizing::new(
                crypto::decrypt_blob_compat(&pwd, &combined).map_err(|e| e.to_string())?,
            );
            let legacy_no_aad = crypto::is_legacy_no_aad_format(&combined);
            let tmp = crypto::unique_tmp_path(&out_path);
            crypto::write_durable(&tmp, &plain).map_err(|e| e.to_string())?;
            if let Err(e) = crypto::replace_file(&tmp, &out_path) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e.to_string());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = std::fs::metadata(&out_path) {
                    let mut p = m.permissions();
                    p.set_mode(0o600);
                    let _ = std::fs::set_permissions(&out_path, p);
                }
            }
            let msg = if legacy_no_aad {
                format!(
                    "Decrypted and saved: {out_path:?}\n\
                     Note: this file was in the legacy (pre-Rust-port) container format, \
                     which doesn't bind an AAD to its ciphertext — its authentication tag \
                     only verifies the bytes weren't tampered with, not that this particular \
                     ciphertext belongs with this particular format/version/KDF. Re-encrypting \
                     it (Encrypt tab) will upgrade it to the current AAD-bound format."
                )
            } else {
                format!("Decrypted and saved: {out_path:?}")
            };
            return Ok(msg);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(m) = std::fs::metadata(&out_path) {
                let mut p = m.permissions();
                p.set_mode(0o600);
                let _ = std::fs::set_permissions(&out_path, p);
            }
        }
        Ok(format!("Decrypted and saved: {out_path:?}"))
    })();
    let _ = tx.send(JobMsg::Done(result));
}

impl eframe::App for UnigenApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.tick_autoclear();
        self.tick_pwd_autoclear();
        self.tick_vault_autolock();
        self.poll_jobs(ctx);

        // Replaces the old `on_close_event` hook, which was removed from
        // eframe's `App` trait. We intercept the close request via viewport
        // input; if a background job is running we cancel the close and
        // show the confirmation window (below), otherwise we clean up and
        // let the close proceed.
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.busy_ops.is_empty() {
                self.enc_pwd.clear();
                self.dec_pwd.clear();
                self.editor_open_pwd.clear();
                self.close_editor();
                self.clear_clipboard();
                self.lock_vault(false);
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.show_close_confirm = true;
            }
        }

        if self.encrypt_shred_prompt_open {
            egui::Window::new("Encryption Passphrase")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(
                        "Enter a passphrase (min 8 characters) to protect this password file:",
                    );
                    ui.add(egui::TextEdit::singleline(&mut self.encrypt_shred_pwd).password(true));
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.encrypt_shred_pwd.clear();
                            self.encrypt_shred_prompt_open = false;
                        }
                        let can_go = self.encrypt_shred_pwd.chars().count() >= 8;
                        if ui
                            .add_enabled(can_go, egui::Button::new("Encrypt & Shred"))
                            .clicked()
                        {
                            self.encrypt_shred_prompt_open = false;
                            self.run_encrypt_and_shred_password_file();
                        }
                    });
                    if !self.encrypt_shred_pwd.is_empty()
                        && self.encrypt_shred_pwd.chars().count() < 8
                    {
                        ui.colored_label(
                            self.palette().danger,
                            "Passphrase must be at least 8 characters.",
                        );
                    }
                });
        }

        if self.editor_open_prompt {
            egui::Window::new("Decrypt for editing")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label("Passphrase for:");
                    if let Some(p) = &self.editor_open_target {
                        ui.small(p.display().to_string());
                    }
                    ui.add(egui::TextEdit::singleline(&mut self.editor_open_pwd).password(true));
                    if !self.editor_open_error.is_empty() {
                        ui.colored_label(self.palette().danger, &self.editor_open_error);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            self.editor_open_pwd.clear();
                            self.editor_open_error.clear();
                            self.editor_open_prompt = false;
                            self.editor_open_target = None;
                        }
                        let can_go = !self.editor_open_pwd.is_empty();
                        if ui
                            .add_enabled(can_go, egui::Button::new("Decrypt"))
                            .clicked()
                        {
                            let path = self.editor_open_target.clone().unwrap();
                            let pwd = std::mem::take(&mut self.editor_open_pwd);
                            self.open_editor_decrypt(path, pwd);
                        }
                    });
                });
        }

        if self.editor_confirm_close {
            egui::Window::new("Discard changes?")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(
                        "You have unsaved edits in the password editor. Close without saving?",
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Keep editing").clicked() {
                            self.editor_confirm_close = false;
                        }
                        if ui.button("Discard & close").clicked() {
                            self.close_editor();
                        }
                    });
                });
        }

        if self.show_close_confirm {
            egui::Window::new("Operation in progress")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(
                        "An encryption, decryption, or shred operation is still running.\n\
                         Closing now may leave an incomplete temporary file (it will use a \
                         unique name and will never overwrite the finished output).",
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Wait for it to finish").clicked() {
                            self.show_close_confirm = false;
                        }
                        if ui.button("Close anyway").clicked() {
                            // Background threads (streaming encrypt/decrypt,
                            // shred) can't be forcibly cancelled from here,
                            // but they can never corrupt the real output:
                            // every writer targets a uniquely-named temp
                            // file and only renames it over the destination
                            // after a full, successful, fsynced write (see
                            // crypto::unique_tmp_path). A hard exit here at
                            // worst leaves an orphaned `*.unigen-tmp` file
                            // next to the intended output, never a
                            // corrupted "finished" file and never someone
                            // else's unrelated `.tmp` file.
                            self.enc_pwd.clear();
                            self.dec_pwd.clear();
                            self.editor_open_pwd.clear();
                            self.close_editor();
                            self.clear_clipboard();
                            std::process::exit(0);
                        }
                    });
                });
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("UNIGEN");
                ui.label("Unicode password generation & file protection");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // ☾ (U+263E) isn't a real emoji codepoint, so most
                    // fonts — including egui's bundled emoji font — have no
                    // glyph for it and render nothing. 🌙 (U+1F319, an
                    // actual emoji) is the equivalent that reliably shows.
                    if ui
                        .button(if self.dark_mode {
                            "☀ Light"
                        } else {
                            "🌙 Dark"
                        })
                        .clicked()
                    {
                        self.dark_mode = !self.dark_mode;
                        theme::apply(ctx, self.dark_mode);
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Generator, "Password Generator");
                ui.selectable_value(&mut self.tab, Tab::FileProtector, "File Protector");
                ui.selectable_value(&mut self.tab, Tab::Vault, "Vault");
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // The File Protector tab's content (three panels + the
            // password editor, which itself grows with search results)
            // can be taller than the window, especially at the min window
            // size or with a long status message at the very bottom (e.g.
            // "Saved & re-encrypted: ..."). Without an outer scroll area
            // that content silently clips at the window edge instead of
            // being reachable. Wrapping in a ScrollArea makes the whole
            // tab scrollable rather than clipped.
            egui::ScrollArea::vertical()
                .id_source("central_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| match self.tab {
                    Tab::Generator => self.ui_generator_tab(ui),
                    Tab::FileProtector => self.ui_file_protector_tab(ui),
                    Tab::Vault => self.ui_vault_tab(ui),
                });
        });
    }
}

impl UnigenApp {
    fn ui_generator_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(300.0);
                ui.group(|ui| {
                    ui.strong("Generation Settings");
                    ui.separator();

                    ui.label("Password length");
                    ui.add(egui::Slider::new(&mut self.length, 8..=128));

                    ui.label("Number of passwords");
                    ui.add(egui::Slider::new(&mut self.count, 1..=10_000));

                    ui.separator();
                    ui.strong("Character sets");
                    for (set, enabled) in self.charsets.iter().zip(self.charset_enabled.iter_mut()) {
                        ui.checkbox(enabled, set.name);
                        ui.small(set.desc);
                    }

                    if self.active_pool().is_empty() {
                        ui.colored_label(egui::Color32::RED, "Select at least one character set.");
                    }
                });
            });

            ui.vertical(|ui| {
                ui.set_width(ui.available_width());
                let pool = self.active_pool();
                let entropy = calculate_entropy(self.length as usize, pool.len());
                let (rating, kind) = rate_entropy(entropy);
                let p = self.palette();
                let color = match kind {
                    "danger" => p.danger,
                    "warning" => p.warning,
                    _ => p.success,
                };

                ui.horizontal(|ui| {
                    ui.group(|ui| {
                        ui.label("Pool size");
                        ui.strong(format!("{}", pool.len()));
                    });
                    ui.group(|ui| {
                        ui.label("Entropy");
                        ui.strong(format!("{entropy:.1} bits"));
                    });
                    ui.group(|ui| {
                        ui.label("Strength");
                        ui.colored_label(color, rating);
                    });
                });

                ui.add_space(8.0);
                let can_generate = !pool.is_empty();
                if ui
                    .add_enabled(can_generate, egui::Button::new("Generate Passwords").min_size(egui::vec2(0.0, 32.0)))
                    .clicked()
                {
                    self.generated = (0..self.count)
                        .map(|_| generate_password(self.length as usize, &pool))
                        .collect();
                    self.gen_status.clear();
                }

                ui.add_space(8.0);
                // Fixed height instead of "fill available space minus a
                // guessed reserve" — that approach kept pushing the button
                // row/status text below the visible window on shorter
                // windows. A fixed height also lets the window itself be
                // sized to fit its content instead of needing to be tall
                // enough to satisfy a dynamic min-height calculation.
                const LIST_HEIGHT: f32 = 260.0;
                ui.group(|ui| {
                    ui.set_height(LIST_HEIGHT);
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            if self.generated.is_empty() {
                                ui.label("Click “Generate Passwords” to begin.");
                            } else {
                                let mut to_copy: Option<String> = None;
                                for (i, pwd) in self.generated.iter().enumerate() {
                                    ui.horizontal(|ui| {
                                        if ui
                                            .button("Copy")
                                            .on_hover_text(format!("Copy just this password; auto-clears from the clipboard in {}s.", self.autoclear_seconds))
                                            .clicked()
                                        {
                                            to_copy = Some(pwd.as_str().to_owned());
                                        }
                                        let label_resp =
                                            ui.monospace(format!("#{}: {}", i + 1, pwd.as_str()));
                                        // Right-click menu as an alternative to the "Copy"
                                        // button / Ctrl+C. Routed through the same
                                        // `to_copy` + `copy_to_clipboard_20s` path used by
                                        // the button above, so it gets the identical
                                        // always-auto-clear behaviour — this is just another
                                        // entry point into the existing secure copy, not a
                                        // separate unguarded clipboard write.
                                        label_resp.context_menu(|ui| {
                                            if ui.button("Copy").clicked() {
                                                to_copy = Some(pwd.as_str().to_owned());
                                                ui.close_menu();
                                            }
                                        });
                                    });
                                }
                                if let Some(pwd) = to_copy {
                                    self.copy_to_clipboard_20s(&pwd);
                                }
                            }
                        });
                });

                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.generated.is_empty(), egui::Button::new("Copy All")).clicked() {
                        let text = Zeroizing::new(self.generated.iter().map(|p| p.as_str()).collect::<Vec<_>>().join("\n"));
                        self.copy_to_clipboard(&text);
                    }
                    if ui
                        .add_enabled(
                            !self.generated.is_empty() && self.pending_pick.is_none(),
                            egui::Button::new("Save to File"),
                        )
                        .clicked()
                    {
                        let default_name = format!("passwords_{}.txt", self.generated.len());
                        self.spawn_dialog(PendingPick::SaveGeneratedPasswords, move || {
                            rfd::FileDialog::new()
                                .set_file_name(default_name)
                                .add_filter("Text files", &["txt"])
                                .save_file()
                        });
                    }
                    if ui.button("Clear Clipboard").clicked() {
                        self.clear_clipboard();
                    }
                    if ui
                        .add_enabled(
                            self.last_saved_password_path.is_some(),
                            egui::Button::new("Encrypt & Shred Saved List"),
                        )
                        .clicked()
                    {
                        self.encrypt_shred_pwd.clear();
                        self.encrypt_shred_prompt_open = true;
                    }
                });

                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.autoclear_enabled, "Auto-clear clipboard after");
                    ui.add(egui::DragValue::new(&mut self.autoclear_seconds).range(5..=300));
                    ui.label("seconds (best-effort — paste can't be reliably detected)");
                });

                ui.horizontal(|ui| {
                    ui.label("Clear passphrase fields after");
                    ui.add(egui::DragValue::new(&mut self.pwd_autoclear_seconds).range(5..=600));
                    ui.label("seconds of inactivity");
                });

                ui.horizontal(|ui| {
                    ui.label("Auto-lock vault after");
                    // 0 disables auto-lock entirely (tick_vault_autolock
                    // treats `vault_autolock_seconds > 0` as the enabled
                    // condition), so this is a single control rather than
                    // a checkbox + DragValue pair like the clipboard one
                    // above.
                    ui.add(egui::DragValue::new(&mut self.vault_autolock_seconds).range(0..=3600));
                    ui.label("seconds of inactivity (0 = never)");
                });

                if !self.gen_status.is_empty() {
                    ui.label(&self.gen_status);
                }
                if !self.clip_status.is_empty() {
                    ui.label(&self.clip_status);
                }
            });
        });
    }

    fn ui_file_protector_tab(&mut self, ui: &mut egui::Ui) {
        ui.columns(2, |cols| {
            // ---- Left column: Encrypt ----
            cols[0].group(|ui| {
                ui.strong("Encrypt File");
                ui.small("Argon2id (default) or PBKDF2-HMAC-SHA256 (legacy) -> AES-256-GCM");
                ui.separator();

                ui.horizontal(|ui| {
                    let label = self
                        .enc_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(no file selected)".to_string());
                    ui.label(label);
                    if ui
                        .add_enabled(self.pending_pick.is_none(), egui::Button::new("Browse…"))
                        .clicked()
                    {
                        self.spawn_dialog(PendingPick::EncryptSelectFile, || {
                            rfd::FileDialog::new().set_title("Select file to encrypt").pick_file()
                        });
                    }
                });

                ui.add_space(6.0);
                ui.label("Key derivation function");
                egui::ComboBox::from_id_source("kdf_choice")
                    .selected_text(match self.kdf_choice {
                        crypto::KDF_ARGON2ID => "Argon2id (recommended, tried first)",
                        crypto::KDF_PBKDF2 => "PBKDF2-HMAC-SHA256 (legacy compatibility)",
                        _ => "Unknown",
                    })
                    .show_ui(ui, |ui| {
                        // Argon2id listed and selected first, per the fix
                        // to the old UI copy that implied PBKDF2 was the
                        // primary path.
                        ui.selectable_value(&mut self.kdf_choice, crypto::KDF_ARGON2ID, "Argon2id (recommended, tried first)");
                        ui.selectable_value(&mut self.kdf_choice, crypto::KDF_PBKDF2, "PBKDF2-HMAC-SHA256 (legacy compatibility)");
                    });
                ui.small(
                    "Argon2id (64 MiB memory, 3 passes, 4 lanes) is the default for all new \
                     encryptions and is tried first — it's far more resistant to GPU/ASIC \
                     cracking than PBKDF2. Only choose PBKDF2 if you need to match an older \
                     workflow.",
                );

                ui.add_space(6.0);
                ui.label(format!("Passphrase (min {} characters)", crypto::MIN_PASSPHRASE_LEN));
                let resp = ui.add(egui::TextEdit::singleline(&mut self.enc_pwd).password(true));
                if resp.changed() {
                    self.enc_pwd_last_edit = Instant::now();
                    // Best-effort: keep re-locking the field's *live*
                    // buffer into physical RAM after every edit (not just
                    // the one-off clone handed to the background job at
                    // encrypt time — see `SecretString::mlock_best_effort`
                    // doc comment for why the live field needs its own
                    // lock, re-applied on each edit since growth moves
                    // the buffer).
                    #[cfg(target_os = "linux")]
                    if self.linux_try_exclusion {
                        self.enc_pwd.mlock_best_effort();
                    }
                }
                if !self.enc_pwd.is_empty() {
                    let bits = estimate_passphrase_entropy(&self.enc_pwd);
                    let (rating, _) = rate_entropy(bits);
                    ui.small(format!(
                        "Estimated strength: {rating} (~{bits:.0} bits, character-class estimate — not a true entropy measurement)"
                    ));
                }
                ui.checkbox(
                    &mut self.enc_pwd_autoclear,
                    format!("Clear passphrase from memory after {}s of inactivity", self.pwd_autoclear_seconds),
                );

                ui.checkbox(&mut self.shred_after, "Verify, then securely shred the original after encryption");

                if cfg!(target_os = "linux") {
                    ui.checkbox(
                        &mut self.linux_try_exclusion,
                        "Best-effort: ask the OS to keep the passphrase out of swap (mlock)",
                    );
                    ui.small("Best effort only — not a guarantee on every kernel/filesystem configuration.");
                }

                ui.add_space(6.0);
                let busy = self.busy_ops.contains("encrypt");
                let ready = self.enc_file.is_some()
                    && self.enc_pwd.chars().count() >= crypto::MIN_PASSPHRASE_LEN
                    && !busy;
                if ui.add_enabled(ready, egui::Button::new(if busy { "Encrypting…" } else { "Encrypt" })).clicked() {
                    self.start_encrypt();
                }
                if let Some(job) = &self.encrypt_job {
                    if let Some(p) = job.progress {
                        ui.add(egui::ProgressBar::new(p).show_percentage());
                    }
                    ui.label(&job.last_status);
                }
                if !self.enc_status.is_empty() {
                    ui.label(&self.enc_status);
                }
            });

            // ---- Right column: Decrypt + Shred ----
            cols[1].group(|ui| {
                ui.strong("Decrypt File");
                ui.small("Select a .enc file produced by this app");
                ui.separator();

                ui.horizontal(|ui| {
                    let label = self
                        .dec_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(no file selected)".to_string());
                    ui.label(label);
                    if ui
                        .add_enabled(self.pending_pick.is_none(), egui::Button::new("Browse…"))
                        .clicked()
                    {
                        self.spawn_dialog(PendingPick::DecryptSelectFile, || {
                            rfd::FileDialog::new()
                                .set_title("Select encrypted file")
                                .add_filter("Encrypted files", &["enc"])
                                .pick_file()
                        });
                    }
                });

                ui.label("Passphrase");
                let resp = ui.add(egui::TextEdit::singleline(&mut self.dec_pwd).password(true));
                if resp.changed() {
                    self.dec_pwd_last_edit = Instant::now();
                    #[cfg(target_os = "linux")]
                    if self.linux_try_exclusion {
                        self.dec_pwd.mlock_best_effort();
                    }
                }
                ui.checkbox(
                    &mut self.dec_pwd_autoclear,
                    format!("Clear passphrase from memory after {}s of inactivity", self.pwd_autoclear_seconds),
                );

                ui.add_space(6.0);
                let busy = self.busy_ops.contains("decrypt");
                let ready = self.dec_file.is_some() && !self.dec_pwd.is_empty() && !busy;
                if ui.add_enabled(ready, egui::Button::new(if busy { "Decrypting…" } else { "Decrypt & Save" })).clicked() {
                    self.start_decrypt();
                }
                if let Some(job) = &self.decrypt_job {
                    if let Some(p) = job.progress {
                        ui.add(egui::ProgressBar::new(p).show_percentage());
                    }
                    ui.label(&job.last_status);
                }
                if !self.dec_status.is_empty() {
                    ui.label(&self.dec_status);
                }

                ui.add_space(14.0);
                ui.separator();
                ui.strong("Manual Secure Shred");
                ui.small("Multi-pass overwrite (random + zero) then delete");

                ui.horizontal(|ui| {
                    let label = self
                        .shred_target
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(no file selected)".to_string());
                    ui.label(label);
                    if ui
                        .add_enabled(self.pending_pick.is_none(), egui::Button::new("Browse…"))
                        .clicked()
                    {
                        self.spawn_dialog(PendingPick::ShredSelectFile, || {
                            rfd::FileDialog::new().set_title("Select file to shred").pick_file()
                        });
                    }
                });

                let shred_busy = self.busy_ops.contains("shred");
                let shred_ready = self.shred_target.is_some() && !shred_busy;
                if ui.add_enabled(shred_ready, egui::Button::new(if shred_busy { "Shredding…" } else { "Shred File" })).clicked() {
                    self.shred_confirm_open = true;
                }
                if self.shred_confirm_open {
                    egui::Window::new("Confirm shred")
                        .collapsible(false)
                        .resizable(false)
                        .show(ui.ctx(), |ui| {
                            ui.label(format!(
                                "Permanently shred this file?\n\n{:?}\n\nThis cannot be undone.",
                                self.shred_target
                            ));
                            ui.horizontal(|ui| {
                                if ui.button("Cancel").clicked() {
                                    self.shred_confirm_open = false;
                                }
                                if ui.button("Shred").clicked() {
                                    self.shred_confirm_open = false;
                                    self.start_shred();
                                }
                            });
                        });
                }
                if let Some(job) = &self.shred_job {
                    ui.label(&job.last_status);
                }
                if !self.shred_status.is_empty() {
                    ui.label(&self.shred_status);
                }
                ui.small(shred::SSD_SHRED_CAVEAT);
            });
        });

        ui.add_space(14.0);
        ui.separator();
        self.ui_password_editor(ui);
    }

    /// In-memory decrypted-password editor: decrypts a small `.enc` text
    /// file straight into a String (never to disk), lets it be searched by
    /// substring (e.g. "which entry is for example.com") and edited, then
    /// re-encrypts back over the original file on Save. The plaintext
    /// buffer and the passphrase used to open it are zeroized the moment
    /// the editor closes — on Discard, on a successful Save+Close, or on
    /// app exit — so nothing decrypted outlives the editor being open.
    fn ui_password_editor(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("Password File Editor");
            ui.small("(decrypted in memory only — never written to disk as plaintext)");
        });

        if !self.editor_open {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        self.pending_pick.is_none(),
                        egui::Button::new("Open .enc file to edit…"),
                    )
                    .clicked()
                {
                    self.spawn_dialog(PendingPick::EditorSelectFile, || {
                        rfd::FileDialog::new()
                            .set_title("Select encrypted password file to edit")
                            .add_filter("Encrypted files", &["enc"])
                            .pick_file()
                    });
                }
                ui.small("Best for small text password lists, not large streamed archives.");
            });
            return;
        }

        // ---- Editor is open ----
        ui.small(
            "Note: this file's decrypted content is only ever kept in memory, but sleep/\
             hibernate can still write RAM (including this) to disk — close the editor before \
             letting the machine sleep if that matters for this file.",
        );
        ui.horizontal(|ui| {
            if let Some(p) = &self.editor_source {
                ui.label(format!("Editing: {}", p.display()));
            }
            let dirty = self.editor_content != self.editor_original_content;
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Close").clicked() {
                    if dirty {
                        self.editor_confirm_close = true;
                    } else {
                        self.close_editor();
                    }
                }
                if ui
                    .add_enabled(dirty, egui::Button::new("Save (re-encrypt)"))
                    .clicked()
                {
                    self.save_editor();
                }
                if dirty {
                    ui.colored_label(self.palette().warning, "Unsaved changes");
                }
            });
        });

        ui.horizontal(|ui| {
            ui.label("Save with KDF:");
            egui::ComboBox::from_id_source("editor_kdf_choice")
                .selected_text(crypto::kdf_name(self.editor_kdf))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.editor_kdf, crypto::KDF_ARGON2ID, "Argon2id (recommended)");
                    ui.selectable_value(&mut self.editor_kdf, crypto::KDF_PBKDF2, "PBKDF2-HMAC-SHA256 (legacy)");
                });
            match self.editor_source_kdf {
                Some(source_kdf) if source_kdf != self.editor_kdf => {
                    ui.colored_label(
                        self.palette().warning,
                        format!(
                            "File is currently {}; saving will change it to {}.",
                            crypto::kdf_name(source_kdf),
                            crypto::kdf_name(self.editor_kdf)
                        ),
                    );
                }
                Some(source_kdf) => {
                    ui.small(format!("Matches file's current KDF ({}).", crypto::kdf_name(source_kdf)));
                }
                None => {
                    ui.small("File's KDF couldn't be read from its header (legacy format); saving will write it as shown above.");
                }
            }
        });

        ui.horizontal(|ui| {
            ui.label("Search:");
            ui.add(
                egui::TextEdit::singleline(&mut self.editor_search)
                    .hint_text("e.g. a site/domain name, to find which line its password is on"),
            );
            // Plain text instead of a "✕" glyph: that symbol isn't in
            // egui's bundled default font (the same tofu-box issue the
            // CJK/Kana fallback fonts fix for *content* doesn't cover UI
            // glyphs), so it rendered as an empty box.
            if !self.editor_search.is_empty() && ui.button("Clear").clicked() {
                self.editor_search.clear();
            }
        });
        ui.small(
            "Tip: the password must be the FIRST thing on the line — add any comment/label AFTER it, \
             separated by one or more spaces (e.g. \"hunter2XyZ99! mysite.com, changed 2024\"). \
             The Copy button on search results copies only the first word, so anything before the \
             password would get copied by mistake, and putting the password anywhere but first \
             would leave it out of the copy entirely.",
        );

        let searching = !self.editor_search.is_empty();

        if searching {
            // While searching, show ONLY the matching lines — not the full
            // content with a separate match list bolted on below it. This
            // view is read-only (line numbers are prepended, so it can't
            // be fed back into a plain edit buffer 1:1); clear the search
            // to go back to the full editable text.
            let needle = self.editor_search.to_lowercase();
            let matches: Vec<(usize, String)> = self
                .editor_content
                .lines()
                .enumerate()
                .filter(|(_, l)| l.to_lowercase().contains(&needle))
                .map(|(i, l)| (i, l.to_string()))
                .collect();
            ui.small(format!(
                "{} matching line(s) — clear search to edit the full file. Copied lines clear from the clipboard after {}s.",
                matches.len(),
                self.autoclear_seconds
            ));
            let mut to_copy: Option<String> = None;
            egui::ScrollArea::vertical()
                .id_source("editor_search_scroll")
                .max_height(340.0)
                .show(ui, |ui| {
                    if matches.is_empty() {
                        ui.small("No matches.");
                    } else {
                        for (line_no, line) in &matches {
                                ui.horizontal(|ui| {
                                    if ui.button("Copy").on_hover_text(format!("Copy just the password (the first word on the line); auto-clears from the clipboard in {}s.", self.autoclear_seconds)).clicked() {
                                        to_copy = Some(password_part(line));
                                    }
                                    let line_resp = ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(format!("{:>4}: {line}", line_no + 1))
                                                .font(egui::FontId::monospace(13.0)),
                                        )
                                        .selectable(true),
                                    );
                                    // Right-click menu mirroring the "Copy" button above:
                                    // "Copy password" copies just the first word (via the
                                    // same auto-clearing path as the button), "Copy line"
                                    // copies the whole displayed line (label + password) for
                                    // when the surrounding comment/label is also wanted —
                                    // that one still auto-clears too, since anything copied
                                    // out of a decrypted password file is sensitive.
                                    let full_line = line.clone();
                                    line_resp.context_menu(|ui| {
                                        if ui.button("Copy password").clicked() {
                                            to_copy = Some(password_part(&full_line));
                                            ui.close_menu();
                                        }
                                        if ui.button("Copy line").clicked() {
                                            to_copy = Some(full_line.clone());
                                            ui.close_menu();
                                        }
                                    });
                                });
                        }
                    }
                });
            if let Some(line) = to_copy {
                self.copy_to_clipboard_20s(&line);
            }
        } else {
            // Below a certain length this used to give a cramped ~120px
            // box; now that the window is taller by default (see main())
            // it gets a proper full-height editing area.
            let mut editor_resp_opt = None;
            egui::ScrollArea::vertical()
                .id_source("editor_main_scroll")
                .max_height(340.0)
                .show(ui, |ui| {
                    let r = ui.add(
                        egui::TextEdit::multiline(&mut self.editor_content)
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(10)
                            .desired_width(f32::INFINITY),
                    );
                    editor_resp_opt = Some(r);
                });
            // Selecting text inside the box and using the built-in
            // Ctrl+C/right-click-select already works via egui's own
            // TextEdit handling. This adds a plain right-click "Copy all"
            // for grabbing the whole decrypted buffer without having to
            // select-all first — routed through the same auto-clearing
            // `copy_to_clipboard_20s` as the rest of the editor's copy
            // actions, since this is decrypted file content.
            if let Some(r) = editor_resp_opt {
                let mut copy_all = false;
                r.context_menu(|ui| {
                    if ui.button("Copy all").clicked() {
                        copy_all = true;
                        ui.close_menu();
                    }
                });
                if copy_all {
                    let text = self.editor_content.as_str().to_owned();
                    self.copy_to_clipboard_20s(&text);
                }
            }
        }

        if !self.editor_status.is_empty() {
            ui.label(&self.editor_status);
        }
    }
}

/// The password is always the *first* whitespace-delimited token on the
/// line; everything after the first run of whitespace (one or more spaces
/// or tabs) is treated as a comment/label and ignored by "Copy". This
/// replaced an earlier '#'-based comment convention: passwords generated by
/// this app never contain a space (checked against every charset in
/// `charsets.rs`), so whitespace is an unambiguous separator — unlike '#',
/// which could collide with a '#' that legitimately appears inside the
/// password itself and silently truncate it.
fn password_part(line: &str) -> String {
    line.split_whitespace().next().unwrap_or("").to_string()
}

/// HIGH fix: previously used `rand::thread_rng()`. That's already a
/// cryptographically secure generator (ChaCha12, seeded from the OS CSPRNG
/// at startup and periodically reseeded) — not a "weak" PRNG — so this
/// wasn't a real entropy defect. Switching to `OsRng` draws directly from
/// the OS CSPRNG (`getrandom(2)`/`/dev/urandom` on Linux, `BCryptGenRandom`
/// on Windows) on every single character, removing any dependency on
/// `rand`'s internal generator/reseed state and any theoretical risk from
/// thread-local RNG state (e.g. around unexpected `fork()`s). Password
/// generation is a low-frequency operation, so the extra per-character
/// syscall cost is irrelevant here.
fn generate_password(length: usize, pool: &[char]) -> Zeroizing<String> {
    use rand::rngs::OsRng;
    use rand::Rng;
    if pool.is_empty() || length == 0 {
        return Zeroizing::new(String::new());
    }
    let mut rng = OsRng;
    Zeroizing::new(
        (0..length)
            .map(|_| pool[rng.gen_range(0..pool.len())])
            .collect(),
    )
}
