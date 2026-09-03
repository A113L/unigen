//! UNIGEN — Unicode Password Utility (Rust Edition)
//!
//! Rust/egui rewrite of the original Tkinter application. See README.md for
//! the list of behavioural changes made during the port (new container
//! format with AAD, unique per-run temp file names, real passphrase
//! zeroization).

// These used to be `mod X;` declarations directly in this file; they now
// live in `src/lib.rs` so `cargo test --lib`, Miri, ASan, and `cargo fuzz`
// can link against them without pulling in eframe's GUI/windowing runtime
// (see lib.rs's module doc comment). Every `foo::bar(...)` call site below
// is unchanged — only where the module is declared moved.
use unigen::{
    charsets, crypto, dpapi, mem_lock, process_isolation, secret, secure_text_edit, shred, vault,
};

use charsets::{
    all_charsets, build_pool, calculate_entropy, estimate_passphrase_entropy, rate_entropy, CharSet,
};
use eframe::egui;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};
use secret::{LockedSecret, SecretString};
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
        accent: Color32::from_rgb(0x4a, 0x90, 0xd9),
        accent_hover: Color32::from_rgb(0x35, 0x78, 0xb8),
        success: Color32::from_rgb(0x2d, 0xd4, 0xbf),
        danger: Color32::from_rgb(0xf0, 0x57, 0x6b),
        warning: Color32::from_rgb(0xd6, 0x8a, 0x19),
        button_bg: Color32::from_rgb(0x23, 0x28, 0x38),
    };

    /// Apply the palette to egui's global Visuals so every default-styled
    /// widget (panels, buttons, inputs, separators) picks it up, matching
    /// how the Python version recolors every ttk/tk widget via its theme
    /// dict rather than special-casing three accent colors.
    ///
    /// Dark-only build: light mode has been removed, so this always applies
    /// the `DARK` palette. The `dark` parameter is kept (always `true` at
    /// call sites) so the function signature and its call sites didn't need
    /// to be reworked beyond removing the toggle itself.
    pub fn apply(ctx: &eframe::egui::Context, dark: bool) {
        let p = &DARK;
        let mut visuals = eframe::egui::Visuals::dark();
        let _ = dark;

        // Clearlooks-inspired styling: restrained 3px corners, crisp 1px
        // borders, subtle shadows, compact controls and a calm blue accent.
        // This keeps egui's accessibility/interaction model intact while
        // getting rid of the default "flat web app" feel.
        visuals.override_text_color = Some(p.text);
        visuals.panel_fill = p.bg;
        visuals.window_fill = p.surface;
        visuals.window_rounding = eframe::egui::Rounding::same(4.0);
        visuals.window_stroke = eframe::egui::Stroke::new(1.0, p.border);
        visuals.faint_bg_color = p.surface_alt;
        visuals.extreme_bg_color = p.input_bg;
        visuals.code_bg_color = p.surface_alt;
        visuals.warn_fg_color = p.warning;
        visuals.error_fg_color = p.danger;
        visuals.popup_shadow = eframe::egui::Shadow {
            offset: eframe::egui::vec2(2.0, 3.0),
            blur: 8.0,
            spread: 1.0,
            color: eframe::egui::Color32::from_black_alpha(100),
        };
        visuals.window_shadow = eframe::egui::Shadow {
            offset: eframe::egui::vec2(0.0, 4.0),
            blur: 12.0,
            spread: 1.0,
            color: eframe::egui::Color32::from_black_alpha(120),
        };
        visuals.menu_rounding = eframe::egui::Rounding::same(4.0);
        visuals.button_frame = true;
        visuals.collapsing_header_frame = true;
        visuals.striped = true;
        visuals.slider_trailing_fill = true;

        // Base widget states. Clearlooks buttons are readable and bounded,
        // rather than relying on large filled rounded rectangles.
        for w in [
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            w.rounding = eframe::egui::Rounding::same(3.0);
        }
        visuals.widgets.noninteractive.rounding = eframe::egui::Rounding::same(3.0);
        visuals.widgets.noninteractive.bg_fill = p.surface;
        visuals.widgets.noninteractive.bg_stroke = eframe::egui::Stroke::new(1.0, p.border);
        // Plain (non-strong) labels, checkbox captions and slider text all
        // resolve their color from this noninteractive fg_stroke rather
        // than always going through `override_text_color` — leaving it at
        // its `Visuals::dark()`/`Visuals::light()` default made that text
        // render at a much lower-contrast gray than the rest of the UI.
        visuals.widgets.noninteractive.fg_stroke = eframe::egui::Stroke::new(1.0, p.text);

        visuals.widgets.inactive.bg_fill = p.button_bg;
        visuals.widgets.inactive.weak_bg_fill = p.button_bg;
        visuals.widgets.inactive.bg_stroke = eframe::egui::Stroke::new(1.0, p.border);
        visuals.widgets.inactive.fg_stroke.color = p.text;

        visuals.widgets.hovered.bg_fill = p.surface_alt;
        visuals.widgets.hovered.weak_bg_fill = p.surface_alt;
        visuals.widgets.hovered.bg_stroke = eframe::egui::Stroke::new(1.0, p.accent);
        visuals.widgets.hovered.fg_stroke.color = p.text;
        visuals.widgets.hovered.expansion = 0.0;

        visuals.widgets.active.bg_fill = p.accent;
        visuals.widgets.active.weak_bg_fill = p.accent;
        visuals.widgets.active.bg_stroke = eframe::egui::Stroke::new(1.0, p.accent_hover);
        visuals.widgets.active.fg_stroke.color = eframe::egui::Color32::WHITE;

        visuals.widgets.open.bg_fill = p.surface_alt;
        visuals.widgets.open.weak_bg_fill = p.surface_alt;
        visuals.widgets.open.bg_stroke = eframe::egui::Stroke::new(1.0, p.accent);

        visuals.selection.bg_fill = p.accent;
        visuals.selection.stroke = eframe::egui::Stroke::new(1.0, p.accent_hover);
        visuals.hyperlink_color = p.accent;
        visuals.text_cursor.stroke = eframe::egui::Stroke::new(1.5, p.accent);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = eframe::egui::vec2(7.0, 5.0);
        style.spacing.window_margin = eframe::egui::Margin::same(10.0);
        style.spacing.menu_margin = eframe::egui::Margin::same(6.0);
        style.spacing.button_padding = eframe::egui::vec2(9.0, 4.0);
        style.spacing.interact_size = eframe::egui::vec2(40.0, 26.0);
        style.spacing.slider_width = 160.0;
        style.spacing.combo_width = 150.0;
        style.spacing.text_edit_width = 300.0;
        style.spacing.icon_width = 14.0;
        style.visuals = visuals;

        // The default egui sizes (Heading 18 / Body & Button & Monospace 14
        // / Small 10) read a little large for a dense utility app like this
        // one. Trimmed down a notch — still comfortably readable. The
        // decrypted-file editor (File Protector tab) now takes at least
        // 3/4 of the window's height, so this sizing keeps it dense rather
        // than sparse even at that larger area.
        use eframe::egui::{FontId, FontFamily, TextStyle};
        style.text_styles = [
            (TextStyle::Heading, FontId::new(17.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(13.0, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(13.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
            (TextStyle::Small, FontId::new(11.0, FontFamily::Proportional)),
        ]
        .into();

        ctx.set_style(style);
    }
}

fn main() -> eframe::Result<()> {
    // Wire up `log`'s output to stderr so RUST_LOG=debug (or =trace) actually
    // shows something. Without this call, every log::warn!/error! emitted by
    // eframe/glow/egui_glow (e.g. GL context creation details, shader
    // compile/link failures, fallback paths taken on buggy/software
    // drivers) has nowhere to go — the `log` crate is a facade with no
    // effect until *some* logger implementation is installed, so the
    // terminal stays completely silent even when something is actually
    // going wrong internally. This was the missing piece behind "the
    // program runs with a terminal window open but nothing is ever
    // printed", independent of whatever the underlying rendering issue
    // turns out to be.
    env_logger::init();

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

    // Cross-platform process hardening (extends the Linux-only core-dump
    // mitigation above to macOS/Windows, and adds anti-injection/
    // anti-debug measures on Windows). See `process_isolation` module
    // docs for exactly what each platform gets and why none of it is a
    // hard security boundary. Must run before any secret (master
    // password, vault entries, editor plaintext) ever enters memory,
    // which is why this is still the very first thing `main` does after
    // logging setup.
    process_isolation::init();

    // Mirror the Python original: size the window relative to the screen
    // (capped to a sane range) and center it, instead of a fixed size.
    // A more compact default now that the scroll area properly fills its
    // space (see auto_shrink fix above) rather than needing extra window
    // height to avoid feeling cramped. Still resizable/centered, with a
    // min size that keeps both tabs usable without overflow.
    // The smaller default text size (see `theme::apply`) means every tab's
    // content is noticeably shorter than it used to be at the old font
    // sizes the 780px height was tuned for — trimmed back down so short
    // tabs like the password generator don't sit in a sea of empty space
    // below their content, while the File Protector tab (still the
    // tallest, thanks to the in-app decrypted password editor at the
    // bottom) remains comfortably scrollable rather than clipped.
    let (win_w, win_h) = (980.0_f32, 700.0_f32);
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
        // Force the legacy GLSL 1.20 shader path instead of letting glow
        // auto-detect a "modern" core-profile GLSL version (140+). Software
        // rasterizers like Mesa's SVGA3D/llvmpipe backend (seen in
        // VirtualBox VMs without real GPU passthrough) have historically
        // buggy core-profile shader compilation/linking, which manifests as
        // garbled/warped glyph and color rendering rather than an outright
        // failure — exactly what the multisampling workaround above didn't
        // fix. GLSL 1.20 uses the old compatibility-style pipeline that
        // these software drivers handle far more reliably. This has no
        // downside on real GPUs (AMD/NVIDIA/Intel all support GLSL 1.20
        // trivially) so it's safe to force unconditionally rather than
        // trying to detect "are we in a VM" at runtime.
        shader_version: Some(eframe::egui_glow::ShaderVersion::Gl120),
        ..Default::default()
    };
    eframe::run_native(
        "UNIGEN — Unicode Password Utility",
        options,
        Box::new(|cc| {
            // Lock out further dynamic-code allocation (Windows ACG) only
            // now, after eframe has already created the GL context and
            // egui_glow has compiled/linked its shaders. Doing this
            // before `run_native` (as originally written) blocked the
            // GPU driver's own startup JIT on Windows 11, which creates
            // the GL context successfully but silently renders nothing
            // — an empty black window with no crash and no error. See
            // `process_isolation::lock_dynamic_code` for the full
            // explanation. No-op on Linux/macOS.
            process_isolation::lock_dynamic_code();

            theme::apply(&cc.egui_ctx, true);
            load_custom_fonts(&cc.egui_ctx);
            // Disable "feathering" — the extra partially-transparent pixels
            // egui's tessellator adds along shape edges (text glyphs,
            // button rounded corners, etc.) to soften aliasing. This is an
            // alpha-blending-heavy technique, and software GL rasterizers
            // like Mesa's SVGA3D backend (seen in VirtualBox VMs without
            // real GPU passthrough) have shown buggy alpha blending here —
            // consistent with the warping being far more visible in dark
            // mode / on saturated button colors (high contrast exposes
            // blending errors) than in light mode (low contrast masks
            // them). Turning feathering off makes edges very slightly more
            // aliased/jagged on a *correctly* behaving driver, but that's a
            // minor cosmetic trade-off, whereas on a buggy driver it should
            // remove the warped-edge artifacts entirely since there's no
            // blended edge pixel left to render incorrectly.
            cc.egui_ctx
                .tessellation_options_mut(|o| o.feathering = false);
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

    // ---- Generator tab ----
    charsets: Vec<CharSet>,
    charset_enabled: Vec<bool>,
    length: u32,
    count: u32,
    // SECURITY: `LockedSecret`, not `Vec<Zeroizing<String>>` — a
    // generated batch sits displayed on screen for as long as the user
    // leaves this tab open (no natural flush point, same "long dwell
    // time" reasoning as `editor_content`/`vault_edit_notes`), so each
    // entry needs to stay sealed at rest and only be revealed
    // transiently (for painting one row, or for a copy/save operation)
    // rather than living as a permanently-plaintext `Zeroizing<String>`.
    generated: Vec<LockedSecret>,
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
    // SECURITY: sealed with `LockedSecret` (ChaCha20-obfuscated-at-rest,
    // same treatment as `enc_pwd`) rather than kept as a live
    // `SecretString` — unified across every passphrase field in the app.
    encrypt_shred_pwd: LockedSecret,

    // ---- Clipboard / auto-clear ----
    clipboard: Option<arboard::Clipboard>,
    autoclear_enabled: bool,
    autoclear_seconds: u32,
    autoclear_deadline: Option<Instant>,
    // SECURITY: was `Option<Zeroizing<String>>`. `Zeroizing<String>` wipes
    // its bytes on drop, but that's the *only* guarantee it gives — the
    // backing `String` is a normal heap allocation with no `mlock` and no
    // zeroize-before-realloc protection, and it sat here, holding a full
    // plaintext copy of whatever password was last copied to the
    // clipboard (including from the password generator), for the entire
    // `autoclear_seconds` window (up to 300s) every single time. That's
    // exactly the class of "stray plaintext copy of a secret parked in
    // ordinary memory" that `secret.rs`'s `LockedSecret` exists to close
    // for `VaultEntry::password` — this field deserves the same
    // treatment: encrypted-at-rest in RAM (ChaCha20 keystream, key in an
    // `mlock`ed allocation) between the moment it's copied and the moment
    // it's cleared, decrypted only into a short-lived `SecretString` via
    // `.reveal()` for the read-back comparison in `tick_autoclear`.
    autoclear_expected: Option<LockedSecret>,
    clip_status: String,

    // ---- File Protector: Encrypt ----
    kdf_choice: u8,
    enc_file: Option<PathBuf>,
    /// SECURITY: sealed with `LockedSecret`, not kept as a live
    /// `SecretString`, for the entire time the Encrypt-File tab isn't
    /// actively being typed into — see `ui_file_protector_tab` for the
    /// reveal-render-reseal pattern. Closes the gap where this field
    /// (unlike vault entry passwords) sat as plain readable UTF-8 in RAM
    /// for the whole autoclear-timeout window, or for as long as the app
    /// was simply open on a different tab.
    enc_pwd: LockedSecret,
    enc_pwd_last_edit: Instant,
    enc_pwd_autoclear: bool,
    shred_after: bool,
    enc_status: String,
    /// Linux-only: best-effort attempt to advise the OS to exclude
    /// decrypted/plaintext temp buffers from swap (mirrors the Python
    /// `linux_try_exclusion` setting; same "best effort, not a guarantee"
    /// caveat applies — see crypto::try_mlock equivalents).
    linux_try_exclusion: bool,
    /// Mirrors the live revealed copy's `is_locked()` from whichever of
    /// the two `vault_master_pwd` UI blocks last rendered this frame —
    /// `vault_master_pwd` itself is sealed (`LockedSecret`) the rest of
    /// the time, so there's no live buffer to query outside those blocks.
    /// `None` means "field is empty, nothing to lock yet" — kept
    /// distinct from `Some(false)` ("tried to lock, OS refused") so the
    /// status label doesn't claim a vacuous mlock success on an empty
    /// buffer as if a real passphrase were actually pinned in RAM.
    vault_master_pwd_mlocked: Option<bool>,

    // ---- File Protector: Decrypt ----
    dec_file: Option<PathBuf>,
    // SECURITY: sealed with `LockedSecret` — same rationale/pattern as
    // `enc_pwd`, see the block that renders this field for the
    // reveal-for-one-frame/reseal-immediately pattern.
    dec_pwd: LockedSecret,
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
    // SECURITY: sealed with `LockedSecret`, not a plain `SecretString` —
    // this is decrypted file content that can stay open (and thus live
    // in memory) for an arbitrarily long editing session with no
    // natural flush point, exactly the "long dwell time" risk class
    // `LockedSecret` exists for (same reasoning as `vault_edit_notes`).
    // Revealed into a short-lived `SecretString` only for the one frame
    // it's being rendered/edited/searched/saved, then resealed — see
    // the editor UI code and `save_editor`/`open_editor_decrypt`.
    editor_content: LockedSecret,
    /// Same sealing rationale as `editor_content` — this is compared
    // against it every frame for the dirty-check, so it needs the same
    // protection or it would just be a second unsealed copy of the same
    // decrypted file sitting in memory.
    editor_original_content: LockedSecret,
    // SECURITY: sealed with `LockedSecret` — this sits live for the
    // entire editor session (not just one frame), which is exactly the
    // "just sitting in memory" window `LockedSecret` exists to close.
    editor_pwd: LockedSecret,
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
    // SECURITY: sealed with `LockedSecret`, unified with every other
    // passphrase-entry field.
    editor_open_pwd: LockedSecret,
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
    // SECURITY: sealed with `LockedSecret` — the master password field
    // can sit live for as long as the unlock/change-password dialogs are
    // open, so it gets the same ChaCha20-obfuscated-at-rest treatment as
    // `enc_pwd`/`dec_pwd` instead of a plain `SecretString`.
    vault_master_pwd: LockedSecret,
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
    /// Like `vault_edit_notes` below: the field can sit open on screen
    /// for a long stretch with no natural flush point, so it's sealed
    /// with `LockedSecret` rather than kept as a live `SecretString` —
    /// same "long plaintext residency" concern, just for `username`
    /// instead of `notes`. Revealed into a short-lived `SecretString`
    /// for exactly one frame at a time to feed the edit widget, then
    /// immediately resealed — see the username UI block below.
    vault_edit_username: LockedSecret,
    vault_edit_password: SecretString,
    vault_edit_url: SecretString,
    /// Unlike the other `vault_edit_*` buffers, notes can sit open and
    /// unedited for a long stretch (the user reading/scrolling rather
    /// than actively typing) with no natural moment that flushes it back
    /// to `vault_entries`. Left as a plain `SecretString` it would be
    /// exactly the "long plaintext residency" problem `LockedSecret`
    /// exists to close (see `secret::LockedSecret` / `mem_cipher`'s doc
    /// comments) — same risk class as the vault-wide `password` field,
    /// just triggered by dwell time on this screen instead of the whole
    /// unlocked-vault lifetime. Kept sealed here; revealed into a
    /// short-lived `SecretString` for exactly one frame at a time to
    /// feed `SecureNotesEdit`, then immediately resealed — see the notes
    /// UI block below.
    vault_edit_notes: LockedSecret,
    vault_reveal_password: bool,
    vault_confirm_delete: Option<u64>,
    /// Auto-lock: mirrors the existing passphrase inactivity-clear
    /// pattern, but locks (re-encrypts and drops plaintext entries from
    /// memory) instead of just clearing a text field.
    vault_last_activity: Instant,
    vault_autolock_seconds: u32,
    /// U-05: how long (if at all) to remember the master password after
    /// a lock, and the DPAPI-sealed cache itself — see
    /// `vault::SessionUnlockCache`'s doc comment for the full policy.
    /// Replaces the previous `vault_remember_session: bool` +
    /// `vault_dpapi_cache: Option<Vec<u8>>` pair, which only ever
    /// implemented one fixed policy and — unlike this type — never
    /// cleared a stale cache when the user switched to a different
    /// vault file.
    vault_session_cache: vault::SessionUnlockCache,

    // ---- Vault: change master password ----
    vault_change_pwd_open: bool,
    // SECURITY: all three change-password fields sealed with
    // `LockedSecret`, unified with the rest of the app's passphrase
    // fields — see `vault_master_pwd` above for the rationale.
    vault_change_pwd_current: LockedSecret,
    vault_change_pwd_new: LockedSecret,
    vault_change_pwd_confirm: LockedSecret,
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
            charsets: sets,
            charset_enabled: enabled,
            length: 20,
            count: 3,
            generated: Vec::new(),
            gen_status: String::new(),
            last_saved_password_path: None,
            encrypt_shred_prompt_open: false,
            encrypt_shred_pwd: LockedSecret::default(),
            clipboard: arboard::Clipboard::new().ok(),
            autoclear_enabled: true,
            autoclear_seconds: 20,
            autoclear_deadline: None,
            autoclear_expected: None,
            clip_status: String::new(),
            kdf_choice: crypto::DEFAULT_KDF, // Argon2id first / default, per updated guidance
            enc_file: None,
            enc_pwd: LockedSecret::default(),
            enc_pwd_last_edit: Instant::now(),
            enc_pwd_autoclear: true,
            shred_after: true,
            enc_status: String::new(),
            linux_try_exclusion: false,
            vault_master_pwd_mlocked: None,
            dec_file: None,
            dec_pwd: LockedSecret::default(),
            dec_pwd_last_edit: Instant::now(),
            dec_pwd_autoclear: true,
            dec_status: String::new(),
            shred_target: None,
            shred_confirm_open: false,
            shred_status: String::new(),
            editor_open: false,
            editor_source: None,
            editor_content: LockedSecret::default(),
            editor_original_content: LockedSecret::default(),
            editor_pwd: LockedSecret::default(),
            editor_kdf: crypto::DEFAULT_KDF,
            editor_source_kdf: None,
            editor_search: String::new(),
            editor_status: String::new(),
            editor_confirm_close: false,
            editor_open_prompt: false,
            editor_open_target: None,
            editor_open_pwd: LockedSecret::default(),
            editor_open_error: String::new(),
            vault_path: None,
            vault_unlocked: false,
            vault_master_pwd: LockedSecret::default(),
            vault_entries: Zeroizing::new(Vec::new()),
            vault_kdf: crypto::DEFAULT_KDF,
            vault_status: String::new(),
            vault_dirty: false,
            vault_search: String::new(),
            vault_selected: None,
            vault_edit_title: SecretString::new(),
            vault_edit_username: LockedSecret::default(),
            vault_edit_password: SecretString::new(),
            vault_edit_url: SecretString::new(),
            vault_edit_notes: LockedSecret::default(),
            vault_reveal_password: false,
            vault_confirm_delete: None,
            vault_last_activity: Instant::now(),
            vault_autolock_seconds: 120,
            vault_session_cache: vault::SessionUnlockCache::new(),
            vault_change_pwd_open: false,
            vault_change_pwd_current: LockedSecret::default(),
            vault_change_pwd_new: LockedSecret::default(),
            vault_change_pwd_confirm: LockedSecret::default(),
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
        &theme::DARK
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
    ///
    /// Builds exactly one owned copy of `text` (`Zeroizing<String>`) and
    /// hands the OS clipboard crate its own separate owned `String` (that
    /// second copy is unavoidable — `arboard` needs ownership, and once
    /// it's in the OS clipboard it's outside this app's control anyway,
    /// same accepted residual risk documented in `secret.rs`). Previously
    /// this called `text.to_string()` twice independently — once for the
    /// clipboard, once stored in `autoclear_expected` — and both were
    /// plain `String`s that leaked unscrubbed plaintext into freed heap
    /// memory on drop/overwrite instead of just the one unavoidable copy.
    ///
    /// SECURITY (follow-up fix): that `autoclear_expected` copy is now a
    /// `LockedSecret`, not a `Zeroizing<String>` — see the field's doc
    /// comment. It used to sit as an ordinary (if zeroize-on-drop) heap
    /// `String` for the whole `autoclear_seconds` window, which for the
    /// password-generator's per-row "Copy" button (the caller of this
    /// function) meant a full plaintext copy of a just-generated
    /// password parked in normal memory, readable by a memory dump or
    /// swapped page, for up to 300s at a time.
    fn copy_to_clipboard_20s(&mut self, text: &str) {
        let owned = Zeroizing::new(text.to_string());
        if let Some(cb) = self.clipboard.as_mut() {
            if cb.set_text(owned.as_str().to_string()).is_ok() {
                self.autoclear_deadline =
                    Some(Instant::now() + Duration::from_secs(self.autoclear_seconds as u64));
                // SECURITY: sealed with `LockedSecret` instead of kept as
                // the plain `owned` — see the field doc comment.
                self.autoclear_expected = Some(LockedSecret::from_str(owned.as_str()));
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
        let owned = Zeroizing::new(text.to_string());
        if let Some(cb) = self.clipboard.as_mut() {
            if cb.set_text(owned.as_str().to_string()).is_ok() {
                self.clip_status = if self.autoclear_enabled {
                    self.autoclear_deadline =
                        Some(Instant::now() + Duration::from_secs(self.autoclear_seconds as u64));
                    // SECURITY: see the field doc comment on `autoclear_expected`.
                    self.autoclear_expected = Some(LockedSecret::from_str(owned.as_str()));
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
        // SECURITY: `self.vault_master_pwd` is sealed at rest
        // (`LockedSecret`) until this exact moment it's needed to
        // actually unlock the vault; revealed once into a live
        // `SecretString` (wipe-on-drop) for that.
        let mut pwd = std::mem::take(&mut self.vault_master_pwd).reveal();
        // Convenience path: the field was left empty (user just clicked
        // "Unlock" again after an auto-lock, or is reopening the app
        // after one under `UntilLogout`) but `vault_session_cache` has a
        // remembered password for this vault — recover it instead of
        // making the user retype it. Any failure inside `recover()`
        // (wrong Windows login session, tampered blob, platform without
        // DPAPI, mode is `Never`) just returns `None` rather than being
        // surfaced as an error, since the user never asked for this to
        // succeed — it's a bonus, not a requirement.
        if pwd.is_empty() {
            if let Some(recovered) = self.vault_session_cache.recover(&path) {
                pwd = recovered;
            }
        }
        let is_new = !path.exists();
        let result = vault::open_or_create(&path, &pwd);
        if result.is_ok() && !is_new {
            // Re-seal (rather than reuse whatever was already
            // cached): this keeps the cache in sync with whatever
            // password just proved correct, including the case
            // where the user typed a *different* password than the
            // one previously cached (e.g. after "Change master
            // password" while a stale cache from before the change
            // would otherwise have gone silently unused forever).
            // `remember()` itself is a no-op (beyond clearing any
            // stale cache) when the mode is `Never` or DPAPI isn't
            // available, so no extra guard is needed here.
            self.vault_session_cache.remember(&path, pwd.as_str());
        }
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
                // Show the *full* error chain (`{:#}`), not just the
                // outermost `.context()` message. `decrypt_vault` wraps
                // the real cause ("AES-GCM auth tag failed", "Argon2id
                // key derivation failed: memory allocation error", a
                // truncated/corrupted file, etc.) behind a generic
                // "wrong master password, or file is not a valid vault"
                // context note — that note is *useful* context, but
                // discarding the underlying cause entirely (the old
                // `{e}` behavior, anyhow's default `Display`) actively
                // hid the real reason from anyone trying to diagnose a
                // failed unlock, which matters most for exactly the
                // failures that *aren't* a typo'd password.
                self.vault_status = format!("Unlock failed: {e:#}");
                // A failed unlock attempt must not leave a stale cached
                // password around claiming to unlock this vault.
                self.vault_session_cache.clear(Some(&path));
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
                // Full chain again (see the matching note in
                // `unlock_vault`) — a save failure's real cause (disk
                // full, permissions, the new self-verification step in
                // `write_vault_file` catching a write that didn't
                // round-trip) is exactly what a user needs to see to do
                // anything useful about it.
                self.vault_status = format!("Save failed: {e:#}");
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
            // Sealed immediately rather than kept as the plain
            // `SecretString` clone `e.username.clone()` would give —
            // see the field's doc comment.
            self.vault_edit_username = LockedSecret::from_str(e.username.as_str());
            self.vault_edit_password = e.password.reveal();
            self.vault_edit_url = e.url.clone();
            // Sealed immediately rather than kept as the plain
            // `SecretString` clone `e.notes.clone()` would give —
            // see the field's doc comment.
            self.vault_edit_notes = LockedSecret::from_str(e.notes.as_str());
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
                // `.reveal()` decrypts into a short-lived `SecretString`
                // (wipe-on-drop) just long enough to copy its bytes into
                // `e.username`; `self.vault_edit_username` itself stays
                // sealed throughout — same handling as `e.notes` below.
                e.username = SecretString::from_str(self.vault_edit_username.reveal().as_str());
                e.password = LockedSecret::from_str(self.vault_edit_password.as_str());
                e.url = SecretString::from_str(self.vault_edit_url.as_str());
                // `.reveal()` decrypts into a short-lived `SecretString`
                // (wipe-on-drop) just long enough to copy its bytes into
                // `e.notes`; `self.vault_edit_notes` itself stays sealed
                // throughout.
                e.notes = SecretString::from_str(self.vault_edit_notes.reveal().as_str());
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
                username: SecretString::from_str(self.vault_edit_username.reveal().as_str()),
                password: LockedSecret::from_str(self.vault_edit_password.as_str()),
                url: SecretString::from_str(self.vault_edit_url.as_str()),
                notes: SecretString::from_str(self.vault_edit_notes.reveal().as_str()),
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
        // Reveal the two "new password" fields once, up front, purely to
        // validate them — the fields themselves stay sealed at rest
        // otherwise.
        let new_pwd_check = self.vault_change_pwd_new.reveal();
        if new_pwd_check.chars().count() < 8 {
            self.vault_change_pwd_error =
                "New password must be at least 8 characters.".to_string();
            return;
        }
        let confirm_check = self.vault_change_pwd_confirm.reveal();
        if new_pwd_check.as_str() != confirm_check.as_str() {
            self.vault_change_pwd_error = "New password and confirmation don't match.".to_string();
            return;
        }

        // Re-verify the *current* password against the file on disk
        // (not just "the vault happens to be unlocked right now") so a
        // stale unlock from long ago can't be used to silently change
        // the password to something the user didn't intend, and so a
        // typo in the current-password field is caught here rather than
        // producing a vault re-encrypted under the wrong assumption.
        //
        // `current` is kept alive (not zeroized yet) past this check:
        // `vault::change_master_password`'s fast path also needs the
        // current password itself, to unwrap the existing vault key
        // before re-wrapping it under the new one — see that function's
        // doc comment.
        let mut current = std::mem::take(&mut self.vault_change_pwd_current).reveal();
        let verify = vault::read_vault_file(&path).and_then(|combined| {
            vault::decrypt_vault(&current, &combined)
        });

        if verify.is_err() {
            current.zeroize();
            self.vault_change_pwd_error = "Current password is incorrect.".to_string();
            return;
        }

        let mut new_pwd = std::mem::take(&mut self.vault_change_pwd_new).reveal();
        drop(new_pwd_check);
        drop(confirm_check);
        let result = vault::change_master_password(
            &path,
            &current,
            &self.vault_entries,
            &new_pwd,
            self.vault_kdf,
        );
        current.zeroize();
        new_pwd.zeroize();
        self.vault_change_pwd_confirm.zeroize();

        match result {
            Ok(()) => {
                self.vault_dirty = false;
                self.vault_change_pwd_open = false;
                self.vault_change_pwd_error.clear();
                self.vault_status = "Master password changed.".to_string();
                // A cache sealed under the *old* password would silently
                // fail to unlock (harmlessly — `unlock_vault` falls back
                // to asking for the password) but there's no reason to
                // keep a now-wrong cached credential around at all, and
                // for `UntilLogout` a stale sidecar file left on disk
                // sealing the *old* password would be actively
                // misleading about what "remembered" even means here.
                self.vault_session_cache.clear(self.vault_path.as_deref());
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
        if dpapi::SUPPORTED {
            let before = self.vault_session_cache.mode;
            ui.label("Remember master password after lock:");
            ui.horizontal(|ui| {
                ui.radio_value(
                    &mut self.vault_session_cache.mode,
                    vault::RememberSession::Never,
                    "Never",
                );
                ui.radio_value(
                    &mut self.vault_session_cache.mode,
                    vault::RememberSession::UntilAppExit,
                    "Until app exits",
                );
                ui.radio_value(
                    &mut self.vault_session_cache.mode,
                    vault::RememberSession::UntilLogout,
                    "Until logout",
                );
            });
            if self.vault_session_cache.mode != before {
                // Switching modes invalidates whatever was cached under
                // the *previous* mode's guarantee — e.g. dropping from
                // `UntilLogout` to `UntilAppExit` must not leave the
                // on-disk sidecar file behind, and dropping to `Never`
                // must not leave anything cached at all.
                self.vault_session_cache.clear(self.vault_path.as_deref());
            }
            ui.small(match self.vault_session_cache.mode {
                vault::RememberSession::Never => {
                    "Every unlock — including right after an auto-lock — asks for the master \
                     password again."
                }
                vault::RememberSession::UntilAppExit => {
                    "An auto-lock still hides your entries, but the next \"Unlock\" click won't \
                     ask for the master password again, for as long as UNIGEN keeps running. \
                     Closing UNIGEN, a manual \"Lock\" click, changing the master password, or \
                     switching vault files all forget it immediately. Windows' own DPAPI keeps \
                     it sealed to your login — this app never stores it as plaintext, and never \
                     writes it to disk in this mode."
                }
                vault::RememberSession::UntilLogout => {
                    "Same as \"Until app exits\", but also survives closing and reopening \
                     UNIGEN — a small DPAPI-sealed file is kept next to the vault for that. A \
                     manual \"Lock\" click, changing the master password, or switching vault \
                     files still forgets it immediately (deletes that file, too)."
                }
            });
        }
        // U-06 fix: this setting (and its live status) previously only
        // appeared on the Encrypt File tab, even though it also governs
        // whether the vault master-password field gets `mlock`ed — a
        // vault-only user had no way to see or control it without
        // visiting an unrelated tab. Same `linux_try_exclusion` field,
        // now also surfaced here with a live status label.
        if mem_lock::SUPPORTED {
            ui.checkbox(
                &mut self.linux_try_exclusion,
                "Best-effort: ask the OS to keep the master password out of swap (mlock/VirtualLock)",
            );
            let (text, kind) =
                mem_lock::status_label_opt(self.linux_try_exclusion, self.vault_master_pwd_mlocked);
            let p = self.palette();
            let color = match kind {
                "success" => p.success,
                "danger" => p.danger,
                "warning" => p.warning,
                _ => p.text_secondary,
            };
            ui.horizontal(|ui| {
                ui.small("Master password memory-lock status:");
                ui.colored_label(color, text);
            });
        }
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
            // SECURITY: sealed at rest; revealed only for this render
            // and resealed immediately after — same pattern as `enc_pwd`.
            let mut live_master_pwd = self.vault_master_pwd.reveal();
            ui.horizontal(|ui| {
                ui.add(secure_text_edit::SecurePasswordEdit::new("vault_master_pwd", &mut live_master_pwd));
                // Must run every frame, not just on edits — `reveal()`
                // allocates a fresh buffer each frame, so gating this
                // behind `resp.changed()` left it unlocked (and the
                // status flickering) on every frame the user wasn't
                // actively typing.
                if self.linux_try_exclusion {
                    live_master_pwd.mlock_best_effort();
                }
                self.vault_master_pwd_mlocked = (!live_master_pwd.is_empty()).then(|| live_master_pwd.is_locked());
                let can_go = self.vault_path.is_some() && !live_master_pwd.is_empty();
                let clicked = ui
                    .add_enabled(can_go, egui::Button::new("Unlock"))
                    .clicked();
                // Reseal right away: `unlock_vault()` reveals its own
                // short-lived copy from the now-sealed field.
                self.vault_master_pwd = LockedSecret::seal(live_master_pwd);
                if clicked {
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
                // Unlike auto-lock (see `tick_vault_autolock`), a
                // deliberate manual lock means the user explicitly wants
                // the vault shut, so the remembered password (if any —
                // in memory for `UntilAppExit`, in memory and on disk
                // for `UntilLogout`) is discarded too — re-locking is
                // only meant to survive an *inactivity* auto-lock
                // transparently, not to be a no-op the user has to
                // consciously work around.
                self.vault_session_cache.clear(self.vault_path.as_deref());
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
            // SECURITY: same rationale as `password`/`notes` below — plain
            // `ui.text_edit_singleline` is backed by `egui::TextEdit`,
            // whose internal undo/redo stack (`Arc<Mutex<Undoer<(...,
            // String)>>>`, persisted in `egui::Memory`) pushes a fresh
            // plain-`String` snapshot of the *entire* field on every
            // keystroke and is unreachable/unzeroizable from application
            // code (see `secure_text_edit.rs` module docs for the
            // confirmed-in-practice core-dump finding). `username` sits in
            // memory for the entire unlocked vault session, same as
            // `password`, so it deserves the same "never hand text to
            // egui's own buffer" treatment `SecurePasswordEdit`/
            // `SecureNotesEdit` already give `password`/`notes` — hence
            // `SecurePasswordEdit::masked(false)`: same no-undo-history
            // guarantee, just with the real characters painted instead of
            // bullets.
            //
            // SECURITY: `vault_edit_username` is itself a `LockedSecret`
            // (sealed at rest) for the same "sits open on screen with no
            // natural flush point" reason as `vault_edit_notes` — see
            // that field's doc comment. `.reveal()` here decrypts it
            // into `username_plain`, a `SecretString` that lives only
            // for this one frame; it's sealed straight back into
            // `self.vault_edit_username` at the end of this block, on
            // every code path, so the plaintext window is exactly one
            // frame wide.
            let mut username_plain = self.vault_edit_username.reveal();
            let user_resp = ui.add(
                secure_text_edit::SecurePasswordEdit::new(
                    "vault_edit_username",
                    &mut username_plain,
                )
                .masked(false),
            );
            let mut user_copy: Option<SecretString> = None;
            user_resp.context_menu(|ui| {
                if ui.button("Copy").clicked() {
                    user_copy = Some(username_plain.clone());
                    ui.close_menu();
                }
            });
            if let Some(v) = user_copy {
                self.copy_to_clipboard(&v);
            }
            // Reseal immediately, same rationale/placement as the notes
            // block below.
            self.vault_edit_username = LockedSecret::seal(username_plain);
            ui.label("Password");
            ui.horizontal(|ui| {
                let pwd_field_resp = ui.add(
                    secure_text_edit::SecurePasswordEdit::new(
                        "vault_edit_password",
                        &mut self.vault_edit_password,
                    )
                    .masked(!self.vault_reveal_password),
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
            // SECURITY: same fix and rationale as `username` above.
            let url_resp = ui.add(
                secure_text_edit::SecurePasswordEdit::new(
                    "vault_edit_url",
                    &mut self.vault_edit_url,
                )
                .masked(false),
            );
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
            // SECURITY: `vault_edit_notes` is a `LockedSecret` (sealed
            // at rest) precisely so it doesn't sit as long-lived
            // plaintext while this panel is just open and not being
            // typed into. `.reveal()` here decrypts it into `notes_plain`
            // — a `SecretString` that lives only for this one frame —
            // and everything below (the widget itself, copy operations)
            // reads/writes that transient buffer. It's sealed straight
            // back into `self.vault_edit_notes` at the end of this
            // block, on every code path (including early edits), so the
            // plaintext window is exactly one frame wide — the same
            // "one frame" exposure the app already accepts elsewhere
            // (see `secure_text_edit` module docs on `egui::Event::Text`).
            let mut notes_plain = self.vault_edit_notes.reveal();
            let notes_resp = ui.add(
                secure_text_edit::SecureNotesEdit::new("vault_edit_notes", &mut notes_plain)
                    .desired_rows(6),
            );

            // Ctrl/Cmd+C inside the field itself: the widget never
            // touches the clipboard directly (see its doc comments) —
            // it only flags the request, so the actual copy still goes
            // through `copy_to_clipboard` here, same autoclear timer as
            // every other copy action in the app.
            if secure_text_edit::take_copy_request(ui, "vault_edit_notes") {
                let to_copy = match secure_text_edit::selected_range(ui, "vault_edit_notes") {
                    Some(range) => secure_text_edit::extract_range(&notes_plain, range),
                    None => Zeroizing::new(notes_plain.as_str().to_string()),
                };
                self.copy_to_clipboard(&to_copy);
            }

            let has_selection =
                secure_text_edit::selected_range(ui, "vault_edit_notes").is_some();
            let mut notes_copy: Option<Zeroizing<String>> = None;
            notes_resp.context_menu(|ui| {
                // SECURITY: only "Copy selection" is exposed here.
                // "Copy all" and "Copy line" each built their payload by
                // cloning the *entire* revealed `notes_plain` (or a
                // line-scan over it) into a fresh, separately-allocated
                // `String`/`Zeroizing<String>` — a second plaintext copy
                // of the whole note sitting in RAM, on top of the one
                // `notes_plain` already holds, for as long as that
                // button's closure lived. "Copy selection" is the only
                // action whose leaked footprint is bounded by what the
                // user actually selected, so it's the only one kept.
                if ui
                    .add_enabled(has_selection, egui::Button::new("Copy selection"))
                    .clicked()
                {
                    if let Some(range) =
                        secure_text_edit::selected_range(ui, "vault_edit_notes")
                    {
                        notes_copy = Some(secure_text_edit::extract_range(&notes_plain, range));
                    }
                    ui.close_menu();
                }
            });
            if let Some(v) = notes_copy {
                self.copy_to_clipboard(&v);
            }

            // Reseal immediately: `notes_plain` (and its heap buffer)
            // is consumed here rather than dropped-then-recreated, so
            // this frame's edits never exist as an unsealed `SecretString`
            // any longer than the widget call above needed them to.
            self.vault_edit_notes = LockedSecret::seal(notes_plain);

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
            // SECURITY: sealed at rest; revealed only for this render
            // and resealed immediately after.
            let mut live_master_pwd = self.vault_master_pwd.reveal();
            ui.horizontal(|ui| {
                ui.label("Master password to save:");
                ui.add(secure_text_edit::SecurePasswordEdit::new("vault_master_pwd", &mut live_master_pwd));
                // Must run every frame — see the matching comment on the
                // unlock-screen block above for why gating this behind
                // `resp.changed()` caused the status to flicker.
                if self.linux_try_exclusion {
                    live_master_pwd.mlock_best_effort();
                }
                self.vault_master_pwd_mlocked = (!live_master_pwd.is_empty()).then(|| live_master_pwd.is_locked());
                if ui.button("Save vault").clicked() {
                    self.save_vault_with(&live_master_pwd);
                    live_master_pwd.clear();
                }
            });
            self.vault_master_pwd = LockedSecret::seal(live_master_pwd);
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
                    // SECURITY: all three fields sealed at rest
                    // (`LockedSecret`); revealed only for this render and
                    // resealed immediately after — same pattern used for
                    // every other passphrase field in this app.
                    let mut live_current = self.vault_change_pwd_current.reveal();
                    let mut live_new = self.vault_change_pwd_new.reveal();
                    let mut live_confirm = self.vault_change_pwd_confirm.reveal();
                    ui.add(
                        secure_text_edit::SecurePasswordEdit::new(
                            "vault_change_pwd_current",
                            &mut live_current,
                        ),
                    );
                    ui.label("New master password (min 8 characters):");
                    ui.add(
                        secure_text_edit::SecurePasswordEdit::new(
                            "vault_change_pwd_new",
                            &mut live_new,
                        ),
                    );
                    ui.label("Confirm new master password:");
                    ui.add(
                        secure_text_edit::SecurePasswordEdit::new(
                            "vault_change_pwd_confirm",
                            &mut live_confirm,
                        ),
                    );
                    if !self.vault_change_pwd_error.is_empty() {
                        ui.colored_label(pal.danger, &self.vault_change_pwd_error);
                    }
                    let mut cancelled = false;
                    let mut go = false;
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                        let can_go = !live_current.is_empty()
                            && live_new.chars().count() >= 8
                            && !live_confirm.is_empty();
                        if ui
                            .add_enabled(can_go, egui::Button::new("Change password"))
                            .clicked()
                        {
                            go = true;
                        }
                    });
                    // Reseal right away: `change_master_password()`
                    // reveals its own short-lived copies from the
                    // now-sealed fields.
                    self.vault_change_pwd_current = LockedSecret::seal(live_current);
                    self.vault_change_pwd_new = LockedSecret::seal(live_new);
                    self.vault_change_pwd_confirm = LockedSecret::seal(live_confirm);
                    if cancelled {
                        self.close_change_pwd_dialog();
                    } else if go {
                        self.change_master_password();
                    }
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
                self.encrypt_shred_pwd.zeroize();
                return;
            }
        };

        // Reveal the sealed passphrase exactly once for this operation;
        // `revealed` is a `SecretString` (wipe-on-drop/realloc) and the
        // field itself stays sealed the whole time otherwise.
        let revealed = self.encrypt_shred_pwd.reveal();
        let pwd = Zeroizing::new(revealed.as_str().to_string());
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

        self.encrypt_shred_pwd.zeroize();
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
                // The read-back itself is wrapped in `Zeroizing` too: it's
                // a fresh plaintext copy of whatever's on the clipboard
                // (secret, if `still_ours` turns out true) and would
                // otherwise leak the same way the old `autoclear_expected`
                // did before this file's copy-to-clipboard paths were
                // fixed to zeroize on drop.
                let cur = self
                    .clipboard
                    .as_mut()
                    .and_then(|cb| cb.get_text().ok())
                    .map(Zeroizing::new);
                // `.reveal()` decrypts into a short-lived `SecretString`
                // just for this comparison — same "only the brief
                // revealed copy is plaintext" guarantee `LockedSecret`
                // gives `VaultEntry::password`'s reveal path.
                let expected_revealed = self.autoclear_expected.as_ref().map(|e| e.reveal());
                let still_ours = match (&cur, &expected_revealed) {
                    (Some(c), Some(e)) => c.as_str() == e.as_str(),
                    (None, _) => true,
                    (Some(_), None) => false,
                };
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
            self.enc_pwd.zeroize();
            self.enc_status = format!(
                "Passphrase cleared from memory after {}s of inactivity.",
                self.pwd_autoclear_seconds
            );
        }
        if self.dec_pwd_autoclear
            && !self.dec_pwd.is_empty()
            && self.dec_pwd_last_edit.elapsed() > secs
        {
            self.dec_pwd.zeroize();
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
        // Reveal the sealed passphrase exactly once for this whole
        // operation. `revealed` is a `SecretString` (wipe-on-drop/realloc),
        // and `self.enc_pwd` stays sealed the entire time — this brief,
        // local plaintext copy is the only one that exists.
        let revealed = self.enc_pwd.reveal();
        if revealed.chars().count() < crypto::MIN_PASSPHRASE_LEN {
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

        let pwd = Zeroizing::new(revealed.as_str().to_string());
        let kdf_id = self.kdf_choice;
        let shred_after = self.shred_after;
        if self.linux_try_exclusion && !try_mlock_str(&pwd) {
            self.enc_status =
                "Warning: mlock()/VirtualLock failed; passphrase remains subject to normal VM paging."
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
        // Reveal the sealed passphrase exactly once for this operation.
        let revealed = self.dec_pwd.reveal();
        let pwd = Zeroizing::new(revealed.as_str().to_string());
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
                // buffer and zeroizes the source `String` afterward. Both
                // `LockedSecret`s are then derived from that one
                // zeroize-on-drop `SecretString` (`plain`) rather than
                // from `text` a second time, so there's still only ever
                // one transient plaintext copy of the freshly-decrypted
                // file, and it's gone (zeroized) as soon as `plain` goes
                // out of scope at the end of this block.
                let plain = SecretString::from(text);
                self.editor_content = LockedSecret::from_str(plain.as_str());
                self.editor_original_content = LockedSecret::from_str(plain.as_str());
                // SECURITY: sealed for the whole editing session — see
                // the field's doc comment.
                self.editor_pwd = LockedSecret::seal(pwd);
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
                self.editor_open_pwd.zeroize();
                self.editor_open_error.clear();
            }
            Err(e) => {
                self.editor_open_pwd.zeroize();
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
        // Revealed only for the duration of this save (encrypt + verify)
        // operation — same transient-reveal, resealed-after pattern used
        // everywhere else `LockedSecret` is read. `editor_content` itself
        // is untouched/still sealed throughout.
        let expected = self.editor_content.reveal();
        // Reveal the sealed passphrase once for this save operation.
        let revealed_pwd = self.editor_pwd.reveal();
        let result = (|| -> anyhow::Result<()> {
            let combined =
                crypto::encrypt_blob(&revealed_pwd, expected.as_bytes(), self.editor_kdf)?;

            // Verify round-trip BEFORE touching the real file: decrypt the
            // freshly-produced ciphertext with the same passphrase and
            // confirm it matches exactly what we intended to save.
            let verify = Zeroizing::new(
                crypto::decrypt_blob(&revealed_pwd, &combined).map_err(|e| {
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
                self.editor_original_content = LockedSecret::from_str(expected.as_str());
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
        self.editor_content.zeroize();
        self.editor_original_content.zeroize();
        self.editor_pwd.zeroize();
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
                    // BUG FIX (found while implementing U-05): switching
                    // to a different vault file never cleared the
                    // session-remember cache for the *previous* vault —
                    // `vault_dpapi_cache`'s own doc comment already
                    // claimed this was cleared "on picking a different
                    // vault file", but nothing here actually did it. A
                    // stale cache is harmless on its own (it's keyed to
                    // the old vault's path and password, so it would
                    // just silently fail to apply to the new one — see
                    // `SessionUnlockCache::recover`), but for
                    // `UntilLogout` it also meant an old vault's sidecar
                    // cache file was left behind on disk indefinitely
                    // instead of being cleaned up the moment the user
                    // moved on to a different vault.
                    self.vault_session_cache.clear(self.vault_path.as_deref());
                    self.vault_path = Some(path);
                }
            }
            PendingPick::NewVault => {
                if let Some(path) = path {
                    self.lock_vault(true);
                    self.vault_session_cache.clear(self.vault_path.as_deref());
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
                // Revealed only for this write-to-file operation — each
                // entry stays sealed in `self.generated` otherwise.
                let revealed: Vec<SecretString> =
                    self.generated.iter().map(|p| p.reveal()).collect();
                let content = Zeroizing::new(
                    revealed
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

/// Best-effort: ask the OS to keep `s`'s backing memory out of swap/the
/// pagefile for as long as this process holds the lock (mirrors the
/// Python original's `try_mlock`, which does the same via ctypes on
/// Linux only, and extends it beyond Linux via `mem_lock`'s Unix
/// `mlock`/Windows `VirtualLock` — see that module's docs). Returns false
/// when the OS refuses the lock, or when the platform has no such
/// primitive (`mem_lock::SUPPORTED == false`); callers must treat it as
/// best-effort, same as every other lock call site in this app.
fn try_mlock_str(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    mem_lock::lock(s.as_ptr(), s.len())
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
    /// By default eframe saves the whole `egui::Context` memory —
    /// including its `Style`/`Visuals`, since `ctx.set_style()` writes
    /// there too — to disk and restores it on the next launch, layered on
    /// top of whatever `theme::apply()` sets in `main()`. That is what
    /// made this app's very first frame after an update sometimes render
    /// with a stale, previously-saved theme (wrong accent color, uncompacted
    /// spacing) until the in-app dark/light toggle was clicked once and
    /// reapplied the current theme at runtime. Nothing here benefits from
    /// surviving a restart anyway (scroll offsets, collapsing-header state,
    /// etc., for a password vault app), so persistence is switched off
    /// entirely and `theme::apply()` is always the sole source of truth.
    fn persist_egui_memory(&self) -> bool {
        false
    }

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
                self.enc_pwd.zeroize();
                self.dec_pwd.zeroize();
                self.editor_open_pwd.zeroize();
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
                    // SECURITY: sealed at rest (`LockedSecret`); revealed
                    // into a live `SecretString` only for this render and
                    // resealed immediately after — same pattern as
                    // `enc_pwd` in the Encrypt tab.
                    let mut live_pwd = self.encrypt_shred_pwd.reveal();
                    ui.add(secure_text_edit::SecurePasswordEdit::new("encrypt_shred_pwd", &mut live_pwd));
                    let mut cancelled = false;
                    let mut go = false;
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                            self.encrypt_shred_prompt_open = false;
                        }
                        let can_go = live_pwd.chars().count() >= 8;
                        if ui
                            .add_enabled(can_go, egui::Button::new("Encrypt & Shred"))
                            .clicked()
                        {
                            self.encrypt_shred_prompt_open = false;
                            go = true;
                        }
                    });
                    let show_too_short = !live_pwd.is_empty() && live_pwd.chars().count() < 8;
                    // Reseal right away: the field is only ever live for
                    // this one render.
                    if cancelled {
                        live_pwd.clear();
                        self.encrypt_shred_pwd = LockedSecret::seal(live_pwd);
                    } else {
                        self.encrypt_shred_pwd = LockedSecret::seal(live_pwd);
                        if go {
                            self.run_encrypt_and_shred_password_file();
                        }
                    }
                    if show_too_short {
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
                    // SECURITY: sealed at rest; revealed only for this
                    // render and resealed immediately after — same
                    // pattern as `enc_pwd`.
                    let mut live_pwd = self.editor_open_pwd.reveal();
                    ui.add(secure_text_edit::SecurePasswordEdit::new("editor_open_pwd", &mut live_pwd));
                    if !self.editor_open_error.is_empty() {
                        ui.colored_label(self.palette().danger, &self.editor_open_error);
                    }
                    let mut cancelled = false;
                    let mut go = false;
                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                            self.editor_open_error.clear();
                            self.editor_open_prompt = false;
                            self.editor_open_target = None;
                        }
                        let can_go = !live_pwd.is_empty();
                        if ui
                            .add_enabled(can_go, egui::Button::new("Decrypt"))
                            .clicked()
                        {
                            go = true;
                        }
                    });
                    if cancelled {
                        live_pwd.clear();
                        self.editor_open_pwd = LockedSecret::default();
                    } else if go {
                        let path = self.editor_open_target.clone().unwrap();
                        self.editor_open_pwd = LockedSecret::default();
                        self.open_editor_decrypt(path, live_pwd);
                    } else {
                        self.editor_open_pwd = LockedSecret::seal(live_pwd);
                    }
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
                            self.enc_pwd.zeroize();
                            self.dec_pwd.zeroize();
                            self.editor_open_pwd.zeroize();
                            self.close_editor();
                            self.clear_clipboard();
                            std::process::exit(0);
                        }
                    });
                });
        }

        egui::TopBottomPanel::top("header").frame(
            egui::Frame::none()
                .fill(self.palette().surface)
                .inner_margin(egui::Margin::symmetric(14.0, 9.0))
                .stroke(egui::Stroke::new(1.0, self.palette().border)),
        ).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(
                    egui::RichText::new("UNIGEN").strong().size(22.0),
                );
                ui.separator();
                ui.label(
                    egui::RichText::new("Unicode password generation & file protection")
                        .color(self.palette().text_secondary),
                );
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let tabs = [
                    (Tab::Generator, "Password Generator"),
                    (Tab::FileProtector, "File Protector"),
                    (Tab::Vault, "Vault"),
                ];
                for (tab, label) in tabs {
                    let selected = self.tab == tab;
                    let button = egui::SelectableLabel::new(
                        selected,
                        egui::RichText::new(label).strong(),
                    );
                    if ui.add(button).clicked() {
                        self.tab = tab;
                    }
                }
            });
        });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(self.palette().bg)
                    .inner_margin(egui::Margin::symmetric(12.0, 10.0)),
            )
            .show(ctx, |ui| {
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
                ui.set_width(270.0);
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
                        .map(|_| {
                            LockedSecret::from_str(
                                generate_password(self.length as usize, &pool).as_str(),
                            )
                        })
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
                                let mut to_copy: Option<Zeroizing<String>> = None;
                                for (i, pwd) in self.generated.iter().enumerate() {
                                    // Revealed only for this row's paint/copy —
                                    // `pwd` itself stays sealed in `self.generated`.
                                    let pwd = pwd.reveal();
                                    ui.horizontal(|ui| {
                                        if ui
                                            .button("Copy")
                                            .on_hover_text(format!("Copy just this password; auto-clears from the clipboard in {}s.", self.autoclear_seconds))
                                            .clicked()
                                        {
                                            to_copy = Some(Zeroizing::new(pwd.as_str().to_owned()));
                                        }
                                        // SECURITY: was `ui.monospace(format!(...))` — a
                                        // plain `egui::Label`, then (in an earlier fix) a
                                        // single `painter.text(line, ...)` call built via
                                        // `layout_no_wrap`. Both build/cache a whole-string
                                        // `Galley` owning a full plaintext copy of this row
                                        // (`#N: password`) in egui's private font cache.
                                        // Confirmed present in a post-run core dump. Now
                                        // measured with `text_width` (per-glyph widths, no
                                        // Galley) and painted one character at a time with
                                        // `paint_chars` — see that function's doc comment in
                                        // `secure_text_edit.rs`. No residual whole-line
                                        // Galley exposure left here: the font cache only
                                        // ever retains single, UI-wide-shared glyphs.
                                        let line = Zeroizing::new(format!(
                                            "#{}: {}",
                                            i + 1,
                                            pwd.as_str()
                                        ));
                                        let font_id =
                                            egui::TextStyle::Monospace.resolve(ui.style());
                                        let text_color = ui.visuals().text_color();
                                        let row_height = ui.fonts(|f| f.row_height(&font_id));
                                        let size = egui::vec2(
                                            secure_text_edit::text_width(ui, &font_id, line.as_str()),
                                            row_height,
                                        );
                                        let (rect, label_resp) = ui.allocate_exact_size(
                                            size,
                                            egui::Sense::click(),
                                        );
                                        secure_text_edit::paint_chars(
                                            ui,
                                            ui.painter(),
                                            rect.left_top(),
                                            line.as_str(),
                                            &font_id,
                                            text_color,
                                        );
                                        // Right-click menu as an alternative to the "Copy"
                                        // button / Ctrl+C. Routed through the same
                                        // `to_copy` + `copy_to_clipboard_20s` path used by
                                        // the button above, so it gets the identical
                                        // always-auto-clear behaviour — this is just another
                                        // entry point into the existing secure copy, not a
                                        // separate unguarded clipboard write.
                                        label_resp.context_menu(|ui| {
                                            if ui.button("Copy").clicked() {
                                                to_copy = Some(Zeroizing::new(pwd.as_str().to_owned()));
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
                        // Revealed only for this join+copy operation —
                        // each entry stays sealed in `self.generated`
                        // otherwise. The joined result is a `Zeroizing`
                        // that's dropped (and wiped) at the end of this
                        // block; the clipboard write itself still goes
                        // through `copy_to_clipboard`'s own `LockedSecret`
                        // staging (`autoclear_expected`), same as every
                        // other copy in the app.
                        let text = Zeroizing::new(
                            self.generated
                                .iter()
                                .map(|p| p.reveal())
                                .collect::<Vec<_>>()
                                .iter()
                                .map(|p| p.as_str())
                                .collect::<Vec<_>>()
                                .join("\n"),
                        );
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
                        self.encrypt_shred_pwd.zeroize();
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
                // SECURITY: `self.enc_pwd` is stored sealed (`LockedSecret`
                // — ChaCha20-obfuscated-at-rest via `mem_cipher`) except
                // right here. It's revealed into a live `SecretString`
                // only for this render, edited in place by the widget,
                // and resealed immediately below (before anything else in
                // this frame runs) — so the plaintext exists in ordinary
                // memory only for the duration of this one `ui.add` call,
                // not for the whole autoclear window and not while any
                // other tab is being shown.
                let mut live_enc_pwd = self.enc_pwd.reveal();
                let resp = ui.add(secure_text_edit::SecurePasswordEdit::new("enc_pwd", &mut live_enc_pwd));
                if resp.changed() {
                    self.enc_pwd_last_edit = Instant::now();
                }
                // Best-effort: lock *this frame's* revealed copy into
                // physical RAM. Must run every frame, not just on edits —
                // `reveal()` allocates a fresh buffer each frame (the
                // previous frame's copy was already zeroized/resealed),
                // so gating this behind `resp.changed()` left it
                // unlocked on every frame the user wasn't actively
                // typing, which showed up as the status flickering
                // between "locked" and "not locked" instead of holding
                // steady.
                if self.linux_try_exclusion {
                    live_enc_pwd.mlock_best_effort();
                }
                if !live_enc_pwd.is_empty() {
                    let bits = estimate_passphrase_entropy(&live_enc_pwd);
                    let (rating, _) = rate_entropy(bits);
                    ui.small(format!(
                        "Estimated strength: {rating} (~{bits:.0} bits — pattern-aware heuristic, not a true entropy measurement)"
                    ));
                }
                ui.checkbox(
                    &mut self.enc_pwd_autoclear,
                    format!("Clear passphrase from memory after {}s of inactivity", self.pwd_autoclear_seconds),
                );

                ui.checkbox(&mut self.shred_after, "Verify, then securely shred the original after encryption");

                if mem_lock::SUPPORTED {
                    ui.checkbox(
                        &mut self.linux_try_exclusion,
                        "Best-effort: ask the OS to keep the passphrase out of swap (mlock/VirtualLock)",
                    );
                    ui.small("Best effort only — not a guarantee on every OS/kernel/filesystem configuration.");
                    // U-06 fix: live status instead of only a one-shot
                    // failure message shown at encrypt time — see
                    // `mem_lock::status_label` doc comment. Reflects this
                    // frame's brief revealed copy; the field is also
                    // ChaCha20-encrypted-at-rest the rest of the time,
                    // independent of mlock.
                    let (text, kind) = mem_lock::status_label_opt(
                        self.linux_try_exclusion,
                        (!live_enc_pwd.is_empty()).then(|| live_enc_pwd.is_locked()),
                    );
                    let p = self.palette();
                    let color = match kind {
                        "success" => p.success,
                        "danger" => p.danger,
                        "warning" => p.warning,
                        _ => p.text_secondary,
                    };
                    ui.horizontal(|ui| {
                        ui.small("Memory-lock status:");
                        ui.colored_label(color, text);
                    });
                    ui.small(
                        "Also kept encrypted at rest in RAM (ChaCha20) whenever this field \
                         isn't the one actively being edited.",
                    );
                }

                ui.add_space(6.0);
                let busy = self.busy_ops.contains("encrypt");
                let ready = self.enc_file.is_some()
                    && live_enc_pwd.chars().count() >= crypto::MIN_PASSPHRASE_LEN
                    && !busy;
                // Reseal right away: nothing below this point needs the
                // live plaintext again this frame — the Encrypt button
                // below only triggers `start_encrypt`, which reveals its
                // own short-lived copy from the now-sealed field.
                self.enc_pwd = LockedSecret::seal(live_enc_pwd);
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
                // SECURITY: `self.dec_pwd` is stored sealed (`LockedSecret`
                // — ChaCha20-obfuscated-at-rest) except right here — same
                // reveal-for-one-frame/reseal-immediately pattern as
                // `enc_pwd` on the Encrypt tab.
                let mut live_dec_pwd = self.dec_pwd.reveal();
                let resp = ui.add(secure_text_edit::SecurePasswordEdit::new("dec_pwd", &mut live_dec_pwd));
                if resp.changed() {
                    self.dec_pwd_last_edit = Instant::now();
                }
                // Must run every frame, not just on edits — see the
                // matching comment on the Encrypt tab's `enc_pwd` block
                // for why gating this behind `resp.changed()` caused the
                // status to flicker.
                if self.linux_try_exclusion {
                    live_dec_pwd.mlock_best_effort();
                }
                // U-06 fix: same live status as the Encrypt tab. No
                // separate checkbox here — `linux_try_exclusion` is one
                // shared setting (toggled on the Encrypt tab or the vault
                // settings panel), so this just reflects its effect on
                // *this* field.
                if mem_lock::SUPPORTED {
                    let (text, kind) = mem_lock::status_label_opt(
                        self.linux_try_exclusion,
                        (!live_dec_pwd.is_empty()).then(|| live_dec_pwd.is_locked()),
                    );
                    let p = self.palette();
                    let color = match kind {
                        "success" => p.success,
                        "danger" => p.danger,
                        "warning" => p.warning,
                        _ => p.text_secondary,
                    };
                    ui.horizontal(|ui| {
                        ui.small("Memory-lock status:");
                        ui.colored_label(color, text);
                    });
                    ui.small(
                        "Also kept encrypted at rest in RAM (ChaCha20) whenever this field \
                         isn't the one actively being edited.",
                    );
                }
                ui.checkbox(
                    &mut self.dec_pwd_autoclear,
                    format!("Clear passphrase from memory after {}s of inactivity", self.pwd_autoclear_seconds),
                );

                ui.add_space(6.0);
                let busy = self.busy_ops.contains("decrypt");
                let ready = self.dec_file.is_some() && !live_dec_pwd.is_empty() && !busy;
                // Reseal right away: nothing below needs the live
                // plaintext again this frame.
                self.dec_pwd = LockedSecret::seal(live_dec_pwd);
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
            // `LockedSecret` deliberately has no `PartialEq` — two seals
            // of the identical plaintext still differ (different random
            // nonce each time), so a ciphertext compare would be
            // meaningless. Revealing both to compare means this dirty
            // check briefly holds two plaintext copies of the file once
            // per frame while the editor's open; accepted the same way
            // the search box below already re-derives plaintext every
            // frame it's non-empty — both are short-lived (dropped at
            // end of frame) rather than a persistent unsealed copy.
            let dirty = self.editor_content.reveal().as_str()
                != self.editor_original_content.reveal().as_str();
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
            // Revealed once per frame while searching — same transient,
            // resealed-after pattern as everywhere else `editor_content`'s
            // plaintext is needed now that it's a `LockedSecret`.
            let content_plain = self.editor_content.reveal();
            // SECURITY: this recomputes on every render frame the search
            // box is non-empty (not just when "Copy" is clicked), so
            // every matching line — each one a decrypted password —
            // previously got copied into a plain, never-zeroized
            // `String` many times per second while this view was simply
            // open. `Zeroizing<String>` wipes each of those copies (the
            // per-line lowercase temporary included) the moment it's
            // dropped at the end of the frame, instead of leaving it
            // sitting in freed-but-unwiped heap memory.
            let matches: Vec<(usize, Zeroizing<String>)> = content_plain
                .lines()
                .enumerate()
                .filter(|(_, l)| Zeroizing::new(l.to_lowercase()).contains(&needle))
                .map(|(i, l)| (i, Zeroizing::new(l.to_string())))
                .collect();
            ui.small(format!(
                "{} matching line(s) — clear search to edit the full file. Copied lines clear from the clipboard after {}s.",
                matches.len(),
                self.autoclear_seconds
            ));
            let mut to_copy: Option<Zeroizing<String>> = None;
            let min_editor_height = ui.ctx().screen_rect().height() * 0.75;
            egui::ScrollArea::vertical()
                .id_source("editor_search_scroll")
                .min_scrolled_height(min_editor_height)
                .max_height(f32::INFINITY)
                .show(ui, |ui| {
                    if matches.is_empty() {
                        ui.small("No matches.");
                    } else {
                        for (line_no, line) in &matches {
                                ui.horizontal(|ui| {
                                    if ui.button("Copy").on_hover_text(format!("Copy just the password (the first word on the line); auto-clears from the clipboard in {}s.", self.autoclear_seconds)).clicked() {
                                        to_copy = Some(password_part(line.as_str()));
                                    }
                                    // SECURITY: was `egui::Label::new(RichText::new(...))`.
                                    // `Label` goes through egui's normal
                                    // WidgetText/Galley pipeline, which builds
                                    // and caches a `Galley` owning a full
                                    // plaintext `String` of the whole
                                    // formatted line — and this line *is* a
                                    // decrypted password (plus whatever
                                    // comment follows it), the most sensitive
                                    // text this view ever shows. Confirmed via
                                    // a post-search core dump. Fixed the same
                                    // way `SecureNotesEdit`'s row painting was
                                    // (see `secure_text_edit::paint_chars`):
                                    // measure with per-glyph widths
                                    // (`text_width`, no Galley involved) and
                                    // paint one character at a time, so
                                    // whatever egui's font cache retains is
                                    // only ever single, UI-wide-shared glyphs
                                    // rather than a contiguous secret
                                    // substring.
                                    let font_id = egui::FontId::monospace(13.0);
                                    let line_text =
                                        Zeroizing::new(format!("{:>4}: {}", line_no + 1, line.as_str()));
                                    let text_color = ui.visuals().text_color();
                                    let size = egui::vec2(
                                        secure_text_edit::text_width(ui, &font_id, line_text.as_str()),
                                        ui.fonts(|f| f.row_height(&font_id)),
                                    );
                                    let (rect, line_resp) =
                                        ui.allocate_exact_size(size, egui::Sense::click());
                                    secure_text_edit::paint_chars(
                                        ui,
                                        ui.painter(),
                                        rect.left_top(),
                                        line_text.as_str(),
                                        &font_id,
                                        text_color,
                                    );
                                    // Right-click menu removed: the "Copy"
                                    // button above already covers copying the
                                    // password, and `line_resp` (from
                                    // `allocate_exact_size`) is unused now
                                    // that nothing hooks a context menu to it.
                                    let _ = line_resp;
                                });
                        }
                    }
                });
            if let Some(line) = to_copy {
                self.copy_to_clipboard_20s(&line);
            }
        } else {
            // Editor should take up at least 3/4 of the window's height so
            // it's the dominant element on screen rather than a cramped
            // fixed-size box.
            let min_editor_height = ui.ctx().screen_rect().height() * 0.75;
            // SECURITY: revealed into `content_plain` for exactly this
            // frame's widget call (edit + paint), then resealed back into
            // `self.editor_content` at the very end of this branch — same
            // reveal-per-frame/reseal-immediately pattern used for
            // `vault_edit_notes`. Keeps this large decrypted buffer from
            // sitting as long-lived plaintext for the whole time the
            // editor's open.
            let mut content_plain = self.editor_content.reveal();
            egui::ScrollArea::vertical()
                .id_source("editor_main_scroll")
                .min_scrolled_height(min_editor_height)
                .max_height(f32::INFINITY)
                .show(ui, |ui| {
                    let available_width = ui.available_width();
                    ui.add(
                        secure_text_edit::SecureNotesEdit::new(
                            "editor_main_content",
                            &mut content_plain,
                        )
                        .desired_width(available_width)
                        .desired_rows(10),
                    );
                });
            // SECURITY fix: the comment this replaced claimed Ctrl+C
            // "already works via egui's own TextEdit handling" — that
            // was wrong. `SecureNotesEdit` (see its module docs)
            // deliberately intercepts Ctrl+C itself and never hands
            // anything to the OS clipboard directly; it only flags the
            // request via `take_copy_request` for the caller to act on.
            //
            // SECURITY (follow-up): this used to fall back to copying
            // the *entire* decrypted file when Ctrl+C was pressed with
            // no selection, and there was a "Copy all" context-menu item
            // doing the same thing. Both are removed: this file's whole
            // point is a list of passwords, and "grab everything at
            // once" is exactly the operation that put a full plaintext
            // copy of the decrypted content on the clipboard (and
            // through `copy_to_clipboard_20s`'s own buffer) in one shot,
            // as opposed to `Copy password`/`Copy line` in the search
            // view above, which only ever copy one already-selected
            // line. Ctrl+C with no selection is now simply a no-op; an
            // explicit selection is required to copy anything from this
            // view.
            if secure_text_edit::take_copy_request(ui, "editor_main_content") {
                if let Some(range) = secure_text_edit::selected_range(ui, "editor_main_content") {
                    let to_copy = secure_text_edit::extract_range(&content_plain, range);
                    self.copy_to_clipboard_20s(&to_copy);
                }
            }
            // Reseal immediately: `content_plain`'s buffer is consumed
            // here (not dropped-then-recreated), so this frame's edits
            // never exist as an unsealed `SecretString` any longer than
            // the widget call above needed them to.
            self.editor_content = LockedSecret::seal(content_plain);
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
///
/// Returns `Zeroizing<String>`, not a plain `String`: this pulls a real
/// password out of decrypted editor content, and callers hand it straight
/// to `copy_to_clipboard_20s`. A plain `String` here would leave that
/// password sitting in unscrubbed freed heap memory indefinitely once
/// dropped — see `secure_text_edit::extract_range`'s doc comment for the
/// same issue found (and fixed) on the Notes copy path.
fn password_part(line: &str) -> Zeroizing<String> {
    Zeroizing::new(line.split_whitespace().next().unwrap_or("").to_string())
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
