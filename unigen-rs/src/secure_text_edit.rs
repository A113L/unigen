//! `SecurePasswordEdit`: a minimal single-line password input widget
//! that never leaves plaintext behind in `egui`'s own persisted state.
//!
//! ## Why not `egui::TextEdit::singleline(..).password(true)`?
//!
//! `.password(true)` only masks the *rendered* glyphs. It does nothing
//! about `egui::TextEdit`'s internal `TextEditState`, which is stored
//! between frames in `egui::Memory` and carries an undo/redo history:
//!
//! ```text
//! pub(crate) undoer: Arc<Mutex<Undoer<(CCursorRange, String)>>>
//! ```
//!
//! Every keystroke pushes a fresh snapshot of the *entire current
//! text* onto that stack, as a plain `String`. That field is
//! `pub(crate)` inside `egui` — application code has no way to reach
//! in and zeroize it before it's dropped, and dropping a `String`
//! doesn't zero its bytes (same "freed but not overwritten" problem
//! `secret.rs`'s module docs describe for the global allocator).
//! Regardless of how well-protected the *visible* buffer is
//! (`SecretString`, `Zeroize`, etc.), every password field built on
//! `TextEdit` was accumulating a growing trail of unzeroized
//! plaintext copies in this undo stack for as long as the field
//! existed. This was confirmed in practice: a manually-typed test
//! password (many keystrokes → many undo snapshots) turned up
//! repeatedly in a post-clear core dump, while a pasted-then-cleared
//! password (a single bulk insert, minimal undo history) did not.
//!
//! ## What this widget does instead
//!
//! It re-implements just enough of a single-line text field to be
//! usable for passwords — click-to-focus, type/paste-to-insert,
//! backspace/delete, left/right/home/end cursor movement — with **no
//! history of any kind**. The only thing persisted between frames in
//! `egui::Memory` is the cursor position, a `usize` — never text. All
//! mutation goes straight through the caller's `SecretString`, so
//! `SecretBytes`'s zeroize-on-relocate/delete/drop guarantees (see
//! `secret.rs`) are the only place backing memory ever moves.
//!
//! Text is rendered as one bullet (`●`) per character — the real
//! contents are never drawn, copied, or logged anywhere in this
//! widget. Selection and copy/cut are intentionally not implemented:
//! a password field has no legitimate reason to put its contents on
//! the system clipboard via select-all-copy, and leaving that out
//! closes off that path entirely rather than relying on discipline.
//!
//! ## Residual risk this does *not* close
//!
//! `egui::Event::Text` and `egui::Event::Paste` hand typed/pasted
//! characters to widgets as plain `String`s owned by egui's own
//! per-frame input queue — that's egui's input pipeline, not
//! anything this widget or `secret.rs` controls. Those `String`s are
//! transient (dropped at the end of the frame they arrive in, same
//! as a keyboard driver's own buffer) rather than accumulating for
//! the field's entire lifetime the way the `TextEdit` undo stack did,
//! so the exposure window is one frame wide instead of "as long as
//! the field exists" — a large reduction, not a complete fix. This is
//! the same class of unavoidable gap already documented in
//! `secret.rs` for `TextBuffer::take()`'s interaction with the system
//! clipboard.

use crate::secret::SecretString;
use egui::{Event, Id, Key, Response, Sense, Ui, Vec2, Widget};

/// Persisted between frames for a given widget `Id`. Deliberately the
/// *only* thing this widget keeps in `egui::Memory` — a character
/// index, never text.
#[derive(Clone, Copy, Default)]
struct CursorState {
    char_index: usize,
}

/// A password-style single-line input backed directly by a
/// `SecretString`. See the module docs for why this exists instead of
/// `egui::TextEdit::password(true)`.
pub struct SecurePasswordEdit<'a> {
    text: &'a mut SecretString,
    id: Id,
    desired_width: Option<f32>,
    hint_text: Option<String>,
    masked: bool,
}

impl<'a> SecurePasswordEdit<'a> {
    /// `id_source` must be stable and unique per field (e.g. a string
    /// literal like `"vault_master_pwd"`) — it's how cursor position
    /// is looked up between frames, same role as `TextEdit::id_source`.
    pub fn new(id_source: impl std::hash::Hash, text: &'a mut SecretString) -> Self {
        Self {
            text,
            id: Id::new(id_source),
            desired_width: None,
            hint_text: None,
            masked: true,
        }
    }

    #[allow(dead_code)]
    pub fn desired_width(mut self, width: f32) -> Self {
        self.desired_width = Some(width);
        self
    }

    /// Mirrors `TextEdit::password(bool)`: `true` (default) shows
    /// `●` per character; `false` shows the real characters, for a
    /// "reveal password" toggle. Note this only ever affects what's
    /// *painted* — the widget never keeps an unmasked copy anywhere,
    /// masked or not, so toggling this carries no extra memory risk.
    pub fn masked(mut self, masked: bool) -> Self {
        self.masked = masked;
        self
    }

    /// Placeholder shown (in the normal text color, not bulleted)
    /// when the field is empty — purely cosmetic, never stored.
    #[allow(dead_code)]
    pub fn hint_text(mut self, hint: impl Into<String>) -> Self {
        self.hint_text = Some(hint.into());
        self
    }
}

impl<'a> Widget for SecurePasswordEdit<'a> {
    fn ui(self, ui: &mut Ui) -> Response {
        let SecurePasswordEdit {
            text,
            id,
            desired_width,
            hint_text,
            masked,
        } = self;

        let font_id = egui::TextStyle::Body.resolve(ui.style());
        let row_height = ui.fonts(|f| f.row_height(&font_id));
        let width = desired_width.unwrap_or_else(|| ui.spacing().text_edit_width);
        let desired_size = Vec2::new(width, row_height + 2.0 * ui.spacing().button_padding.y);

        let (rect, _) = ui.allocate_exact_size(desired_size, Sense::hover());
        let mut response = ui.interact(rect, id, Sense::click());
        response = response.on_hover_cursor(egui::CursorIcon::Text);

        if response.clicked() {
            ui.memory_mut(|m| m.request_focus(id));
        }
        let has_focus = ui.memory(|m| m.has_focus(id));

        // Only a `usize` cursor position ever round-trips through
        // egui::Memory here — see module docs.
        let mut cursor: CursorState = ui
            .memory_mut(|m| m.data.get_temp::<CursorState>(id))
            .unwrap_or_default();
        cursor.char_index = cursor.char_index.min(text.len_chars());

        if has_focus {
            let events = ui.input(|i| i.events.clone());
            for event in &events {
                match event {
                    Event::Text(t) | Event::Paste(t) => {
                        if !t.is_empty() {
                            let byte_idx = text.byte_index_from_char_index(cursor.char_index);
                            text.insert_str(byte_idx, t);
                            cursor.char_index += t.chars().count();
                            response.mark_changed();
                        }
                    }
                    Event::Key {
                        key: Key::Backspace,
                        pressed: true,
                        ..
                    } => {
                        if cursor.char_index > 0 {
                            let end = text.byte_index_from_char_index(cursor.char_index);
                            let start = text.byte_index_from_char_index(cursor.char_index - 1);
                            text.delete_byte_range(start..end);
                            cursor.char_index -= 1;
                            response.mark_changed();
                        }
                    }
                    Event::Key {
                        key: Key::Delete,
                        pressed: true,
                        ..
                    } => {
                        if cursor.char_index < text.len_chars() {
                            let start = text.byte_index_from_char_index(cursor.char_index);
                            let end = text.byte_index_from_char_index(cursor.char_index + 1);
                            text.delete_byte_range(start..end);
                            response.mark_changed();
                        }
                    }
                    Event::Key {
                        key: Key::ArrowLeft,
                        pressed: true,
                        ..
                    } => {
                        cursor.char_index = cursor.char_index.saturating_sub(1);
                    }
                    Event::Key {
                        key: Key::ArrowRight,
                        pressed: true,
                        ..
                    } => {
                        cursor.char_index = (cursor.char_index + 1).min(text.len_chars());
                    }
                    Event::Key {
                        key: Key::Home,
                        pressed: true,
                        ..
                    } => {
                        cursor.char_index = 0;
                    }
                    Event::Key {
                        key: Key::End,
                        pressed: true,
                        ..
                    } => {
                        cursor.char_index = text.len_chars();
                    }
                    _ => {}
                }
            }
        }

        ui.memory_mut(|m| m.data.insert_temp(id, cursor));

        // --- painting: only ever draws '●' per character, never the
        // real contents ---
        let visuals = ui.style().interact_selectable(&response, has_focus);
        ui.painter()
            .rect(rect, visuals.rounding, ui.visuals().extreme_bg_color, visuals.bg_stroke);

        let char_count = text.len_chars();
        let (display, text_color): (std::borrow::Cow<str>, _) = if char_count == 0 {
            (
                hint_text.unwrap_or_default().into(),
                ui.visuals().weak_text_color(),
            )
        } else if masked {
            ("\u{2022}".repeat(char_count).into(), ui.visuals().text_color())
        } else {
            // Reveal mode: paint the real characters. Still nothing
            // beyond this one paint call ever sees them — no copy is
            // made, nothing is stored.
            (text.as_str().into(), ui.visuals().text_color())
        };

        let text_pos = rect.left_center() + Vec2::new(ui.spacing().button_padding.x, 0.0);
        ui.painter()
            .text(text_pos, egui::Align2::LEFT_CENTER, display.as_ref(), font_id.clone(), text_color);

        if has_focus {
            // Approximate advance for cursor placement. Uses the
            // bullet glyph's width even in reveal mode for simplicity
            // — cursor position is a visual approximation either way,
            // not a security-relevant value.
            let bullet_advance = ui.fonts(|f| f.glyph_width(&font_id, '\u{2022}'));
            let cursor_x = text_pos.x + bullet_advance * cursor.char_index as f32;
            let top = rect.top() + 2.0;
            let bottom = rect.bottom() - 2.0;
            ui.painter().line_segment(
                [egui::pos2(cursor_x, top), egui::pos2(cursor_x, bottom)],
                egui::Stroke::new(1.0, ui.visuals().text_color()),
            );
        }

        response
    }
}

/// Convenience free function, mirroring `ui.text_edit_singleline`'s
/// ergonomics: `secure_text_edit::secure_password_edit(ui, "my_id", &mut self.some_pwd)`.
#[allow(dead_code)]
pub fn secure_password_edit(
    ui: &mut Ui,
    id_source: impl std::hash::Hash,
    text: &mut SecretString,
) -> Response {
    ui.add(SecurePasswordEdit::new(id_source, text))
}
