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
use std::ops::Range;

/// Persisted between frames for a given widget `Id`. Deliberately the
/// *only* thing this widget keeps in `egui::Memory` — a character
/// index (and, for `SecureNotesEdit`, a second character index marking
/// the other end of a selection) — never text, never an undo history.
#[derive(Clone, Copy, Default)]
struct CursorState {
    char_index: usize,
    /// The non-moving end of an in-progress selection, if any.
    /// `SecurePasswordEdit` never sets this (no selection support
    /// there — see its module docs on why copy/select was left out of
    /// that widget on purpose). `SecureNotesEdit` uses it for
    /// shift+arrow, click-drag, and select-all.
    anchor: Option<usize>,
    /// Vertical scroll offset in pixels, `SecureNotesEdit` only. Just
    /// a float — never text — same "no content in Memory" rule as
    /// everything else this module persists.
    scroll_y: f32,
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

        // Without this, egui's own focus-navigation intercepts arrow
        // keys (and Tab) to move focus between widgets *before* our
        // `match event` loop below ever sees them — the field would
        // never receive ArrowLeft/Right itself. Must be (re-)declared
        // every frame the widget has focus, same as `TextEdit` does
        // internally.
        if has_focus {
            ui.memory_mut(|m| {
                m.set_focus_lock_filter(
                    id,
                    egui::EventFilter {
                        horizontal_arrows: true,
                        vertical_arrows: false,
                        tab: false,
                        escape: false,
                    },
                )
            });
        }

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

/// A multi-line text input backed directly by a `SecretString`, for
/// fields like vault "Notes" that are shown in the clear (unlike
/// `SecurePasswordEdit`) but still deserve the same protection this
/// module gives against `egui::TextEdit`'s internal undo stack — see
/// the module docs above. Recovery codes, backup phrases, etc. typed
/// into a plain `egui::TextEdit::multiline` accumulate the same trail
/// of unzeroized plaintext snapshots that motivated `SecurePasswordEdit`
/// in the first place; this widget closes that off the same way, by
/// never handing the text to `egui`'s own buffer/undoer at all.
///
/// Only scalar UI state is persisted in `egui::Memory` between frames
/// (cursor/selection, scroll position, and the resize height) — never text
/// and never an undo history. Visual wrapping is presentation-only.
pub struct SecureNotesEdit<'a> {
    text: &'a mut SecretString,
    id: Id,
    desired_width: Option<f32>,
    desired_rows: usize,
    hint_text: Option<String>,
}

impl<'a> SecureNotesEdit<'a> {
    /// `id_source` must be stable and unique per field, same role as
    /// `SecurePasswordEdit::new`'s.
    pub fn new(id_source: impl std::hash::Hash, text: &'a mut SecretString) -> Self {
        Self {
            text,
            id: Id::new(id_source),
            desired_width: None,
            desired_rows: 6,
            hint_text: None,
        }
    }

    #[allow(dead_code)]
    pub fn desired_width(mut self, width: f32) -> Self {
        self.desired_width = Some(width);
        self
    }

    /// Mirrors `TextEdit::desired_rows` — how many lines tall the box
    /// is painted, independent of how much text is actually in it.
    pub fn desired_rows(mut self, rows: usize) -> Self {
        self.desired_rows = rows.max(1);
        self
    }

    /// Placeholder shown (in the normal text color) when the field is
    /// empty — purely cosmetic, never stored.
    #[allow(dead_code)]
    pub fn hint_text(mut self, hint: impl Into<String>) -> Self {
        self.hint_text = Some(hint.into());
        self
    }
}

impl<'a> Widget for SecureNotesEdit<'a> {
    fn ui(self, ui: &mut Ui) -> Response {
        let SecureNotesEdit { text, id, desired_width, desired_rows, hint_text } = self;
        let font_id = egui::TextStyle::Body.resolve(ui.style());
        let row_height = ui.fonts(|f| f.row_height(&font_id));
        let default_width = desired_width.unwrap_or_else(|| ui.spacing().text_edit_width);
        let padding = ui.spacing().button_padding;
        let min_height = row_height * 3.0 + 2.0 * padding.y;
        let default_height = row_height * desired_rows.max(1) as f32 + 2.0 * padding.y;
        let max_height = row_height * 40.0 + 2.0 * padding.y;
        let height_id = id.with("height");
        let mut height = ui.memory(|m| m.data.get_temp::<f32>(height_id))
            .unwrap_or(default_height).clamp(min_height, max_height);

        // Horizontal resize mirrors the vertical one: the width is
        // remembered across frames the same way the height is, and is
        // bounded below by a usable minimum and above by whatever room the
        // surrounding layout has available right now (so dragging the grip
        // can't push content outside the panel/window it's laid out in).
        let min_width = (row_height * 10.0).max(120.0);
        let avail_width = ui.available_width().max(min_width);
        let max_width = avail_width.max(default_width);
        let width_id = id.with("width");
        let mut width = ui.memory(|m| m.data.get_temp::<f32>(width_id))
            .unwrap_or(default_width).clamp(min_width, max_width);

        let (rect, _) = ui.allocate_exact_size(Vec2::new(width, height), Sense::hover());

        // Register the main field interaction first. The resize handle and
        // scrollbar are registered afterwards so they take precedence over
        // the full-field drag/click interaction when their hit rectangles
        // overlap.
        let field_response = ui.interact(rect, id, Sense::click_and_drag());

        let resize_id = id.with("resize");
        let resize_size = 18.0;
        let resize_rect = egui::Rect::from_min_max(
            egui::pos2((rect.max.x - resize_size).max(rect.min.x), (rect.max.y - resize_size).max(rect.min.y)),
            rect.max,
        );
        let resize_response = ui.interact(resize_rect, resize_id, Sense::drag())
            .on_hover_cursor(egui::CursorIcon::ResizeNwSe);
        if resize_response.dragged() {
            let delta = ui.input(|i| i.pointer.delta());
            if delta.y != 0.0 {
                height = (height + delta.y).clamp(min_height, max_height);
                ui.memory_mut(|m| m.data.insert_temp(height_id, height));
            }
            if delta.x != 0.0 {
                width = (width + delta.x).clamp(min_width, max_width);
                ui.memory_mut(|m| m.data.insert_temp(width_id, width));
            }
            ui.ctx().request_repaint();
        }
        ui.memory_mut(|m| m.data.insert_temp(height_id, height));
        ui.memory_mut(|m| m.data.insert_temp(width_id, width));

        let mut response = field_response;
        response = response.on_hover_cursor(egui::CursorIcon::Text);
        let mut cursor: CursorState = ui.memory_mut(|m| m.data.get_temp::<CursorState>(id)).unwrap_or_default();
        cursor.char_index = cursor.char_index.min(text.len_chars());
        cursor.anchor = cursor.anchor.map(|a| a.min(text.len_chars()));

        let scrollbar_w = 8.0;
        let content_rect = egui::Rect::from_min_max(rect.min, egui::pos2(rect.max.x - scrollbar_w - 2.0, rect.max.y));
        let text_rect = egui::Rect::from_min_max(
            content_rect.min + Vec2::new(padding.x, padding.y),
            content_rect.max - Vec2::new(padding.x, padding.y),
        );
        let top_left = text_rect.left_top();
        let wrap_width = text_rect.width().max(1.0);
        let visual_rows = build_visual_rows(ui, text.as_str(), &font_id, wrap_width);
        let content_height = row_height * visual_rows.len().max(1) as f32;
        let visible_height = text_rect.height().max(0.0);
        let max_scroll = (content_height - visible_height).max(0.0);
        cursor.scroll_y = cursor.scroll_y.clamp(0.0, max_scroll);

        // Build an actual interactive scrollbar. Previously the thumb was
        // only painted, so the visible "anchor" could not be dragged.
        let scrollbar_id = id.with("scrollbar");
        // Keep the scrollbar clear of the resize grip. Without this small
        // exclusion the two hit targets overlap in the bottom-right corner
        // and the scrollbar wins the pointer grab, making the resize grip
        // appear visible but effectively unusable.
        let scrollbar_bottom = (rect.max.y - resize_size - 1.0).max(rect.min.y + 2.0);
        let scrollbar_track = egui::Rect::from_min_max(
            egui::pos2(rect.max.x - scrollbar_w, rect.min.y + 2.0),
            egui::pos2(rect.max.x, scrollbar_bottom),
        );
        let track_h = scrollbar_track.height().max(1.0);
        let thumb_h = if content_height > 0.0 {
            (track_h * (visible_height / content_height)).clamp(18.0, track_h)
        } else {
            track_h
        };
        let thumb_travel = (track_h - thumb_h).max(0.0);
        let scroll_frac = if max_scroll > 0.0 { cursor.scroll_y / max_scroll } else { 0.0 };
        let thumb_y = scrollbar_track.min.y + thumb_travel * scroll_frac;
        let scrollbar_thumb = egui::Rect::from_min_max(
            egui::pos2(scrollbar_track.min.x, thumb_y),
            egui::pos2(scrollbar_track.max.x, thumb_y + thumb_h),
        );

        // Track click is handled before the thumb so the thumb gets the
        // higher-priority hit test when both overlap.
        let scrollbar_track_response = ui.interact(scrollbar_track, scrollbar_id.with("track"), Sense::click());
        let scrollbar_thumb_response = ui.interact(scrollbar_thumb, scrollbar_id.with("thumb"), Sense::drag())
            .on_hover_cursor(egui::CursorIcon::ResizeVertical);

        if scrollbar_thumb_response.dragged() && thumb_travel > 0.0 {
            let dy = ui.input(|i| i.pointer.delta().y);
            if dy != 0.0 {
                cursor.scroll_y = (cursor.scroll_y + dy * max_scroll / thumb_travel).clamp(0.0, max_scroll);
            }
            ui.ctx().request_repaint();
        } else if scrollbar_track_response.clicked() && !scrollbar_thumb_response.hovered() && max_scroll > 0.0 {
            if let Some(pos) = scrollbar_track_response.interact_pointer_pos() {
                let target = ((pos.y - scrollbar_track.min.y - thumb_h * 0.5) / thumb_travel.max(1.0)).clamp(0.0, 1.0);
                cursor.scroll_y = target * max_scroll;
            }
        }

        let pos_to_idx = |pos: egui::Pos2, scroll_y: f32| char_index_from_visual_pos(
            ui, text.as_str(), &font_id, &visual_rows, top_left, row_height,
            pos + Vec2::new(0.0, scroll_y),
        );
        let resizing = resize_response.drag_started() || resize_response.dragged();
        let scrollbar_dragging = scrollbar_thumb_response.drag_started() || scrollbar_thumb_response.dragged();
        let over_scrollbar = scrollbar_track_response.hovered() || scrollbar_thumb_response.hovered();

        if !resizing && !scrollbar_dragging && !over_scrollbar {
            if response.drag_started() {
                if let Some(pos) = response.interact_pointer_pos() { let idx = pos_to_idx(pos, cursor.scroll_y); cursor.char_index = idx; cursor.anchor = Some(idx); }
                ui.memory_mut(|m| m.request_focus(id));
            } else if response.dragged() {
                if let Some(pos) = response.interact_pointer_pos() { cursor.char_index = pos_to_idx(pos, cursor.scroll_y); }
            } else if response.clicked() {
                if let Some(pos) = response.interact_pointer_pos() {
                    let idx = pos_to_idx(pos, cursor.scroll_y);
                    if ui.input(|i| i.modifiers.shift) { if cursor.anchor.is_none() { cursor.anchor = Some(cursor.char_index); } } else { cursor.anchor = None; }
                    cursor.char_index = idx;
                }
                ui.memory_mut(|m| m.request_focus(id));
            }
        }

        if (response.hovered() || scrollbar_track_response.hovered()) && !resizing && !scrollbar_dragging {
            let scroll_delta = ui.input(|i| i.smooth_scroll_delta.y);
            if scroll_delta != 0.0 {
                cursor.scroll_y = (cursor.scroll_y - scroll_delta).clamp(0.0, max_scroll);
            }
        }
        let has_focus = ui.memory(|m| m.has_focus(id));
        if has_focus && !resizing && !scrollbar_dragging {
            ui.memory_mut(|m| m.set_focus_lock_filter(id, egui::EventFilter { horizontal_arrows: true, vertical_arrows: true, tab: false, escape: false }));
        }

        if has_focus && !resizing {
            let events = ui.input(|i| i.events.clone());
            for event in &events {
                match event {
                    Event::Text(t) | Event::Paste(t) => {
                        if !t.is_empty() { delete_selection(text, &mut cursor); let byte_idx = text.byte_index_from_char_index(cursor.char_index); text.insert_str(byte_idx, t); cursor.char_index += t.chars().count(); response.mark_changed(); }
                    }
                    Event::Key { key: Key::Enter, pressed: true, modifiers, .. } if !modifiers.shift => {
                        delete_selection(text, &mut cursor); let byte_idx = text.byte_index_from_char_index(cursor.char_index); text.insert_str(byte_idx, "\n"); cursor.char_index += 1; response.mark_changed();
                    }
                    Event::Key { key: Key::Backspace, pressed: true, .. } => {
                        if delete_selection(text, &mut cursor) { response.mark_changed(); } else if cursor.char_index > 0 { let end = text.byte_index_from_char_index(cursor.char_index); let start = text.byte_index_from_char_index(cursor.char_index - 1); text.delete_byte_range(start..end); cursor.char_index -= 1; response.mark_changed(); }
                    }
                    Event::Key { key: Key::Delete, pressed: true, .. } => {
                        if delete_selection(text, &mut cursor) { response.mark_changed(); } else if cursor.char_index < text.len_chars() { let start = text.byte_index_from_char_index(cursor.char_index); let end = text.byte_index_from_char_index(cursor.char_index + 1); text.delete_byte_range(start..end); response.mark_changed(); }
                    }
                    Event::Key { key: Key::A, pressed: true, modifiers, .. } if modifiers.command => { cursor.anchor = Some(0); cursor.char_index = text.len_chars(); }
                    Event::Key { key: Key::C, pressed: true, modifiers, .. } if modifiers.command => { ui.memory_mut(|m| m.data.insert_temp(id.with("copy_req"), true)); }
                    Event::Key { key: Key::ArrowLeft, pressed: true, modifiers, .. } => { extend_or_collapse(&mut cursor, modifiers.shift); cursor.char_index = cursor.char_index.saturating_sub(1); }
                    Event::Key { key: Key::ArrowRight, pressed: true, modifiers, .. } => { extend_or_collapse(&mut cursor, modifiers.shift); cursor.char_index = (cursor.char_index + 1).min(text.len_chars()); }
                    Event::Key { key: Key::ArrowUp, pressed: true, modifiers, .. } => { extend_or_collapse(&mut cursor, modifiers.shift); cursor.char_index = move_cursor_visual(&visual_rows, cursor.char_index, -1); }
                    Event::Key { key: Key::ArrowDown, pressed: true, modifiers, .. } => { extend_or_collapse(&mut cursor, modifiers.shift); cursor.char_index = move_cursor_visual(&visual_rows, cursor.char_index, 1); }
                    Event::Key { key: Key::Home, pressed: true, modifiers, .. } => { extend_or_collapse(&mut cursor, modifiers.shift); cursor.char_index = line_start(text.as_str(), cursor.char_index); }
                    Event::Key { key: Key::End, pressed: true, modifiers, .. } => { extend_or_collapse(&mut cursor, modifiers.shift); cursor.char_index = line_end(text.as_str(), cursor.char_index); }
                    _ => {}
                }
            }
        }

        let visual_rows = build_visual_rows(ui, text.as_str(), &font_id, wrap_width);
        let content_height = row_height * visual_rows.len().max(1) as f32;
        let max_scroll = (content_height - visible_height).max(0.0);
        cursor.scroll_y = cursor.scroll_y.clamp(0.0, max_scroll);
        let cursor_row = visual_row_for_cursor(&visual_rows, cursor.char_index);
        let cursor_top = row_height * cursor_row as f32;
        let cursor_bottom = cursor_top + row_height;
        if cursor_top < cursor.scroll_y { cursor.scroll_y = cursor_top; }
        else if cursor_bottom > cursor.scroll_y + visible_height { cursor.scroll_y = cursor_bottom - visible_height; }
        cursor.scroll_y = cursor.scroll_y.clamp(0.0, max_scroll);
        ui.memory_mut(|m| m.data.insert_temp(id, cursor));

        let visuals = ui.style().interact_selectable(&response, has_focus);
        ui.painter().rect(rect, visuals.rounding, ui.visuals().extreme_bg_color, visuals.bg_stroke);
        let painter = ui.painter().with_clip_rect(text_rect);
        let draw_top = top_left - Vec2::new(0.0, cursor.scroll_y);
        let content = text.as_str();

        if let Some(anchor) = cursor.anchor {
            if anchor != cursor.char_index {
                let (sel_start, sel_end) = if anchor < cursor.char_index { (anchor, cursor.char_index) } else { (cursor.char_index, anchor) };
                for (row_i, row) in visual_rows.iter().enumerate() {
                    if sel_end < row.start || sel_start > row.end { continue; }
                    let row_len = row.end - row.start;
                    let local_start = sel_start.saturating_sub(row.start).min(row_len);
                    let local_end = sel_end.saturating_sub(row.start).min(row_len);
                    let row_text = slice_chars(content, row.start, row.end);
                    let x0 = draw_top.x + char_advance(ui, &font_id, row_text, local_start);
                    let mut x1 = draw_top.x + char_advance(ui, &font_id, row_text, local_end);
                    if sel_end > row.end { x1 += ui.fonts(|f| f.glyph_width(&font_id, ' ')); }
                    x1 = x1.max(x0 + 2.0);
                    let y0 = draw_top.y + row_height * row_i as f32;
                    painter.rect_filled(egui::Rect::from_min_max(egui::pos2(x0, y0), egui::pos2(x1, y0 + row_height)), 0.0, ui.visuals().selection.bg_fill);
                }
            }
        }
        if content.is_empty() {
            if let Some(hint) = &hint_text { painter.text(draw_top, egui::Align2::LEFT_TOP, hint, font_id.clone(), ui.visuals().weak_text_color()); }
        } else {
            // SECURITY: painted one character at a time via
            // `paint_chars` rather than one `painter.text(row_text, ...)`
            // call per row — see that function's doc comment for why:
            // the whole-row version leaves the actual secret text
            // sitting as a plain `String` inside egui's private Galley
            // cache, outside every `SecretString`/`LockedSecret`
            // guarantee this app otherwise relies on.
            for (i, row) in visual_rows.iter().enumerate() {
                let row_text = slice_chars(content, row.start, row.end);
                paint_chars(
                    ui,
                    &painter,
                    draw_top + Vec2::new(0.0, row_height * i as f32),
                    row_text,
                    &font_id,
                    ui.visuals().text_color(),
                );
            }
        }
        if has_focus {
            let row_i = visual_row_for_cursor(&visual_rows, cursor.char_index);
            let row = &visual_rows[row_i];
            let local_col = cursor.char_index.saturating_sub(row.start).min(row.end - row.start);
            let row_text = slice_chars(content, row.start, row.end);
            let cursor_x = draw_top.x + char_advance(ui, &font_id, row_text, local_col);
            let y = draw_top.y + row_height * row_i as f32;
            painter.line_segment([egui::pos2(cursor_x, y), egui::pos2(cursor_x, y + row_height)], egui::Stroke::new(1.0, ui.visuals().text_color()));
        }
        if max_scroll > 0.0 {
            ui.painter().rect_filled(
                scrollbar_track,
                scrollbar_w / 2.0,
                ui.visuals().extreme_bg_color,
            );
            let thumb_fill = if scrollbar_thumb_response.hovered() || scrollbar_thumb_response.dragged() {
                ui.visuals().widgets.hovered.bg_fill
            } else {
                ui.visuals().widgets.inactive.bg_fill
            };
            ui.painter().rect_filled(
                scrollbar_thumb,
                scrollbar_w / 2.0,
                thumb_fill,
            );
        }
        // Three diagonal grip marks make the resize affordance obvious.
        // The hit target is the full `resize_rect`, not just these pixels.
        let grip_color = ui.visuals().widgets.inactive.fg_stroke.color;
        for offset in [11.0, 7.0, 3.0] {
            ui.painter().line_segment(
                [
                    egui::pos2(rect.max.x - offset - 4.0, rect.max.y - 3.0),
                    egui::pos2(rect.max.x - 3.0, rect.max.y - offset - 4.0),
                ],
                egui::Stroke::new(1.0, grip_color),
            );
        }
        response
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VisualRow { start: usize, end: usize }

/// Sums per-glyph advance widths for `text` instead of measuring via
/// `Fonts::layout_no_wrap` (which — see `paint_chars` below — builds and
/// caches a `Galley` owning a full plaintext copy of `text`). Used to
/// size a rect for secret text *before* painting it with `paint_chars`,
/// so the measurement step itself doesn't reintroduce the same leak
/// `paint_chars` exists to avoid.
pub(crate) fn text_width(ui: &Ui, font_id: &egui::FontId, text: &str) -> f32 {
    ui.fonts(|f| text.chars().map(|c| f.glyph_width(font_id, c)).sum())
}

/// Paints `text` one character at a time instead of via
/// `egui::Painter::text(..., text, ...)` on the whole string.
///
/// SECURITY: `Painter::text` (and `Fonts::layout_no_wrap`, which it
/// calls internally) builds an `egui::Galley` — a struct that owns a
/// plain, un-zeroized `String` copy of whatever text was laid out — and
/// caches it in `egui::Fonts`' internal LRU cache, keyed by the text
/// itself, for reuse across frames. That cache is private to `egui`;
/// this app has no handle into it and cannot zeroize or evict entries.
/// Painting a whole line/row of notes that way means the *actual
/// secret content* sits as a plaintext `String` inside that cache,
/// outside `SecretString`/`LockedSecret`'s reach, for however many
/// frames `egui` chooses to keep it — this was confirmed in practice:
/// it's what turned up in a post-edit core dump even after
/// `vault_edit_notes` itself was sealed as a `LockedSecret`.
///
/// Painting one `char` at a time instead means every Galley `egui`
/// caches contains a single character — 'a', 'b', '3', etc. Those are
/// shared across the *entire* UI (every label, button, and field in
/// the app reuses the same handful of per-character cache entries), so
/// the cache never holds a contiguous run of secret text as a
/// substring. A memory scan can still tell that the letters composing
/// "test" have been painted somewhere, exactly as it could for any
/// text the app has ever displayed — but it can no longer read the
/// word "test" back out of the cache the way it could read a whole
/// cached line. This is the same one-glyph-at-a-time approach
/// `SecurePasswordEdit` already uses for its `●` bullets, generalized
/// to real (variable-width) glyphs instead of one fixed repeated one.
pub(crate) fn paint_chars(
    ui: &Ui,
    painter: &egui::Painter,
    mut pos: egui::Pos2,
    text: &str,
    font_id: &egui::FontId,
    color: egui::Color32,
) {
    for ch in text.chars() {
        let w = ui.fonts(|f| f.glyph_width(font_id, ch));
        painter.text(pos, egui::Align2::LEFT_TOP, ch, font_id.clone(), color);
        pos.x += w;
    }
}

fn slice_chars(content: &str, start: usize, end: usize) -> &str {
    let start_b = content.char_indices().nth(start).map(|(b, _)| b).unwrap_or(content.len());
    let end_b = content.char_indices().nth(end).map(|(b, _)| b).unwrap_or(content.len());
    &content[start_b..end_b]
}

fn build_visual_rows(ui: &Ui, content: &str, font_id: &egui::FontId, max_width: f32) -> Vec<VisualRow> {
    let mut rows = Vec::new();
    let mut row_start = 0usize;
    let mut row_width = 0.0f32;
    let mut last_space_after = None;
    let mut char_index = 0usize;
    for ch in content.chars() {
        if ch == '\n' {
            rows.push(VisualRow { start: row_start, end: char_index });
            row_start = char_index + 1;
            row_width = 0.0;
            last_space_after = None;
            char_index += 1;
            continue;
        }
        let width = ui.fonts(|f| f.glyph_width(font_id, ch));
        if char_index > row_start && row_width + width > max_width {
            if let Some(space_after) = last_space_after.filter(|p| *p > row_start) {
                rows.push(VisualRow { start: row_start, end: space_after });
                row_start = space_after;
                row_width = 0.0;
            } else {
                rows.push(VisualRow { start: row_start, end: char_index });
                row_start = char_index;
                row_width = 0.0;
            }
            last_space_after = None;
        }
        row_width += width;
        char_index += 1;
        if ch.is_whitespace() { last_space_after = Some(char_index); }
    }
    if row_start < char_index || rows.is_empty() || content.ends_with('\n') {
        rows.push(VisualRow { start: row_start, end: char_index });
    }
    rows
}

fn visual_row_for_cursor(rows: &[VisualRow], char_index: usize) -> usize {
    if rows.is_empty() { return 0; }
    rows.iter().position(|row| char_index <= row.end).unwrap_or(rows.len() - 1)
}

/// Converts a flat character index into (logical line, column), using
/// only newline-delimited lines. This intentionally ignores visual wrapping.
fn line_and_col(content: &str, char_index: usize) -> (usize, usize) {
    let mut line = 0usize;
    let mut col = 0usize;
    for (i, ch) in content.chars().enumerate() {
        if i == char_index {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Returns the character index of the beginning of the logical line
/// containing `char_index`. Visual wrapping does not affect this.
fn line_start(content: &str, char_index: usize) -> usize {
    let at = char_index.min(content.chars().count());
    let (_, col) = line_and_col(content, at);
    at - col
}

/// Returns the character index just after the last character of the
/// logical line containing `char_index` (the newline itself is excluded).
fn line_end(content: &str, char_index: usize) -> usize {
    let at = char_index.min(content.chars().count());
    let (line, _) = line_and_col(content, at);
    let mut idx = 0usize;
    for (l, segment) in content.split('\n').enumerate() {
        let seg_len = segment.chars().count();
        if l == line {
            return idx + seg_len;
        }
        idx += seg_len + 1;
    }
    content.chars().count()
}

fn move_cursor_visual(rows: &[VisualRow], char_index: usize, delta: isize) -> usize {
    if rows.is_empty() { return char_index; }
    let row_i = visual_row_for_cursor(rows, char_index);
    let row = &rows[row_i];
    let col = char_index.saturating_sub(row.start).min(row.end - row.start);
    let target = row_i as isize + delta;
    if target < 0 { return 0; }
    let target = target as usize;
    if target >= rows.len() { return rows.last().map(|r| r.end).unwrap_or(char_index); }
    let target_row = &rows[target];
    target_row.start + col.min(target_row.end - target_row.start)
}

fn char_index_from_visual_pos(ui: &Ui, content: &str, font_id: &egui::FontId, rows: &[VisualRow], top_left: egui::Pos2, row_height: f32, pos: egui::Pos2) -> usize {
    if rows.is_empty() { return 0; }
    let rel_y = (pos.y - top_left.y).max(0.0);
    let row_i = ((rel_y / row_height).floor() as usize).min(rows.len() - 1);
    let row = rows[row_i];
    let row_text = slice_chars(content, row.start, row.end);
    let rel_x = (pos.x - top_left.x).max(0.0);
    let mut acc = 0.0f32;
    let mut col = 0usize;
    for ch in row_text.chars() {
        let w = ui.fonts(|f| f.glyph_width(font_id, ch));
        if acc + w / 2.0 > rel_x { break; }
        acc += w;
        col += 1;
    }
    row.start + col.min(row.end - row.start)
}

/// If `shift` is held, starts a selection anchored at the cursor's
/// current position (if one isn't already in progress) so the upcoming
/// cursor move extends it. If `shift` isn't held, drops any existing
/// selection — a plain arrow/Home/End press always collapses it, same
/// as every other text editor.
fn extend_or_collapse(cursor: &mut CursorState, shift: bool) {
    if shift {
        if cursor.anchor.is_none() {
            cursor.anchor = Some(cursor.char_index);
        }
    } else {
        cursor.anchor = None;
    }
}

/// If a non-empty selection exists, deletes it (zeroizing the vacated
/// bytes the same way every other mutation on `SecretString` does),
/// collapses the cursor to where the selection started, and clears the
/// anchor. Returns whether anything was deleted, so callers (Backspace/
/// Delete) know not to *additionally* remove one more character.
fn delete_selection(text: &mut SecretString, cursor: &mut CursorState) -> bool {
    let Some(anchor) = cursor.anchor else {
        return false;
    };
    if anchor == cursor.char_index {
        cursor.anchor = None;
        return false;
    }
    let (start, end) = if anchor < cursor.char_index {
        (anchor, cursor.char_index)
    } else {
        (cursor.char_index, anchor)
    };
    let start_b = text.byte_index_from_char_index(start);
    let end_b = text.byte_index_from_char_index(end);
    text.delete_byte_range(start_b..end_b);
    cursor.char_index = start;
    cursor.anchor = None;
    true
}

/// Sums glyph widths for the first `upto_col` characters of `line`, to
/// place a selection-highlight edge at the right x position. Same
/// approach the caret placement below already uses.
fn char_advance(ui: &Ui, font_id: &egui::FontId, line: &str, upto_col: usize) -> f32 {
    ui.fonts(|f| line.chars().take(upto_col).map(|c| f.glyph_width(font_id, c)).sum())
}

/// Convenience free function, mirroring `ui.add(egui::TextEdit::multiline(..))`'s
/// ergonomics: `secure_text_edit::secure_notes_edit(ui, "my_id", &mut self.notes)`.
#[allow(dead_code)]
pub fn secure_notes_edit(
    ui: &mut Ui,
    id_source: impl std::hash::Hash,
    text: &mut SecretString,
) -> Response {
    ui.add(SecureNotesEdit::new(id_source, text))
}

/// The current selection in a `SecureNotesEdit` with the given
/// `id_source`, as a char range, or `None` if there is no active
/// selection (nothing dragged/shift-selected, or the field has never
/// been focused this session). Call this *after* `ui.add(..)` for the
/// same frame's selection. Used by callers that want a "Copy
/// selection" action alongside the widget's own Ctrl+C handling — see
/// `take_copy_request`.
pub fn selected_range(ui: &Ui, id_source: impl std::hash::Hash) -> Option<Range<usize>> {
    let id = Id::new(id_source);
    let cursor: CursorState = ui.memory(|m| m.data.get_temp::<CursorState>(id))?;
    let anchor = cursor.anchor?;
    if anchor == cursor.char_index {
        return None;
    }
    Some(if anchor < cursor.char_index {
        anchor..cursor.char_index
    } else {
        cursor.char_index..anchor
    })
}

/// The char range of the line the caret is currently on in a
/// `SecureNotesEdit` with the given `id_source` (not including the
/// trailing newline). Lets a caller offer a "Copy line" action without
/// requiring the user to manually select the line first.
///
/// SECURITY: no longer called from `main.rs` — the Notes context menu's
/// "Copy line" action was removed because it cloned the whole scanned
/// line into a fresh, separately-allocated `String`, an extra plaintext
/// copy in RAM beyond the already-revealed `notes_plain`. Kept here
/// (rather than deleted) since it's still exercised by the unit test
/// below and may be reintroduced behind a tighter memory contract later.
#[allow(dead_code)]
pub fn current_line_range(ui: &Ui, id_source: impl std::hash::Hash, text: &SecretString) -> Range<usize> {
    // Important: this intentionally uses logical newline-delimited lines,
    // not `VisualRow`s. Wrapping is presentation-only and must never change
    // what the existing "Copy line" API means.
    let id = Id::new(id_source);
    let cursor: CursorState = ui.memory(|m| m.data.get_temp::<CursorState>(id)).unwrap_or_default();
    let content = text.as_str();
    let at = cursor.char_index.min(text.len_chars());
    line_start(content, at)..line_end(content, at)
}

/// Whether Ctrl/Cmd+C was pressed in the `SecureNotesEdit` with the
/// given `id_source` since the last time this was called — and clears
/// the flag. The widget itself never touches the OS clipboard (see its
/// `ui()` doc comment on the Ctrl+C handler); callers are expected to
/// poll this right after `ui.add(..)`, and if it's `true`, copy
/// `selected_range` (or the whole field, if there's no selection —
/// matching ordinary Ctrl+C behavior) through their own clipboard path
/// so autoclear-style protections stay consistent across every "copy"
/// action in the app, not just the ones with a visible button.
pub fn take_copy_request(ui: &Ui, id_source: impl std::hash::Hash) -> bool {
    let id = Id::new(id_source).with("copy_req");
    let requested = ui.memory(|m| m.data.get_temp::<bool>(id)).unwrap_or(false);
    if requested {
        ui.memory_mut(|m| m.data.remove::<bool>(id));
    }
    requested
}

/// Extracts `range` (a char range) from `text` as an owned string. Only
/// meant to be called at the moment a selection is actually about to be
/// copied to the system clipboard — which turns it into plaintext anyway,
/// exactly like the existing whole-field "Copy" button already did for the
/// full contents. Everywhere else, the text stays inside `SecretString`.
///
/// Returns `Zeroizing<String>` rather than a plain `String`: this used to
/// hand back a bare `String`, and every caller stored the result in a
/// plain `Option<String>` local before forwarding it to
/// `copy_to_clipboard`/`copy_to_clipboard_20s`. Rust's `Drop` for `String`
/// deallocates without scrubbing the bytes first, so that plaintext
/// selection sat in freed-but-not-overwritten heap memory for the rest of
/// the process's life — recoverable from a core/stack dump taken any time
/// after the copy, not just during it. `Zeroizing<String>` wipes the
/// buffer on drop, closing that window; callers must keep using
/// `Zeroizing<String>` all the way through instead of unwrapping back into
/// a plain `String`.
pub fn extract_range(text: &SecretString, range: Range<usize>) -> zeroize::Zeroizing<String> {
    let len = text.len_chars();
    let start = text.byte_index_from_char_index(range.start.min(len));
    let end = text.byte_index_from_char_index(range.end.min(len));
    zeroize::Zeroizing::new(text.as_str()[start..end].to_string())
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    #[test]
    fn extract_range_pulls_out_the_right_substring() {
        let s = SecretString::from_str("hello world");
        assert_eq!(extract_range(&s, 0..5).as_str(), "hello");
        assert_eq!(extract_range(&s, 6..11).as_str(), "world");
    }

    #[test]
    fn extract_range_clamps_past_the_end() {
        let s = SecretString::from_str("hi");
        assert_eq!(extract_range(&s, 0..100).as_str(), "hi");
    }

    #[test]
    fn delete_selection_removes_forward_selection() {
        let mut s = SecretString::from_str("hello world");
        let mut cursor = CursorState {
            char_index: 5, // after "hello", anchor before it
            anchor: Some(0),
            scroll_y: 0.0,
        };
        assert!(delete_selection(&mut s, &mut cursor));
        assert_eq!(s.as_str(), " world");
        assert_eq!(cursor.char_index, 0);
        assert!(cursor.anchor.is_none());
    }

    #[test]
    fn delete_selection_removes_backward_selection() {
        // Same range, but the cursor is the earlier end (as if the user
        // shift+Home'd from partway through the word back to the start).
        let mut s = SecretString::from_str("hello world");
        let mut cursor = CursorState {
            char_index: 0,
            anchor: Some(5),
            scroll_y: 0.0,
        };
        assert!(delete_selection(&mut s, &mut cursor));
        assert_eq!(s.as_str(), " world");
        assert_eq!(cursor.char_index, 0);
    }

    #[test]
    fn delete_selection_is_a_noop_with_no_anchor() {
        let mut s = SecretString::from_str("unchanged");
        let mut cursor = CursorState { char_index: 3, anchor: None, scroll_y: 0.0 };
        assert!(!delete_selection(&mut s, &mut cursor));
        assert_eq!(s.as_str(), "unchanged");
    }

    #[test]
    fn delete_selection_is_a_noop_when_anchor_equals_cursor() {
        let mut s = SecretString::from_str("unchanged");
        let mut cursor = CursorState { char_index: 3, anchor: Some(3), scroll_y: 0.0 };
        assert!(!delete_selection(&mut s, &mut cursor));
        assert_eq!(s.as_str(), "unchanged");
        assert!(cursor.anchor.is_none(), "a zero-width anchor should still be cleared");
    }

    #[test]
    fn extend_or_collapse_sets_anchor_only_on_first_shift_move() {
        let mut cursor = CursorState { char_index: 4, anchor: None, scroll_y: 0.0 };
        extend_or_collapse(&mut cursor, true);
        assert_eq!(cursor.anchor, Some(4));
        // A second shift-move shouldn't reset the anchor to the
        // (already moved) cursor position.
        cursor.char_index = 6;
        extend_or_collapse(&mut cursor, true);
        assert_eq!(cursor.anchor, Some(4));
    }

    #[test]
    fn extend_or_collapse_drops_anchor_without_shift() {
        let mut cursor = CursorState { char_index: 4, anchor: Some(0), scroll_y: 0.0 };
        extend_or_collapse(&mut cursor, false);
        assert!(cursor.anchor.is_none());
    }

    #[test]
    fn multiline_selection_spanning_a_newline() {
        // "line one\nline two" — select from char 2 ("n" in "line") on
        // the first line through char 3 on the second line.
        let mut s = SecretString::from_str("line one\nline two");
        let mut cursor = CursorState {
            char_index: "line one\nlin".chars().count(),
            anchor: Some(2),
            scroll_y: 0.0,
        };
        let deleted = delete_selection(&mut s, &mut cursor);
        assert!(deleted);
        assert_eq!(s.as_str(), "lie two");
        assert_eq!(cursor.char_index, 2);
    }
    #[test]
    fn current_line_range_remains_logical_when_text_contains_long_lines() {
        // This is the contract used by the Notes context menu: a visual
        // wrap must not turn one logical line into several copyable lines.
        let s = SecretString::from_str("one two three four");
        let content = s.as_str();
        let at = content.chars().count();
        assert_eq!(line_start(content, at)..line_end(content, at), 0..18);

        let s = SecretString::from_str("first line\nsecond line that wraps visually");
        let content = s.as_str();
        let at = 16;
        assert_eq!(line_start(content, at)..line_end(content, at), 11..42);
    }

}
