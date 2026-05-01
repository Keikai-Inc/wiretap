//! Terminal-protocol responder for captured pty sessions.
//!
//! ## What this is
//!
//! A pty has two ends: the application end (vim/bash/etc.) and the
//! terminal end (the human-facing renderer). The terminal end isn't
//! passive — it answers a protocol. When vim sends OSC 11 (`what's the
//! background color?`), the terminal at the other end answers
//! `\x1b]11;rgb:RRRR/GGGG/BBBB\x1b\\`. Same for DA1, DA2, DSR/CPR,
//! DECRQM-private mode queries, OSC 10/11/12 color queries, and the
//! CSI t-suite of window-manipulation reports.
//!
//! hop-tap was originally designed assuming **one** terminal answers
//! per pty (the captured user's actual terminal at the far end of the
//! ssh pipe). When `tap connect` streams that pty's output to a
//! subscriber's local terminal, the subscriber's terminal autonomously
//! answers any queries it sees there — and the answer races back
//! through `Inject` into the pty as if the operator typed it. vim
//! then sees garbage like `:3838/0c0c/2a2a` (the body of an OSC color
//! response) on its ex command line.
//!
//! tmux solves this by being the terminal: it answers queries itself,
//! from its own virtual screen state. Subscribers are dumb displays.
//! Phase 1 of `docs/render-only-architecture.md` ports that idea here.
//!
//! ## How it works
//!
//! `alacritty_terminal::Term` already contains the protocol-response
//! logic — DA1, DA2, DSR, DECRQM-private, OSC color queries, text area
//! reports — wired through its `EventListener`. The daemon's previous
//! `VoidListener` dropped those events on the floor; that's why the
//! captured app's queries never got answered (well, they got answered
//! by the subscribers' terminals, which is the bug).
//!
//! [`ResponderListener`] is an `EventListener` impl that captures the
//! relevant `Event` variants — `PtyWrite`, `ColorRequest`,
//! `TextAreaSizeRequest` — into a shared byte buffer. The daemon
//! drains that buffer after each `Processor::advance(&mut term,
//! bytes)` call and writes the bytes back to the pty's master fd.
//! Queries get answered by the daemon's own grid model, instantly,
//! before the captured app's response timeout.
//!
//! Side-effect events the captured app might emit but the daemon
//! doesn't act on — `Bell`, `Wakeup`, `Title`, `ResetTitle`,
//! `MouseCursorDirty`, `CursorBlinkingChange`, `Exit`, `ChildExit`,
//! `ClipboardStore`, `ClipboardLoad` — are silently ignored. We're
//! not a windowing system.
//!
//! ## Color palette
//!
//! Queries for OSC 10/11/12 (foreground / background / cursor color)
//! and OSC 4 (palette index) come through `Event::ColorRequest(index,
//! formatter)`. The listener provides a hardcoded palette derived from
//! alacritty's defaults. The captured app gets a stable, sensible
//! answer regardless of what color scheme any subscriber's local
//! terminal uses — which is correct, since the captured app's notion
//! of "the terminal" is the daemon now, not any individual operator.
//!
//! Configurable palette is a follow-up; see the design doc.
//!
//! ## Phase 2 staging
//!
//! This module is **not wired into the daemon yet**. Phase 1 closes
//! the immediate vim/htop/Claude bug by filtering captured-app
//! queries out of the subscriber broadcast (see `query_filter.rs`)
//! — that's a smaller change that doesn't depend on the daemon
//! owning the protocol.
//!
//! When Phase 2 lands (subscribers see rendered cells, not raw
//! bytes), the daemon becomes the canonical responder for the
//! captured pty's protocol queries, and that's where this module
//! gets switched on. Until then it compiles and is unit-tested but
//! isn't constructed by `main.rs`.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::vte::ansi::{NamedColor, Rgb};

/// Shared response buffer. The listener pushes into it via interior
/// mutability (alacritty calls `send_event(&self, ...)` so the
/// listener can't be `&mut`); the daemon drains it after each
/// `Processor::advance()`.
pub(crate) type ResponseBuf = Arc<Mutex<Vec<u8>>>;

/// `EventListener` impl that turns alacritty's terminal-protocol
/// events into bytes the daemon writes back to the pty master fd.
///
/// Only events relevant to "answer queries the captured app sent"
/// are translated. Display-side events (Bell, Title, Wakeup, etc.)
/// are ignored — the daemon isn't a window/UI.
pub(crate) struct ResponderListener {
    buf: ResponseBuf,
    palette: Palette,
}

impl ResponderListener {
    /// Create a listener writing into `buf` and answering color
    /// queries from a default alacritty-style palette.
    pub(crate) fn new(buf: ResponseBuf) -> Self {
        Self { buf, palette: Palette::default() }
    }

    fn push(&self, bytes: &[u8]) {
        let mut guard = self.buf.lock().expect("response buffer poisoned");
        guard.extend_from_slice(bytes);
    }
}

impl EventListener for ResponderListener {
    fn send_event(&self, event: Event) {
        match event {
            // Direct response strings — DA1, DA2, DSR-5, DSR-6,
            // DECRQM-private, CSI 18 t (text-area chars). Alacritty
            // formats these completely and we just forward.
            Event::PtyWrite(text) => {
                self.push(text.as_bytes());
            }

            // OSC 10/11/12 (fg/bg/cursor) and OSC 4 (palette idx)
            // come through here. Index is the NamedColor or palette
            // slot; alacritty's formatter wraps our color into the
            // proper response with the original terminator.
            Event::ColorRequest(index, formatter) => {
                let color = self.palette.color_for_index(index);
                let response = formatter(color);
                self.push(response.as_bytes());
            }

            // CSI 14 t / 15 t / 16 t — pixel-size queries. Most TUI
            // apps don't use these, but a few do (image-capable apps,
            // some progress libraries). Stub with cell=8x16, no
            // window decoration.
            Event::TextAreaSizeRequest(formatter) => {
                // We don't track the captured pty's cell/window size
                // (that's a display concept the daemon doesn't have),
                // so synthesize a reasonable default. The grid dims
                // are filled in by the caller via the formatter
                // callback chain inside alacritty before we get here.
                //
                // Looking at alacritty's text_area_size_pixels: it
                // calls the formatter with a WindowSize derived from
                // num_lines × cell_height etc. We don't have access
                // to those; pass a stub. Apps that genuinely need
                // pixel sizes (sixel apps mostly) won't be on Phase 1
                // anyway.
                let response = formatter(WindowSize {
                    num_lines: 0,
                    num_cols: 0,
                    cell_width: 8,
                    cell_height: 16,
                });
                self.push(response.as_bytes());
            }

            // Clipboard load: the captured app asked to receive the
            // clipboard contents. We have no clipboard at the daemon
            // level — silently ignore. (Subscribers might want to
            // implement this later by routing to their local
            // clipboard, but that's a Phase-2+ concern.)
            Event::ClipboardLoad(_, _) => {}

            // Everything else is a display-side concern that doesn't
            // produce bytes back to the pty:
            //   Title / ResetTitle: window decoration, daemon ignores
            //   ClipboardStore: we don't have a clipboard
            //   MouseCursorDirty / CursorBlinkingChange: display only
            //   Wakeup: damage-tracking notification for renderers
            //   Bell: \a from captured app, no response
            //   Exit / ChildExit: lifecycle, handled elsewhere
            _ => {}
        }
    }
}

/// Color palette used to answer OSC 10/11/12 and OSC 4 queries.
///
/// Hardcoded to alacritty's default scheme. The captured app's
/// queries get a stable answer; subscribers' local terminals see
/// rendered cells (in Phase 2) or raw bytes (now), unaffected.
struct Palette {
    fg: Rgb,
    bg: Rgb,
    cursor: Rgb,
    /// 256-color palette (slots 0..256). Filled with alacritty's
    /// defaults — first 16 are the standard ANSI colors, then the
    /// 6×6×6 cube and the grayscale ramp.
    indexed: [Rgb; 256],
}

impl Default for Palette {
    fn default() -> Self {
        let mut indexed = [Rgb { r: 0, g: 0, b: 0 }; 256];

        // Standard ANSI colors 0-7 (alacritty's defaults).
        let ansi = [
            (0x18, 0x18, 0x18), // black
            (0xCC, 0x66, 0x66), // red
            (0xB5, 0xBD, 0x68), // green
            (0xF0, 0xC6, 0x74), // yellow
            (0x81, 0xA2, 0xBE), // blue
            (0xB2, 0x94, 0xBB), // magenta
            (0x8A, 0xBE, 0xB7), // cyan
            (0xC5, 0xC8, 0xC6), // white
        ];
        for (i, &(r, g, b)) in ansi.iter().enumerate() {
            indexed[i] = Rgb { r, g, b };
        }
        // Bright colors 8-15.
        let bright = [
            (0x66, 0x66, 0x66),
            (0xD5, 0x4E, 0x53),
            (0xB9, 0xCA, 0x4A),
            (0xE7, 0xC5, 0x47),
            (0x7A, 0xA6, 0xDA),
            (0xC3, 0x97, 0xD8),
            (0x70, 0xC0, 0xB1),
            (0xEA, 0xEA, 0xEA),
        ];
        for (i, &(r, g, b)) in bright.iter().enumerate() {
            indexed[8 + i] = Rgb { r, g, b };
        }

        // 6×6×6 RGB cube starts at index 16.
        let levels = [0u8, 0x5F, 0x87, 0xAF, 0xD7, 0xFF];
        for r in 0..6 {
            for g in 0..6 {
                for b in 0..6 {
                    indexed[16 + r * 36 + g * 6 + b] =
                        Rgb { r: levels[r], g: levels[g], b: levels[b] };
                }
            }
        }
        // Grayscale ramp 232..256.
        for i in 0..24 {
            let v = 0x08 + (i as u8) * 10;
            indexed[232 + i] = Rgb { r: v, g: v, b: v };
        }

        Self {
            fg: Rgb { r: 0xC5, g: 0xC8, b: 0xC6 },
            bg: Rgb { r: 0x1D, g: 0x1F, b: 0x21 },
            cursor: Rgb { r: 0xC5, g: 0xC8, b: 0xC6 },
            indexed,
        }
    }
}

impl Palette {
    /// Return the color for an alacritty `NamedColor` slot or a
    /// 256-color palette index. OSC 10 → Foreground, 11 →
    /// Background, 12 → Cursor; OSC 4 → indexed palette.
    fn color_for_index(&self, index: usize) -> Rgb {
        if index == NamedColor::Foreground as usize {
            self.fg
        } else if index == NamedColor::Background as usize {
            self.bg
        } else if index == NamedColor::Cursor as usize {
            self.cursor
        } else if index < 256 {
            self.indexed[index]
        } else {
            // Out of range — return foreground as a benign default.
            self.fg
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alacritty_terminal::event::VoidListener;
    use alacritty_terminal::grid::Dimensions;
    use alacritty_terminal::term::{Config, Term};
    use alacritty_terminal::vte::ansi::Processor;

    /// Fixed dimensions for the test terminal.
    struct TestDims;
    impl Dimensions for TestDims {
        fn columns(&self) -> usize { 80 }
        fn screen_lines(&self) -> usize { 24 }
        fn total_lines(&self) -> usize { 24 }
    }

    /// Build a Term wired to the responder, drive `bytes` through the
    /// vte processor, and return the response bytes the listener
    /// captured.
    fn run(bytes: &[u8]) -> Vec<u8> {
        let buf: ResponseBuf = Arc::new(Mutex::new(Vec::new()));
        let listener = ResponderListener::new(buf.clone());
        let mut term = Term::new(Config::default(), &TestDims, listener);
        let mut processor: Processor = Processor::new();
        processor.advance(&mut term, bytes);
        let guard = buf.lock().unwrap();
        guard.clone()
    }

    /// Same but starting from a pre-driven term state — lets a test
    /// set up modes (e.g. focus reporting on) before issuing a query.
    fn run_with_setup(setup: &[u8], query: &[u8]) -> Vec<u8> {
        let buf: ResponseBuf = Arc::new(Mutex::new(Vec::new()));
        let listener = ResponderListener::new(buf.clone());
        let mut term = Term::new(Config::default(), &TestDims, listener);
        let mut processor: Processor = Processor::new();
        processor.advance(&mut term, setup);
        // Drain any responses from setup (none expected for plain
        // mode-set sequences, but be safe).
        buf.lock().unwrap().clear();
        processor.advance(&mut term, query);
        let guard = buf.lock().unwrap();
        guard.clone()
    }

    #[test]
    fn answers_da1() {
        // \x1b[c — primary device attributes.
        // alacritty replies \x1b[?6c (vt102).
        let resp = run(b"\x1b[c");
        assert_eq!(resp, b"\x1b[?6c");
    }

    #[test]
    fn answers_da2() {
        // \x1b[>c — secondary device attributes.
        // alacritty replies \x1b[>0;<version>;1c
        let resp = run(b"\x1b[>c");
        assert!(resp.starts_with(b"\x1b[>0;"));
        assert!(resp.ends_with(b";1c"));
    }

    #[test]
    fn answers_dsr_status() {
        // \x1b[5n — request status report. Reply \x1b[0n (ready).
        let resp = run(b"\x1b[5n");
        assert_eq!(resp, b"\x1b[0n");
    }

    #[test]
    fn answers_dsr_cursor_position() {
        // \x1b[6n — cursor position report. Cursor at 1;1 by default.
        let resp = run(b"\x1b[6n");
        assert_eq!(resp, b"\x1b[1;1R");
    }

    #[test]
    fn answers_dsr_cursor_after_movement() {
        // Move cursor down 4 rows + right 7 cols, then query.
        let resp = run(b"\x1b[5;8H\x1b[6n");
        assert_eq!(resp, b"\x1b[5;8R");
    }

    #[test]
    fn answers_decrqm_focus_unset_by_default() {
        // \x1b[?1004$p — query focus reporting. Default is unset (2).
        let resp = run(b"\x1b[?1004$p");
        assert_eq!(resp, b"\x1b[?1004;2$y");
    }

    #[test]
    fn answers_decrqm_focus_after_set() {
        // Enable focus reporting, then query.
        let resp = run_with_setup(b"\x1b[?1004h", b"\x1b[?1004$p");
        assert_eq!(resp, b"\x1b[?1004;1$y");
    }

    #[test]
    fn answers_decrqm_bracketed_paste() {
        let resp = run_with_setup(b"\x1b[?2004h", b"\x1b[?2004$p");
        assert_eq!(resp, b"\x1b[?2004;1$y");
    }

    #[test]
    fn answers_decrqm_sgr_mouse() {
        let resp = run_with_setup(b"\x1b[?1006h", b"\x1b[?1006$p");
        assert_eq!(resp, b"\x1b[?1006;1$y");
    }

    #[test]
    fn answers_decrqm_unknown_mode() {
        // Unknown private mode → state 0 (NotSupported).
        let resp = run(b"\x1b[?9999$p");
        assert_eq!(resp, b"\x1b[?9999;0$y");
    }

    #[test]
    fn answers_osc_11_bg_color_query() {
        // \x1b]11;?\x07 — query background color.
        // Response form: \x1b]11;rgb:RRRR/GGGG/BBBB\x07
        let resp = run(b"\x1b]11;?\x07");
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.starts_with("\x1b]11;rgb:"));
        assert!(s.ends_with('\x07'));
    }

    #[test]
    fn answers_osc_10_fg_color_query() {
        let resp = run(b"\x1b]10;?\x07");
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.starts_with("\x1b]10;rgb:"));
    }

    #[test]
    fn answers_osc_4_palette_query() {
        // \x1b]4;3;?\x07 — query palette index 3 (yellow).
        let resp = run(b"\x1b]4;3;?\x07");
        let s = std::str::from_utf8(&resp).unwrap();
        assert!(s.starts_with("\x1b]4;3;rgb:"));
    }

    #[test]
    fn answers_csi_18_t_text_area_chars() {
        // \x1b[18t — request text area in chars. Reply \x1b[8;<rows>;<cols>t
        let resp = run(b"\x1b[18t");
        assert_eq!(resp, b"\x1b[8;24;80t");
    }

    #[test]
    fn ignores_bell() {
        // \x07 BEL emits Event::Bell; the listener ignores it.
        let resp = run(b"\x07");
        assert!(resp.is_empty());
    }

    #[test]
    fn ignores_title_set() {
        // OSC 0 sets the window title — display-side event, no response.
        let resp = run(b"\x1b]0;hello\x07");
        assert!(resp.is_empty());
    }

    #[test]
    fn ignores_plain_text() {
        // Printable text changes the grid but produces no response bytes.
        let resp = run(b"hello world\r\n");
        assert!(resp.is_empty());
    }

    #[test]
    fn multiple_queries_accumulate() {
        // Two queries in one chunk → both responses concatenated.
        let resp = run(b"\x1b[c\x1b[5n");
        assert_eq!(resp, b"\x1b[?6c\x1b[0n");
    }

    #[test]
    fn that_term_uses_voidlistener_too() {
        // Sanity check: VoidListener still works (no response when
        // it's the listener — so nothing changes for callers that
        // don't want responses).
        let mut term = Term::new(Config::default(), &TestDims, VoidListener);
        let mut processor: Processor = Processor::new();
        processor.advance(&mut term, b"\x1b[c");
        // No way to observe a response from VoidListener, but the
        // call shouldn't panic — that's the assertion.
    }
}
