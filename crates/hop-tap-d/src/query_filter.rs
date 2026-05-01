//! Strip captured-app terminal-protocol queries out of the byte
//! stream broadcast to subscribers.
//!
//! ## Why this exists
//!
//! When the captured app (vim, htop, Claude Code, …) starts up it
//! probes its terminal: "what's your background color?" (OSC 11),
//! "what device attributes do you support?" (DA1), "where's the
//! cursor?" (DSR 6), "is mode 2026 enabled?" (DECRQM-private), etc.
//! In a normal pty conversation, the terminal at the master end of
//! the pty (bob's actual terminal — alacritty / iTerm / sshd-pipe)
//! sees those queries and answers. Vim is happy.
//!
//! hop-tap captures the slave→master side of the pty via eBPF and
//! broadcasts the raw bytes to subscribers (`tap connect` sessions).
//! That broadcast includes the queries vim emitted. Subscribers'
//! terminals see the queries and **also** answer them — and their
//! answers race back through `Inject` into the pty as if the
//! operator had typed them. Vim, having already consumed bob's
//! terminal's response, treats the subscriber's late response as
//! keystrokes. Symptoms in vim: `:3838/0c0c/2a2a` ex-mode garbage
//! from leaked OSC color responses; spurious focus-in/out events;
//! mouse-event interpretation issues.
//!
//! The fix: don't show subscribers the queries. Bob's terminal is
//! still answering them as it always has — that's how the pty's
//! protocol works. We just stop forwarding the questions to anyone
//! else, so no one else volunteers an answer.
//!
//! See `docs/render-only-architecture.md` for the full architectural
//! discussion (this is "Phase 1" there). Phase 2 makes the
//! distinction structural — subscribers see rendered cells, not raw
//! bytes — and at that point this filter becomes obsolete.
//!
//! ## What gets dropped
//!
//! Only **queries the captured app sends to its terminal**:
//!
//! - DA1: `\x1b[c`, `\x1b[0c`
//! - DA2: `\x1b[>c`, `\x1b[>0c`
//! - DSR-5 / DSR-6: `\x1b[5n`, `\x1b[6n`
//! - DECRQM-private: `\x1b[?<n>$p` (any mode)
//! - DECRQM (ANSI): `\x1b[<n>$p`
//! - OSC color queries: `\x1b]N;?<terminator>` for N in {4, 10, 11, 12, 17, 19}
//! - Window manipulation queries: `\x1b[14t`, `\x1b[15t`, `\x1b[16t`,
//!   `\x1b[18t`, `\x1b[19t`, `\x1b[21t` (text-area / window / icon
//!   reports)
//! - Kitty keyboard probe: `\x1b[?u`
//! - Orphan string-terminators (`\x1b\\`) trailing OSC sequences
//! - All DCS sequences (DECRQSS, sixel queries, terminfo replies —
//!   never visible content, always terminal-protocol)
//!
//! Everything else (printable text, cursor moves, SGR, alt-screen
//! switches, OSC title sets, OSC color *sets*, plain bell, etc.)
//! passes through byte-for-byte.
//!
//! ## How it works
//!
//! Bytes flow through two parallel paths:
//!
//! 1. A `vte::Parser` driving a [`Classifier`] (a `Perform` impl
//!    whose only job is to set "dispatched / is-query" flags when
//!    a sequence completes).
//! 2. A raw-byte buffer that captures every byte we see while a
//!    sequence is in progress.
//!
//! On each completed sequence, the classifier tells us whether to
//! commit the raw bytes to the output or discard them. Bytes in
//! ground state pass straight through, byte-for-byte. The raw
//! buffer is the source of truth for output bytes — vte's parsed
//! form (params, intermediates, action) is only used for
//! classification, not reconstruction. This avoids vte's lossy
//! normalization of default parameters (e.g. `\x1b[K` →
//! `\x1b[0K`).

use alacritty_terminal::vte::{Params, Parser, Perform};

/// Strip captured-app queries from `bytes` and return the remainder.
///
/// The output is suitable for forwarding to subscribers without
/// causing their local terminals to volunteer protocol responses.
pub fn strip_queries(bytes: &[u8]) -> Vec<u8> {
    let mut classifier = Classifier::default();
    let mut parser = Parser::new();

    // Drive every byte through vte. The classifier owns the output
    // buffer and the per-sequence raw-byte buffer. Vte's callbacks
    // tell us whether a given byte is in ground state (print /
    // execute → commit immediately) or mid-sequence / sequence-end
    // (let the buffer accumulate, then commit-or-drop on dispatch).
    //
    // Driving byte-by-byte rather than chunk-by-chunk lets the
    // classifier observe each byte's classification individually,
    // which is what avoids the ground-vs-sequence state-mismatch
    // bug (where a `\` byte after OSC's `\x1b` ST-start was leaking
    // because our outer loop thought we'd left the sequence but
    // the parser was still in Escape state).
    for &b in bytes {
        classifier.start_byte(b);
        parser.advance(&mut classifier, &[b]);
        classifier.end_byte();
    }

    // If we ended mid-sequence (rare — eBPF events don't normally
    // split sequences, but be safe), the accumulated seq_buf gets
    // dropped: it can't be classified, and forwarding partial
    // bytes to subscribers would leave their parsers broken.
    classifier.into_output()
}

/// Filter state — both `vte::Perform` (callbacks tell us how vte
/// classified each byte) *and* the byte buffer (we accumulate raw
/// input into `seq_buf` and `out` based on those classifications).
///
/// Per-byte protocol:
///   1. Caller pushes the byte into `seq_buf` via `start_byte`.
///   2. Caller drives `parser.advance(&mut self, &[b])`. Vte fires
///      one of our callbacks:
///      - `print` / `execute`: the byte was in ground state.
///        `current_kind = Ground` so `end_byte` flushes `seq_buf`
///        (which is just `[b]`) directly to `out`.
///      - `osc_dispatch` / `csi_dispatch` / `esc_dispatch` /
///        `unhook`: a sequence completed on this byte.
///        `current_kind = Dispatched(query)` so `end_byte` either
///        commits `seq_buf` to `out` (non-query) or drops it.
///      - none: byte is mid-sequence. `current_kind = MidSequence`.
///        `end_byte` leaves `seq_buf` intact for next byte.
#[derive(Default)]
struct Classifier {
    out: Vec<u8>,
    seq_buf: Vec<u8>,
    current_kind: ByteKind,
    /// When `Some(should_drop)`, the next byte is expected to be
    /// the `\\` completing an ST after a non-BEL-terminated OSC.
    /// vte fires that as a separate `esc_dispatch(byte=0x5C)`; we
    /// mirror the OSC's drop/keep decision so the ST stays attached
    /// to the correct fate.
    ///
    /// `None` means "no pending ST" — an `esc_dispatch(0x5C)` arriving
    /// in this state is an orphan we should drop.
    pending_st_drop: Option<bool>,
}

#[derive(Default, Debug)]
enum ByteKind {
    /// No callback yet for this byte (will be set by `start_byte`).
    #[default]
    Pending,
    /// `print`/`execute` fired — byte was in ground state.
    Ground,
    /// No callback fired — byte is mid-sequence, keep accumulating.
    MidSequence,
    /// A dispatch callback fired (sequence completed). Bool is
    /// true if it's a captured-app query that should be dropped.
    Dispatched(bool),
}

impl Classifier {
    fn start_byte(&mut self, b: u8) {
        self.seq_buf.push(b);
        self.current_kind = ByteKind::MidSequence;
    }

    fn end_byte(&mut self) {
        match std::mem::take(&mut self.current_kind) {
            ByteKind::Ground => {
                // The byte we just pushed to seq_buf is the *only*
                // byte there (ground state means we weren't
                // accumulating a sequence). Flush it to out.
                self.out.append(&mut self.seq_buf);
            }
            ByteKind::Dispatched(is_query) => {
                if is_query {
                    self.seq_buf.clear();
                } else {
                    self.out.append(&mut self.seq_buf);
                }
            }
            ByteKind::MidSequence | ByteKind::Pending => {
                // Keep accumulating.
            }
        }
    }

    fn into_output(self) -> Vec<u8> {
        self.out
    }
}

impl Perform for Classifier {
    // print and execute fire in ground state, exclusively. Mark
    // the byte as ground so end_byte commits.
    fn print(&mut self, _c: char) {
        self.current_kind = ByteKind::Ground;
    }

    fn execute(&mut self, _byte: u8) {
        self.current_kind = ByteKind::Ground;
    }

    fn osc_dispatch(&mut self, params: &[&[u8]], bell_terminated: bool) {
        let is_query = is_osc_query(params);
        self.current_kind = ByteKind::Dispatched(is_query);
        if !bell_terminated {
            // The OSC ended via `\x1b\\`. vte fires this dispatch on
            // the `\x1b` byte; the `\\` arrives as a separate
            // esc_dispatch on the next byte. Track the OSC's
            // keep-or-drop decision so the ST tail mirrors it.
            self.pending_st_drop = Some(is_query);
        }
    }

    fn csi_dispatch(
        &mut self,
        params: &Params,
        intermediates: &[u8],
        _ignore: bool,
        action: char,
    ) {
        self.current_kind =
            ByteKind::Dispatched(is_csi_query(params, intermediates, action));
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        // ESC `\\` (byte 0x5C, no intermediates) is the trailing half
        // of a non-BEL-terminated OSC's ST. vte fires `osc_dispatch`
        // on the leading `\x1b` and `esc_dispatch(0x5C)` on the
        // `\\`. To keep the ST attached to its OSC, we tracked the
        // OSC's drop/keep decision in `pending_st_drop`.
        //
        // Cases:
        //   - `\\` arrives with `pending_st_drop = Some(d)` → mirror
        //     `d`. (OSC SET → keep ST; OSC QUERY → drop ST.)
        //   - `\\` arrives with `pending_st_drop = None` → orphan
        //     ST (rare; malformed input). Drop.
        //   - Any other ESC sequence → not a query, keep.
        if intermediates.is_empty() && byte == 0x5C {
            let should_drop = self.pending_st_drop.take().unwrap_or(true);
            self.current_kind = ByteKind::Dispatched(should_drop);
        } else {
            self.current_kind = ByteKind::Dispatched(false);
        }
    }

    // DCS sequences (DECRQSS, sixel responses, terminfo dumps) are
    // always terminal-protocol, never visible content. Drop the
    // entire DCS by classifying its closing `unhook` as a query.
    // The intermediate `put` calls are mid-sequence (no kind change),
    // and `hook` itself is mid-sequence too — only `unhook` ends.
    fn hook(
        &mut self,
        _params: &Params,
        _intermediates: &[u8],
        _ignore: bool,
        _action: char,
    ) {
        // DCS start — bytes keep accumulating in seq_buf.
    }

    fn put(&mut self, _byte: u8) {
        // DCS data byte. Stays in seq_buf as part of the DCS.
    }

    fn unhook(&mut self) {
        self.current_kind = ByteKind::Dispatched(true);
    }
}

/// Classify a CSI sequence by terminator + intermediates + first
/// param. Returns true if it's a captured-app query (drop), false
/// otherwise.
fn is_csi_query(params: &Params, intermediates: &[u8], action: char) -> bool {
    match action {
        // DA1: \x1b[c (no intermediates) or \x1b[0c.
        // DA2: \x1b[>c — the `>` is captured by vte as an intermediate.
        'c' => true,
        // DSR-5 (status report) and DSR-6 (cursor position) — drop.
        // Other CSI-n forms shouldn't occur in slave→master from a
        // well-behaved app; we only drop the known query params.
        // DSR-private (`\x1b[?5n` etc.) has '?' in intermediates.
        'n' if intermediates.is_empty() => is_dsr_query(params),
        // DECRQM (ANSI mode query): `\x1b[<n>$p`.
        'p' if intermediates == b"$" => true,
        // DECRQM (private mode query): `\x1b[?<n>$p`.
        'p' if intermediates == b"?$" => true,
        // Kitty keyboard probe: `\x1b[?u`.
        'u' if intermediates == b"?" => true,
        // CSI t — only specific n values are reports. Most n values
        // are commands (resize/raise/iconify) that subscribers can
        // and should still see.
        't' if intermediates.is_empty() => is_window_manip_query(params),
        _ => false,
    }
}

/// `\x1b[5n` and `\x1b[6n` are status / cursor-position requests
/// from the captured app (queries — drop). Other CSI-n forms (e.g.
/// the legacy `\x1b[7n` "request user-defined keys") shouldn't
/// occur in slave→master; treat unrecognized `n` params as "not a
/// query" and forward.
fn is_dsr_query(params: &Params) -> bool {
    let first = params.iter().next().and_then(|p| p.first().copied());
    matches!(first, Some(5) | Some(6))
}

/// `\x1b[<n>t` — window manipulation. Most `n` values are *commands*
/// (resize, raise, lower, set title …) and not queries. Only
/// certain `n` values request reports back from the terminal:
///   14 → window pixel size
///   15 → screen pixel size
///   16 → cell pixel size
///   18 → text area in chars
///   19 → screen size in chars
///   21 → window title report
fn is_window_manip_query(params: &Params) -> bool {
    let first = params.iter().next().and_then(|p| p.first().copied());
    matches!(first, Some(14) | Some(15) | Some(16) | Some(18) | Some(19) | Some(21))
}

/// Classify an OSC sequence as a query.
///
/// OSC sequences from the captured app come in three shapes:
/// - SET: `\x1b]<code>;<value>\x07`            → params: ["<code>", "<value>"]
/// - QUERY: `\x1b]<code>;?\x07`                → params: ["<code>", "?"]
/// - PALETTE QUERY: `\x1b]4;<idx>;?\x07`       → params: ["4", "<idx>", "?"]
///
/// Anything ending in a literal `?` after the OSC code is a query.
fn is_osc_query(params: &[&[u8]]) -> bool {
    params.len() >= 2 && params.last() == Some(&b"?".as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Queries that must be dropped ===

    #[test]
    fn drops_da1() {
        assert_eq!(strip_queries(b"\x1b[c"), b"");
        assert_eq!(strip_queries(b"\x1b[0c"), b"");
    }

    #[test]
    fn drops_da2() {
        assert_eq!(strip_queries(b"\x1b[>c"), b"");
        assert_eq!(strip_queries(b"\x1b[>0c"), b"");
    }

    #[test]
    fn drops_dsr_status() {
        assert_eq!(strip_queries(b"\x1b[5n"), b"");
    }

    #[test]
    fn drops_dsr_cursor_position() {
        assert_eq!(strip_queries(b"\x1b[6n"), b"");
    }

    #[test]
    fn drops_decrqm_private() {
        assert_eq!(strip_queries(b"\x1b[?1004$p"), b"");
        assert_eq!(strip_queries(b"\x1b[?2026$p"), b"");
        assert_eq!(strip_queries(b"\x1b[?9999$p"), b"");
    }

    #[test]
    fn drops_decrqm_public() {
        assert_eq!(strip_queries(b"\x1b[4$p"), b"");
        assert_eq!(strip_queries(b"\x1b[20$p"), b"");
    }

    #[test]
    fn drops_kitty_keyboard_probe() {
        assert_eq!(strip_queries(b"\x1b[?u"), b"");
    }

    #[test]
    fn drops_osc_color_queries() {
        // OSC 11 ?  — bg color query, BEL-terminated.
        assert_eq!(strip_queries(b"\x1b]11;?\x07"), b"");
        // OSC 10 ?  — fg color query, ST-terminated.
        assert_eq!(strip_queries(b"\x1b]10;?\x1b\\"), b"");
        // OSC 12 ?  — cursor color.
        assert_eq!(strip_queries(b"\x1b]12;?\x07"), b"");
        // OSC 4;<n>;?  — palette index query.
        assert_eq!(strip_queries(b"\x1b]4;3;?\x07"), b"");
    }

    #[test]
    fn drops_window_manipulation_queries() {
        assert_eq!(strip_queries(b"\x1b[14t"), b"");
        assert_eq!(strip_queries(b"\x1b[18t"), b"");
        assert_eq!(strip_queries(b"\x1b[19t"), b"");
        assert_eq!(strip_queries(b"\x1b[21t"), b"");
    }

    #[test]
    fn drops_dcs_sequences() {
        // DECRQSS settings query — DCS, always dropped.
        assert_eq!(strip_queries(b"\x1bP$qm\x1b\\"), b"");
    }

    // === Things that must pass through unchanged ===

    #[test]
    fn keeps_printable_text() {
        assert_eq!(strip_queries(b"hello world"), b"hello world");
    }

    #[test]
    fn keeps_c0_controls() {
        assert_eq!(strip_queries(b"\r\n\t"), b"\r\n\t");
        assert_eq!(strip_queries(b"\x07"), b"\x07"); // bell
    }

    #[test]
    fn keeps_cursor_movement() {
        assert_eq!(strip_queries(b"\x1b[5;10H"), b"\x1b[5;10H"); // CUP
        assert_eq!(strip_queries(b"\x1b[2J"), b"\x1b[2J");       // ED2
        assert_eq!(strip_queries(b"\x1b[K"), b"\x1b[K");         // EL — default param
    }

    #[test]
    fn keeps_sgr_runs() {
        assert_eq!(strip_queries(b"\x1b[31m"), b"\x1b[31m");
        assert_eq!(strip_queries(b"\x1b[1;38;5;208m"), b"\x1b[1;38;5;208m");
        assert_eq!(strip_queries(b"\x1b[0m"), b"\x1b[0m");
    }

    #[test]
    fn keeps_alt_screen_switch() {
        assert_eq!(strip_queries(b"\x1b[?1049h"), b"\x1b[?1049h");
        assert_eq!(strip_queries(b"\x1b[?1049l"), b"\x1b[?1049l");
    }

    #[test]
    fn keeps_osc_title_set() {
        // OSC 0 / 1 / 2 with text — never a query, always forward.
        assert_eq!(strip_queries(b"\x1b]0;hello\x07"), b"\x1b]0;hello\x07");
        assert_eq!(strip_queries(b"\x1b]2;world\x1b\\"), b"\x1b]2;world\x1b\\");
    }

    #[test]
    fn keeps_osc_color_set() {
        // OSC 11 with rgb spec — that's a SET, not a QUERY. Forward.
        let set = b"\x1b]11;rgb:1234/5678/9abc\x07";
        assert_eq!(strip_queries(set), set);
    }

    #[test]
    fn keeps_csi_t_non_query_actions() {
        // \x1b[1t is "deiconify window" — a *command*, not a report
        // request. Forward.
        assert_eq!(strip_queries(b"\x1b[1t"), b"\x1b[1t");
        // \x1b[2t is "iconify". Forward.
        assert_eq!(strip_queries(b"\x1b[2t"), b"\x1b[2t");
    }

    #[test]
    fn keeps_save_restore_cursor() {
        // ESC 7 (save), ESC 8 (restore) — single-byte ESC sequences.
        assert_eq!(strip_queries(b"\x1b7"), b"\x1b7");
        assert_eq!(strip_queries(b"\x1b8"), b"\x1b8");
    }

    // === Mixed streams ===

    #[test]
    fn drops_query_keeps_surrounding_text() {
        // vim startup pattern: ANSI reset, OSC color query, then some text.
        let input = b"\x1b[0mhello\x1b]11;?\x07world";
        let output = strip_queries(input);
        assert_eq!(output, b"\x1b[0mhelloworld");
    }

    #[test]
    fn drops_multiple_queries() {
        let input = b"\x1b[c\x1b[5n\x1b]11;?\x07normal text\x1b[?2004$p";
        let output = strip_queries(input);
        assert_eq!(output, b"normal text");
    }

    #[test]
    fn keeps_command_csi_decscusr() {
        // \x1b[2 q is "DECSCUSR set cursor style 2" (intermediate ' ').
        // Not a DECRQM query; forward.
        assert_eq!(strip_queries(b"\x1b[2 q"), b"\x1b[2 q");
    }

    // === Realistic vim-startup sequence ===

    #[test]
    fn vim_startup_filter() {
        // What vim 8.x sends roughly on startup:
        //   - send DA1
        //   - send DSR 6
        //   - query bg color
        //   - clear screen
        //   - alt screen
        //   - set cursor position
        //   - render initial buffer (some printable text)
        let input: Vec<u8> = [
            b"\x1b[c".as_slice(),                    // DA1 query
            b"\x1b[6n",                              // DSR 6 query
            b"\x1b]11;?\x07",                        // bg color query
            b"\x1b[?1049h",                          // enter alt screen (SET, not query)
            b"\x1b[2J",                              // clear screen
            b"\x1b[1;1H",                            // cursor home
            b"~                                  ", // vim's tilde column
            b"\r\n\x1b[K",
        ]
        .concat();

        let output = strip_queries(&input);

        // No queries in output: the three queries above should all be gone.
        assert!(!output.windows(3).any(|w| w == b"\x1b[c"));
        assert!(!output.windows(3).any(|w| w == b"\x1b[6"));
        assert!(!output.windows(2).any(|w| w == b";?"));

        // Visual / state-changing content preserved.
        assert!(output.windows(8).any(|w| w == b"\x1b[?1049h"));
        assert!(output.windows(4).any(|w| w == b"\x1b[2J"));
        assert!(output.windows(2).any(|w| w == b"~ "));
        assert!(output.windows(3).any(|w| w == b"\x1b[K"));
    }

    // === Partial-sequence handling (sequences split mid-byte across reads) ===

    #[test]
    fn handles_split_query_across_chunks() {
        // Within a single strip_queries call, the parser holds state.
        // Across calls it does not (each call gets a fresh parser),
        // but eBPF events deliver contiguous chunks so this is a
        // single-call concern.
        let input = b"\x1b]11;?\x07";
        assert_eq!(strip_queries(input), b"");
    }

    #[test]
    fn vim_idle_redraw_passthrough() {
        // Once vim is running and idle, output is mostly cursor moves
        // + SGR + text. None of it should be touched.
        let input: Vec<u8> = [
            b"\x1b[1;1H".as_slice(),
            b"\x1b[7mNORMAL\x1b[27m  ",
            b"\x1b[K\r\n",
            b"some text",
            b"\x1b[2;1H",
            b"\x1b[Kmore",
        ]
        .concat();

        let output = strip_queries(&input);
        assert_eq!(output, input);
    }
}
