# Render-only subscriber architecture (tmux-style)

Goal: stop forwarding raw pty bytes to subscribers. The daemon owns
the terminal-protocol boundary toward the captured app, owns a
virtual screen per pty, and serves subscribers a rendered view of
that screen. Subscribers' local terminals become dumb displays — they
never participate in the pty's terminal protocol, so their query
responses, focus events, mouse events, etc. can no longer leak
through `Inject` and corrupt the captured app's state.

This is the architectural model tmux has used since 2007 and the
reason tmux + vim has never had the bug we just hit. We already have
the building block — `alacritty_terminal::Term` per pty in the
daemon, fed by `Processor::advance(&mut term, bytes)` on every
captured output batch. The current `TapStreamFrame::Initial` already
renders that screen via `render_grid_to_bytes`. What we don't have is
**(a)** the daemon answering protocol queries on behalf of the
captured pty's terminal end, and **(b)** the live `Output` stream
flowing as render-diffs instead of raw bytes.

## Why the current design has the bug

The pty has two ends. The application end is the captured app
(vim/bash/etc) — that's settled. The terminal end is what *answers*
the protocol: what color am I, what attributes do I support, where's
the cursor, what window am I, etc. The capture is invisible to the
captured app, so as far as vim is concerned the terminal end is
whatever bob's actual terminal is at the other end of the ssh pipe.

When `tap connect` streams that pty's output to alice's terminal, two
terminals are now seeing the same pty traffic. Vim sends a query.
*Both* terminals receive it. *Both* answer. Vim's query was meant for
one answerer; the second answer arrives late, vim has moved on, and
the bytes are interpreted as keystrokes. Symptom: `:3838/0c0c/2a2a`
in vim's command line — the body of an OSC 11 color response leaking
into ex-mode.

The filter approach (parse stdin, drop terminal-side response
shapes) is a long-tail patch: every new protocol (kitty keyboard,
in-band resize, sixel queries, modify-other-keys variants) is another
filter rule. tmux's design avoids this because in tmux's world there
*is* only one terminal per pane: tmux itself.

## Target architecture

```
Captured app (vim, bash, etc.)
        ▲
        │  pty master/slave (one terminal-protocol boundary)
        ▼
hop-tap-d
  │  ├── alacritty_terminal::Term per pty (the virtual terminal)
  │  ├── Processor (vte) feeds output bytes into Term
  │  ├── ResponderPerform answers queries: writes responses
  │  │   back to the pty master fd, not to subscribers
  │  └── Renderer diffs Term grid → GridUpdate frames per subscriber
        ▲
        │  bincode-framed local socket (no raw pty bytes leave here)
        ▼
tap CLI / hop client
  │  └── Reads GridUpdate frames, repaints local terminal cells
        ▲
        │  Local stdin in raw mode (one terminal-protocol boundary)
        ▼
Operator's local terminal (alice)
```

Two terminal-protocol boundaries, **completely isolated by the
daemon's `Term`**. Each boundary has exactly one terminal at the end:
- Captured-side: hop-tap-d *is* the terminal
- Operator-side: alice's terminal is the terminal; tap CLI consumes
  its responses for its own UI (picker, compose mode), never relays
  them anywhere

## Phase 1: filter queries out of the subscriber broadcast (~80 lines)

> **Earlier draft of this section proposed a daemon-side responder
> that answered queries directly (~400 lines, similar to tmux's
> `input.c`). That was wrong for our architecture and is recorded
> in "Why we don't add a daemon-side responder" below.**

### What we actually do

In `ingest_event`'s slave→master broadcast path, run the captured
output bytes through a `vte::Parser` and **drop captured-app
queries** before forwarding to subscribers. Everything else
(printable text, cursor moves, SGR, alt-screen toggles, OSC title
sets, etc.) passes through unchanged.

The filtered byte set is bounded:

| Query                                | Wire form                  | Rationale for dropping                                                         |
|--------------------------------------|----------------------------|--------------------------------------------------------------------------------|
| DA1 (primary device attrs)           | `\x1b[c` / `\x1b[0c`       | Captured app probing device — bob's terminal already answered                  |
| DA2 (secondary device attrs)         | `\x1b[>c` / `\x1b[>0c`     | Same                                                                           |
| DSR-5 (status report request)        | `\x1b[5n`                  | "Are you ready?" — bob's terminal answered                                     |
| DSR-6 (cursor position request)      | `\x1b[6n`                  | "Where's the cursor?" — bob's terminal answered                                |
| DECRQM (mode query, all variants)    | `\x1b[<n>$p`, `\x1b[?<n>$p`| "Is mode N enabled?" — bob's terminal answered                                 |
| OSC color queries (10/11/12, 4)      | `\x1b]N;?\x07`, etc.       | "What color are you?" — bob's terminal answered                                |
| OSC palette queries                  | `\x1b]4;<n>;?\x07`         | Same, indexed                                                                  |
| Window-manipulation queries          | `\x1b[14t` / `\x1b[18t`/etc.| "What size are you?" — bob's terminal answered                                |
| Kitty keyboard probes                | `\x1b[?u`                  | "Do you do kitty kbd?" — bob's terminal will (or won't) answer                |
| DECRQSS (settings query)             | `\x1bP$q...\x1b\\`         | DCS — bob's terminal will (or won't) answer                                    |

Identification is by escape-sequence shape, not by tracking app
intent. The vte parser tells us "this is a CSI ending in `c`" or
"this is an OSC starting with `11;?`"; we match against the table
and drop.

### Why this works

Bob's actual terminal is connected to bob's pty's master and has
been answering all these queries since the session opened. The
kernel's pty subsystem routes vim's query bytes from the slave to
the master, where bob's terminal reads them and writes responses
back. That conversation is **invisible** to subscribers in the
current design (responses are master→slave, only slave→master
output is broadcast). All Phase 1 does is prevent vim's queries
from leaking to subscribers — which means subscribers' terminals
don't see queries, never volunteer responses, and the only thing
on the wire from alice → daemon → master_fd is real keystrokes.

**Architecture in one sentence**: subscribers don't see the
captured app's questions, so their terminals don't volunteer
answers.

### Why we don't add a daemon-side responder

Originally the plan was to make the daemon itself answer queries
(tmux-style), then keep broadcasting raw output to subscribers.
That breaks because:

1. **Bob's actual terminal at the far end of the pty is still
   answering.** The eBPF capture is observational — we can't
   "unsubscribe" bob's terminal from the pty. So if our daemon
   also answers, vim gets *two* responses to every query.
   Whichever arrives second lands as keystroke garbage. That's
   the same class of bug as the original, just from a different
   double-up.

2. **Subscribers' terminals would still see the raw query in the
   broadcast** and respond a third time. So adding a daemon
   answerer doesn't even reduce the count of stray responses.

The architectural condition under which "daemon answers" is
correct is the tmux model: there's only one terminal, and it's the
daemon (pty's master is held by the daemon, not by an external
terminal emulator). hop-tap doesn't own the pty — it observes one
that already has a terminal at the other end. So daemon-as-
responder is wrong here. *Phase 2's render-only stream changes
this implicitly* — subscribers see cells, not raw bytes, so the
question of "who answers" disappears for that side.

### Implementation shape

```rust
// In ingest_event, slave→master case:
let live_for_subscribers = if state.subscribers.is_empty() {
    None
} else {
    Some(strip_queries(&event.data[..captured]))
};
```

`strip_queries` runs a `vte::Parser` driving a small `Perform`
that:
- buffers bytes verbatim while in ground state (passthrough)
- on dispatch of a CSI / OSC / DCS, classifies by introducer +
  terminator + first param-byte (`?`-as-query for OSC)
- if classification matches the table above, *discards* the
  buffered bytes for that sequence
- otherwise commits them to the output

Same vte machinery as the shelved stdin filter, but in the
**broadcast** direction with the **inverse** classification (drop
queries, keep responses-and-everything-else).

### Tests

Unit tests in `responder.rs`'s home (or a new `query_filter.rs`):
- Each query in the table → dropped, output empty
- Plain printable text → forwarded byte-for-byte
- Cursor moves, SGR runs → forwarded byte-for-byte
- OSC title set (no `?`) → forwarded
- Mixed stream (text + query + text) → query stripped, text intact
- Partial-sequence-across-reads → handled by parser state

Integration test target: drive `vim --clean` through a captured
session, scrape alice's tap stdout, assert no `\x1b]11;?` (or
similar query bytes) reach her terminal.

### What was the unused `responder.rs` for?

Phase 1's prior misadventure produced
`crates/hop-tap-d/src/responder.rs` (a `ResponderListener` /
`Palette` pair that turns alacritty's `Event` stream into pty
responses). That module is **kept in tree, unused** because it
slots into Phase 2 directly: when subscribers are render-only and
the daemon owns the protocol toward the captured app, the
`ResponderListener` is the right way to source query answers from
alacritty's existing logic. Until Phase 2 lands, it compiles
cleanly but isn't wired up.

### Test apps (regression matrix)

The Phase 1 filter is "correct" if these apps run cleanly under a
captured session with one or more subscribers attached:

| App                   | Queries known to send                                  | Bug-mode if queries leak                  |
|-----------------------|--------------------------------------------------------|-------------------------------------------|
| **vim**               | DA1, DA2, DSR 6, OSC 10/11, OSC 12 (cursor color)      | OSC color responses appear as `:3838/0c0c/2a2a` in ex mode (the bug we hit) |
| **htop**              | DA1, DSR 6, CSI 18 t, OSC 10/11                        | Status bar misalignment, color glitches when subscribers attach |
| **Claude Code (TUI)** | DA1, DA2, OSC 10/11, DECRQM-2026, bracketed paste      | Inline pastes corrupt, synchronized-output fallbacks |
| **nvim**              | All of vim's + DECRQM-2017 (kitty kbd query)           | Same as vim + kitty kbd fallback issues   |
| **less**              | DA1, DSR 6                                             | Small surface; mostly OK even unfiltered  |

For each app, the test is: launch in a captured session, attach via
`tap connect`, exercise normal usage. None of the symptoms above
should appear. The pre-Phase-1 filter behavior is the reference for
what a "broken" run looks like (the OSC color leak we documented in
the bug report).

## Phase 2: render-only live stream (~1500 lines)

The bigger change. Replace `TapStreamFrame::Output(Vec<u8>)` with
`TapStreamFrame::GridUpdate { ... }`. After each ingest, diff the new
grid state against the last sent state for *that* subscriber, encode
the diff, push it down the channel.

### Frame format

```rust
enum TapStreamFrame {
    Initial { rows: u16, cols: u16, replay_bytes: Vec<u8> },
    GridUpdate {
        // Cells that changed since the last frame this subscriber
        // received. Coalesced into runs by row to keep encoding
        // small for typical updates (one prompt repaint = one run).
        runs: Vec<CellRun>,
        // Cursor moved-to position, if changed.
        cursor: Option<(u16, u16)>,
        // Cursor visible / blink state, if changed.
        cursor_style: Option<CursorStyle>,
        // Terminal mode bits (alt-screen, app-cursor, mouse-on, etc.)
        mode_changes: Option<TermMode>,
    },
    Resize { rows: u16, cols: u16 },
    Closed { reason: Option<String> },
}

struct CellRun {
    row: u16,
    col_start: u16,
    cells: Vec<Cell>, // glyph + fg + bg + flags
}
```

Subscribers reconstruct by applying runs cell-by-cell to a local
shadow grid, then re-emitting changed regions to their stdout via
cursor-positioning + SGR (same primitives as `render_grid_to_bytes`
but only for dirty cells).

### Diff algorithm

Cheapest path: alacritty exposes `damage` info via `term.damage()`,
which returns dirty rows/columns since the last call. We use that
plus a local "previous grid" snapshot per subscriber to encode diffs.
For unchanged frames (between vim keystrokes, no output), the
GridUpdate is empty and we skip sending it entirely.

Damage tracking has to be per-subscriber because subscribers can
attach at different times — what's "dirty" since *your* last frame
is different from what's dirty since *my* last frame. Solution: each
subscriber owns a `previous_grid: Grid<Cell>` that we diff against
on every send. Fast: most frames touch <10 cells.

### Cursor, scroll, alt-screen

- Cursor: send `cursor: Some(pt)` only when it moved between frames.
- Scroll: alacritty's grid handles scroll regions internally. The
  result is just "all rows changed by one offset" — encode as a
  single `Resize-style scroll-up` op? Or just blast the changed
  cells. Start with the latter; optimize if profiling demands it.
- Alt-screen: vim/less/htop enter alt screen with `\x1b[?1049h`. The
  daemon's `Term.mode()` reflects this. Subscribers track it via
  `mode_changes` and switch their local terminal's screen
  accordingly. On detach, subscriber restores primary screen.

### Resize semantics

Capture-side resize (TIOCSWINSZ on the pty) → daemon resizes its
`Term`, broadcasts `Resize { rows, cols }`. Subscribers receive,
adjust their local rendering region (probably letterbox if their
terminal is bigger; truncate or scroll if smaller).

Subscriber-side resize (alice resizes her terminal) → tap CLI
notices via SIGWINCH, but **does not** propagate to the daemon.
Subscriber's terminal size is irrelevant to the captured pty.
Subscriber just re-renders the grid into the new local size.

### Mouse forwarding

If the captured app enables mouse reporting (`\x1b[?1000h` etc.),
the daemon's `Term.mode()` reflects it. Subscribers see the mode bit
in `mode_changes` and may choose to enable mouse reporting on their
*local* terminal. When a subscriber's local terminal emits a mouse
event on stdin, the tap CLI parses it (its own mini-parser),
re-encodes it for the captured pty's expected mouse protocol, and
sends it via `Inject` — *now* it's structured input, not a leaking
escape sequence. Same primitive but the encoding/decoding is
explicit, not accidental.

### Tap CLI changes

- Drop the raw-bytes-to-stdout path. Implement a "renderer" that
  reads `GridUpdate` frames, applies them to a local shadow grid,
  and emits cursor-positioned SGR runs for the dirty cells.
- The stdin pipe still feeds `Inject` for keystrokes, but with no
  raw pty traffic on the wire there's no terminal-response leak.
  The local terminal's spontaneous events (focus/mouse/paste) still
  arrive on stdin — handle them via a small explicit parser, not the
  filter approach. Mouse/paste get re-encoded toward the captured
  pty if the captured app wants them; focus events are dropped (or
  re-encoded if the captured app enabled focus reporting).

### Open questions for Phase 2

- **Frame rate**: send a GridUpdate per ingest batch, or coalesce on
  a timer (16ms = 60fps)? Coalesce — vim renders in bursts, no point
  emitting 30 GridUpdates per second.
- **Wire size**: cell-by-cell diff with attributes can be chunky. RLE
  the runs by attribute. Bincode handles this cheaply. Order of magn
  goal: typical vim-keystroke frame ≤ 200 bytes on the wire.
- **Backpressure**: slow subscriber — drop frames or block ingest?
  Drop, with a `LastSyncedSeq` that lets the subscriber request a
  full re-render on reconnect.
- **Hop bridge**: hop-tap-d's stream goes over hop's QUIC channel
  for remote use. Frame format is the same; hop just forwards
  bincode messages. No change there.

## Phase 3: cleanup (~1 day)

- Drop the `TapStreamFrame::Output(Vec<u8>)` variant. Existing
  Initial-frame replay path stays — it becomes "render the current
  grid as a single full-screen GridUpdate" plus the alt-screen
  preamble.
- The stdin filter we wrote becomes a tiny parser used for *tap*'s
  own UI input (picker, compose mode), and a structured mouse/paste
  decoder for re-encoding toward the captured pty. The
  terminal-response classification logic disappears — local
  terminal isn't responding to anyone.
- Document the architecture in CLAUDE.md so future work doesn't
  reintroduce raw-byte forwarding paths.

## Migration plan

Phase 1 ships behind no flag — it strictly *adds* daemon-side
protocol responses, doesn't change the wire format. Old tap clients
keep working. **Vim bug closes here.**

Phase 2 ships behind `--render-only` (or by sending a new request
type, `SubscribeGrid` vs `Subscribe`). Old clients use the old
`Output(bytes)` path; new clients use `GridUpdate`. Once the new
path is proven on real workloads (vim, htop, less, fzf, nvim, tmux
inside tap), we delete the old path in Phase 3.

A clean version of this would land Phase 1 first, soak for a week or
two on the bug we just fixed, then Phase 2 as a separate effort with
its own design pass. We don't have to commit to the full Phase 2
scope today — Phase 1 is well-defined enough to start on its own.

## What we're not doing

- **Not** rewriting the daemon's ingestion or eBPF capture. The
  output side of Phase 1 (responses written to master_fd) reuses
  existing infrastructure.
- **Not** changing the `Inject` path's wire format — keystrokes
  from subscribers still flow as raw bytes into master_fd.
  Subscribers send fewer of them now (no terminal-response
  contamination), but the path itself is unchanged.
- **Not** building a real-tmux equivalent. We're not implementing
  windows, panes, status bars, key bindings, command mode, or any
  of the multiplexer surface area. We're borrowing tmux's
  *protocol-layer architecture*, not its UX.

## Open questions to resolve before code

Decided (per discussion 2026-04-30):
- **Scope**: Phase 1 minimum viable subset. Vim, htop, Claude Code
  are the regression targets; cover the queries those send (DA1,
  DA2, DSR 5/6, OSC 10/11, DECRQM-1004/1006/2004/2026, CSI 18 t).
  Defer cursor color, palette, pixel-size, theme reports, sixel,
  kitty kbd until a real app actually needs them.
- **Behavior model**: copy tmux's `input.c` answer-set verbatim. For
  any query not in the supported list, **silently ignore** — tmux
  does, modern apps handle no-reply gracefully via timeouts.

Still to settle:
- **`RespondingTerm` placement**: own module
  (`hop-tap-d/src/responder.rs`) for testability — the responder is
  self-contained and benefits from in-memory pty substitution in
  unit tests.
- **Color palette**: hardcode alacritty defaults for the initial
  cut; configurable via daemon config in a follow-up. Don't block
  Phase 1 on this.
- **Tests**: in-memory `Write` impl as the master-fd substitute,
  drive `Processor` with query bytes, assert the response bytes
  written. One test per supported query, plus negative tests
  (e.g., `\x1b[?9999$p` produces no output).
