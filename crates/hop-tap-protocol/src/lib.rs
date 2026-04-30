//! Wire types for the hop-tap extension subprotocol.
//!
//! These types are the contract between hop-tap-d (the extension
//! daemon) and any caller that wants to ask it for sessions or
//! subscribe to live output. The only callers we ship are:
//!
//! - **`hop-tap-probe`** — bundled in this workspace; talks ipc-channel
//!   directly to a running hop-tap-d for development / smoke testing.
//! - **`hop-cli`** — the production path; relays through hop's
//!   extension dispatcher. Pulls this crate in via path dependency.
//!
//! The wire format is bincode 2 with `serde`. Encode every request /
//! response with `bincode::serde::encode_to_vec(value, bincode::config::standard())`,
//! decode with `bincode::serde::decode_from_slice`.
//!
//! ## Why a separate crate?
//!
//! Originally this lived inside hop-tap-d as a private module. Once
//! hop-cli grew a `tap` verb we needed a single source of truth for
//! the wire types — extracting prevents silent drift if a field is
//! renamed in one place but not the other. The crate is intentionally
//! tiny (just serde derives, no logic) so cross-workspace consumers
//! don't pay a transitive cost.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod local;

/// Peer-initiated request. Carried inside `ExtMessage::Request.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapRequest {
    /// List currently-active sessions. Returns [`TapResponse::SessionList`].
    List,
    /// Snapshot the visible screen for a given pty index. Returns
    /// [`TapResponse::Snapshot`] on success or [`TapResponse::Error`]
    /// if the index isn't currently being captured.
    Snapshot { pty_index: i32 },
    /// Write `bytes` into the captured session's pty master, as if
    /// the user typed them. Authorized only for the session's opener
    /// or a creator-role peer — read scope alone is not enough. The
    /// daemon clones the master fd from whoever holds it (sshd, tmux,
    /// the local terminal) via `pidfd_getfd` and writes through that.
    Inject { pty_index: i32, bytes: Vec<u8> },
    /// Send a signal to the session's opener (the shell). Default is
    /// SIGHUP — the same signal a closed terminal emulator sends, so
    /// well-behaved shells exit cleanly and propagate to children.
    /// If `force` is set we send SIGKILL instead.
    /// Same write-scope authorization as Inject.
    Kill { pty_index: i32, force: bool },
}

/// Daemon's reply. Carried inside `ExtMessage::Response.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapResponse {
    SessionList(Vec<SessionInfo>),
    Snapshot {
        pty_index: i32,
        rows: u16,
        cols: u16,
        /// One entry per row, top-to-bottom, with no trailing CR/LF.
        /// Trailing whitespace is preserved so the caller can choose
        /// whether to display a 24-row block verbatim or trim.
        contents: Vec<String>,
    },
    /// Reply to a successful [`TapRequest::Inject`]. `bytes_written`
    /// can be smaller than the requested length on a short write
    /// (rare for ptys; the kernel buffer is typically large enough).
    Injected {
        pty_index: i32,
        bytes_written: usize,
    },
    /// Reply to a successful [`TapRequest::Kill`]. Reports which
    /// pid we signaled and the signal number used.
    Killed {
        pty_index: i32,
        pid: u32,
        signal: i32,
    },
    Error(String),
}

/// One row of a [`TapResponse::SessionList`].
///
/// Mirrors the fields of `SessionState` we expose to peers. Internal
/// fields (the alacritty `Term`, the parser, raw byte counts beyond
/// what we surface) stay daemon-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub pty_index: i32,
    /// Sticky identity captured the first time the daemon saw this
    /// pty. For sessions that started after the daemon, this is the
    /// controlling shell — i.e., who logged in. Diverges from
    /// `last_*` whenever a privileged sub-command (sudo, su) writes
    /// into the same pty. **Use `opener_*` for authorization
    /// decisions** (e.g. "is this peer allowed to view this
    /// session"); use `last_*` for diagnostic display.
    pub opener_pid: u32,
    pub opener_comm: String,
    pub opener_uid: u32,
    pub opener_gid: u32,
    pub opener_username: Option<String>,
    /// Most recent writer — what's actually emitting bytes right
    /// now. Updates on every event.
    pub last_pid: u32,
    pub last_comm: String,
    pub last_uid: u32,
    pub last_gid: u32,
    /// Best-effort username resolution via `getpwuid_r`. None if
    /// the uid doesn't exist in the daemon's view of /etc/passwd
    /// (common under PID/user namespacing).
    pub last_username: Option<String>,
    pub output_bytes: u64,
    pub input_bytes: u64,
    pub output_events: u64,
    pub input_events: u64,
    /// Milliseconds since session creation.
    pub age_ms: u64,
    /// Milliseconds since last observed activity.
    pub idle_ms: u64,
}

/// Carried inside `ExtMessage::StreamOpen.payload`. The peer asks
/// to subscribe to live updates from a specific session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapStreamRequest {
    Subscribe { pty_index: i32 },
}

/// Carried inside `ExtMessage::StreamFrame.payload`. The first frame
/// after `StreamOpened` is always [`TapStreamFrame::Initial`] which
/// catches the subscriber up to current state; subsequent frames
/// stream live as the session produces output.
///
/// Wire fidelity is byte-level: `Output(bytes)` is the raw kernel-
/// captured slave→master write, including any escape sequences. The
/// subscriber writes those bytes to its own terminal verbatim and
/// the receiving terminal interprets them — same path the original
/// shell→pty bytes would take. No client-side emulator round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapStreamFrame {
    /// Sent once, immediately after `StreamOpened`. Carries the
    /// kernel's current view of the session's dimensions plus a
    /// `replay_bytes` payload synthesised from the daemon's grid
    /// state — write it to your terminal first so the screen is
    /// in sync before live frames start arriving.
    Initial {
        rows: u16,
        cols: u16,
        replay_bytes: Vec<u8>,
    },
    /// Live slave→master output bytes since the last frame. Written
    /// verbatim to the subscriber's terminal.
    Output(Vec<u8>),
    /// The kernel-reported dimensions changed (TIOCSWINSZ). The
    /// subscriber may or may not propagate this to its own terminal
    /// — semantically it's "this is the size the underlying session
    /// thinks it has," not "resize your viewport now."
    Resize { rows: u16, cols: u16 },
}
