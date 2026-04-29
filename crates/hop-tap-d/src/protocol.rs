//! hop-tap subprotocol carried inside `ExtMessage::Request.payload` /
//! `ExtMessage::Response.payload`.
//!
//! The Hop extension framework treats payloads as opaque bytes — each
//! extension defines its own framing. We use bincode 2 (with serde) to
//! match what hop-core uses for its own message bodies.
//!
//! ## Wire scheme
//!
//! Request:  `bincode::serde::encode_to_vec(&TapRequest, ..)`
//! Response: `bincode::serde::encode_to_vec(&TapResponse, ..)`
//!
//! Decode with `bincode::serde::decode_from_slice` and `bincode::config::standard()`.
//!
//! Phase 1.7 carries two operations:
//! - [`TapRequest::List`] → enumerate active sessions.
//! - [`TapRequest::Snapshot`] → return current screen contents for a
//!   given pty index as a row-by-row plaintext array.
//!
//! Streaming subscriptions land later — they map onto `ExtMessage::StreamOpen`
//! / `StreamFrame` / `StreamClosed` and require a different shape.

use serde::{Deserialize, Serialize};

/// Peer-initiated request. Carried inside `ExtMessage::Request.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapRequest {
    /// List currently-active sessions. Returns [`TapResponse::SessionList`].
    List,
    /// Snapshot the visible screen for a given pty index. Returns
    /// [`TapResponse::Snapshot`] on success or [`TapResponse::Error`]
    /// if the index isn't currently being captured.
    Snapshot { pty_index: i32 },
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
    pub last_pid: u32,
    pub last_comm: String,
    /// Last observed real uid of a writer in this session. The
    /// "owner" semantics here are deliberately weak: a sudo'd
    /// command shifts last_uid to 0 mid-session, which is
    /// accurate (the bytes really came from a uid=0 process) but
    /// not the same as "who logged in." A future phase can record
    /// the controlling process's uid separately at session
    /// creation time.
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
    /// recent byte history (rolling buffer; size bounded by the
    /// daemon) the client should write to its terminal first so it
    /// catches up to the current screen state.
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
