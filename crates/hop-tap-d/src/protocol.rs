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
    pub output_bytes: u64,
    pub input_bytes: u64,
    pub output_events: u64,
    pub input_events: u64,
    /// Milliseconds since session creation.
    pub age_ms: u64,
    /// Milliseconds since last observed activity.
    pub idle_ms: u64,
}
