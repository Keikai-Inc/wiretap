//! Re-export shim so internal callers can keep using
//! `hop_tap_d::protocol::*` paths without churn. Wire types live in
//! the standalone `hop-tap-protocol` crate so cross-workspace
//! consumers (e.g. hop-cli) can depend on them without pulling
//! hop-tap-d's heavyweight build (aya, alacritty_terminal, ebpf
//! object).

pub use hop_tap_protocol::{
    SessionInfo, TapRequest, TapResponse, TapStreamFrame, TapStreamRequest,
};
