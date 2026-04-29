//! Library half of `hop-tap-d`. Re-exports the protocol/wire-format
//! modules so binaries in this package (the daemon at `src/main.rs`
//! and the probe at `src/bin/probe.rs`) and any future external
//! consumers can share the same definitions.
//!
//! Everything else in `src/main.rs` is daemon-private — it bundles
//! aya, the eBPF object, the session table, and the tokio runtime,
//! all of which are gated to Linux at runtime.

pub mod extension;
pub mod protocol;
