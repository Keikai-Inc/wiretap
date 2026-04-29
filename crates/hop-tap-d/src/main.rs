//! `hop-tap-d` — userspace daemon for the hop-tap extension.
//!
//! Loads the kernel-side eBPF program (compiled separately by
//! `hop-tap-ebpf` with vlad's rustc fork), attaches its kprobes /
//! tracepoints, and reads captured TTY events from per-CPU perf
//! arrays. Maintains an off-screen `termwiz::Surface` per session so
//! it can produce a "snapshot" payload (escape sequences sufficient
//! to reproduce the current screen on a fresh terminal) when a peer
//! subscribes.
//!
//! For Phase 1.1, this is just a stub that prints a startup line and
//! exits. Subsequent sub-phases wire in:
//!
//!   1.2: load the eBPF object and read PingEvents from a perf array
//!   1.5: session table, lifecycle tracking
//!   1.6: termwiz Surface per session, snapshot generation
//!   1.7: ipc-channel server, bootstrap file, ExtMessage handling

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "hop-tap-d starting"
    );

    // TODO(1.2): load eBPF object via aya, attach kprobes, spawn perf-array reader.
    // TODO(1.6): construct termwiz Surface map.
    // TODO(1.7): bind IpcOneShotServer, write bootstrap file, handle ExtMessages.

    info!("phase 1.1 skeleton — no work yet, exiting");
    Ok(())
}
