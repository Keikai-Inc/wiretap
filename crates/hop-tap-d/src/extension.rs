//! Local mirror of hop-core's extension wire types.
//!
//! We deliberately do **not** depend on `hop-core` directly — pulling
//! it in would drag in iroh, redb, ed25519-dalek pre-release, and
//! ~hundreds of transitive crates that hop-tap doesn't need. The
//! extension ABI is small and stable enough that mirroring it here is
//! lower-cost than cross-coupling the workspaces.
//!
//! The two pieces we mirror:
//!
//! - [`ExtMessage`] — the protocol envelope (Hello, HelloAck, Request,
//!   Response, plus stream variants we don't yet implement).
//! - [`Bootstrap`] — the TOML rendezvous file an extension daemon
//!   writes on startup so hop can discover the ipc-channel server.
//!
//! If hop-core's definitions ever drift, this file has to track them
//! byte-for-byte. To make that easier the field/variant names match
//! hop-core's exactly; bincode/serde will refuse to deserialize on
//! mismatch, surfacing the drift loudly rather than silently.

use serde::{Deserialize, Serialize};

/// One protocol message between the hop daemon and an extension daemon.
///
/// Both directions use the same enum so a single
/// `IpcSender<ExtMessage>` / `IpcReceiver<ExtMessage>` pair can carry
/// traffic each way. Variants document direction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtMessage {
    /// hop → extension: rendezvous handshake. Carries the reverse-server
    /// name the extension should connect back to.
    Hello {
        hop_version: String,
        reverse_name: String,
    },

    /// extension → hop: handshake completion + version exchange.
    HelloAck { ext_version: String },

    /// hop → extension: single request, single response.
    Request {
        request_id: u64,
        peer_id: String,
        peer_username: Option<String>,
        peer_role: String,
        payload: Vec<u8>,
    },

    /// hop → extension: open a long-running stream. Not yet implemented
    /// in hop-tap; we politely close any incoming StreamOpen in v1.
    StreamOpen {
        request_id: u64,
        peer_id: String,
        peer_username: Option<String>,
        peer_role: String,
        payload: Vec<u8>,
    },

    /// hop → extension: input bytes from a peer on an open stream.
    StreamInput { stream_id: u64, payload: Vec<u8> },

    /// hop → extension: peer-side close.
    StreamClose { stream_id: u64 },

    /// extension → hop: response to a [`Request`].
    Response {
        request_id: u64,
        ok: bool,
        payload: Vec<u8>,
    },

    /// extension → hop: stream open ack.
    StreamOpened { request_id: u64, stream_id: u64 },

    /// extension → hop: data frame.
    StreamFrame { stream_id: u64, payload: Vec<u8> },

    /// extension → hop: stream end-of-life.
    StreamClosed {
        stream_id: u64,
        reason: Option<String>,
    },
}

/// Contents of a bootstrap-rendezvous file. Written by the extension
/// daemon on startup; read by the hop daemon to discover where to
/// connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    /// ipc-channel server name (opaque string; on Unix this is the
    /// path / address of the listening socket).
    pub server_name: String,
    /// PID of the writing daemon — used to detect stale entries.
    pub pid: u32,
    /// Protocol version this daemon speaks. Compared against the
    /// manifest's `version` at handshake time.
    pub version: String,
}

#[cfg(unix)]
pub fn write_bootstrap_atomically(
    path: &std::path::Path,
    server_name: &str,
    version: &str,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path
        .parent()
        .context("bootstrap path has no parent directory")?;
    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory {}", parent.display()))?;
    }

    let bs = Bootstrap {
        server_name: server_name.to_string(),
        pid: std::process::id(),
        version: version.to_string(),
    };
    let serialized = toml::to_string(&bs).context("serializing bootstrap")?;

    let tmp_path = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&tmp_path)
        .or_else(|_| {
            // Stale tmp from a prior crash; remove and retry.
            let _ = std::fs::remove_file(&tmp_path);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o600)
                .open(&tmp_path)
        })
        .with_context(|| format!("creating temp bootstrap {}", tmp_path.display()))?;
    f.write_all(serialized.as_bytes())
        .context("writing bootstrap")?;
    f.sync_all().context("fsync bootstrap")?;
    drop(f);
    std::fs::rename(&tmp_path, path).context("rename bootstrap into place")?;
    Ok(())
}
