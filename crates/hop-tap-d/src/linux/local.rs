//! Local Unix-socket listener for the standalone `tap` CLI.
//!
//! Authentication on this socket is `SO_PEERCRED`: the kernel
//! tells us who's connecting (uid/gid/pid). The daemon constructs
//! a synthetic `PeerContext` from that — uid 0 → "creator" role
//! (sees everything), other uids → "peer" role gated by
//! `opener_username`. There's no on-the-wire identity claim; the
//! caller has no way to lie about who they are.
//!
//! Wire format: length-prefixed bincode of
//! [`hop_tap_protocol::local::LocalMessage`]. See that module for
//! the protocol shape.

use std::sync::Arc;

use anyhow::{Context, Result};
use hop_tap_protocol::{
    local::LocalMessage, TapRequest, TapResponse, TapStreamRequest,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Maximum bincode payload size we accept on the local socket.
/// Mirrors hop-core's frame cap so a hostile / runaway local
/// client can't trigger unbounded allocation.
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Spin up the local-socket listener. Binds to `socket_path`,
/// chmod 0666 so any local user can connect, then accept-loop
/// forever — each connection gets its own task that runs through
/// the same `handle_tap_request` / `register_subscriber` paths
/// the hop extension uses.
///
/// `peer_for_uid` constructs a `PeerContext` from the connecting
/// uid. That callback lives in main.rs because it imports
/// `lookup_username`; threading it in keeps this module
/// transport-only.
pub(crate) async fn run_local_listener<F>(
    socket_path: std::path::PathBuf,
    sessions: super::SessionTable,
    streams: super::StreamsMap,
    next_stream_id: Arc<std::sync::atomic::AtomicU64>,
    peer_for_uid: F,
) -> Result<()>
where
    F: Fn(u32, Option<i32> /* pid */) -> super::PeerContext + Send + Sync + Clone + 'static,
{
    // If a previous run left a socket file behind, remove it. Bind
    // would otherwise EADDRINUSE.
    let _ = std::fs::remove_file(&socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o666))
        .with_context(|| format!("chmod 0666 {}", socket_path.display()))?;
    info!(path = %socket_path.display(), "local socket listening (mode 0666)");

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "local accept failed");
                continue;
            }
        };
        let cred = match stream.peer_cred() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "SO_PEERCRED failed; closing connection");
                continue;
            }
        };
        let uid = cred.uid();
        // peer_cred().pid() is Option<i32> on tokio's Unix sockets —
        // the kernel only fills it in when the SCM_CREDENTIALS path is
        // available, but for local AF_UNIX it always is.
        let pid = cred.pid();
        let peer = peer_for_uid(uid, pid);
        debug!(uid, pid = ?pid, role = %peer.peer_role, "local connection");

        let sessions = sessions.clone();
        let streams = streams.clone();
        let next_stream_id = next_stream_id.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, peer, sessions, streams, next_stream_id).await
            {
                debug!(error = %e, "local connection ended");
            }
        });
    }
}

async fn handle_connection(
    stream: UnixStream,
    peer: super::PeerContext,
    sessions: super::SessionTable,
    streams: super::StreamsMap,
    next_stream_id: Arc<std::sync::atomic::AtomicU64>,
) -> Result<()> {
    let cfg = bincode::config::standard();
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    // into_split: owned halves so the writer task can outlive
    // handle_connection's stack frame.
    let (mut read_half, mut write_half) = stream.into_split();

    // Per-connection state: forwarder tasks for any streams we've
    // opened. We don't need to track them by stream_id — when this
    // connection drops, the forwarder tasks notice their write_half
    // is gone and exit.
    //
    // We do need a way for forwarder tasks to write back to the
    // socket. Easiest: forwarders push outbound LocalMessages onto
    // a single mpsc; one task drains it and writes to write_half.
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<LocalMessage>();

    // Spawn the writer task. Drains out_rx, writes length-prefixed
    // bincode to write_half.
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let bytes = match bincode::serde::encode_to_vec(&msg, cfg) {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, "encode LocalMessage");
                    continue;
                }
            };
            let len = bytes.len() as u32;
            if write_half.write_all(&len.to_be_bytes()).await.is_err() {
                break;
            }
            if write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    // Read loop.
    loop {
        let mut len_buf = [0u8; 4];
        if read_half.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            warn!(len, "local frame exceeds MAX_FRAME_SIZE; closing");
            break;
        }
        buf.resize(len, 0);
        if read_half.read_exact(&mut buf).await.is_err() {
            break;
        }
        let (msg, _): (LocalMessage, _) = match bincode::serde::decode_from_slice(&buf, cfg) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "decode LocalMessage");
                continue;
            }
        };

        match msg {
            LocalMessage::Call {
                request_id,
                payload,
            } => {
                let resp = handle_call(&sessions, &streams, &peer, payload);
                let _ = out_tx.send(LocalMessage::Reply {
                    request_id,
                    payload: resp,
                });
            }
            LocalMessage::Subscribe {
                request_id,
                payload,
            } => {
                handle_subscribe(
                    &sessions,
                    &streams,
                    &next_stream_id,
                    &peer,
                    request_id,
                    payload,
                    out_tx.clone(),
                );
            }
            // Inbound messages we don't accept from clients. The
            // wire protocol uses the same enum in both directions
            // for symmetry; these arms catch a misbehaving client.
            LocalMessage::Reply { .. }
            | LocalMessage::StreamOpened { .. }
            | LocalMessage::StreamFrame { .. }
            | LocalMessage::StreamClosed { .. } => {
                warn!("client sent server-direction LocalMessage; ignoring");
            }
        }
    }

    drop(out_tx);
    let _ = writer_task.await;
    Ok(())
}

fn handle_call(
    sessions: &super::SessionTable,
    streams: &super::StreamsMap,
    peer: &super::PeerContext,
    req: TapRequest,
) -> TapResponse {
    super::handle_tap_request(sessions, streams, peer, req)
}

fn handle_subscribe(
    sessions: &super::SessionTable,
    streams: &super::StreamsMap,
    next_stream_id: &Arc<std::sync::atomic::AtomicU64>,
    peer: &super::PeerContext,
    request_id: u64,
    req: TapStreamRequest,
    out_tx: mpsc::UnboundedSender<LocalMessage>,
) {
    let TapStreamRequest::Subscribe {
        pty_index,
        viewport_rows,
        viewport_cols,
    } = req;
    match super::register_subscriber(
        sessions,
        streams,
        next_stream_id,
        peer,
        pty_index,
        viewport_rows,
        viewport_cols,
    ) {
        Err(reason) => {
            let _ = out_tx.send(LocalMessage::StreamClosed {
                stream_id: request_id,
                reason: Some(reason),
            });
        }
        Ok(super::SubscribeOk { stream_id, rx }) => {
            let _ = out_tx.send(LocalMessage::StreamOpened {
                request_id,
                stream_id,
            });
            let streams = streams.clone();
            let sessions = sessions.clone();
            tokio::spawn(async move {
                forward_to_local(stream_id, pty_index, rx, out_tx, streams, sessions).await;
            });
        }
    }
}

/// Per-stream forwarder for local connections. Drains
/// SubscriberMsgs and converts each to LocalMessage::StreamFrame /
/// StreamClosed, then sends to the connection's writer task.
async fn forward_to_local(
    stream_id: u64,
    pty_index: i32,
    mut rx: mpsc::UnboundedReceiver<super::SubscriberMsg>,
    out_tx: mpsc::UnboundedSender<LocalMessage>,
    streams: super::StreamsMap,
    sessions: super::SessionTable,
) {
    while let Some(msg) = rx.recv().await {
        match msg {
            super::SubscriberMsg::Frame(frame) => {
                if out_tx
                    .send(LocalMessage::StreamFrame {
                        stream_id,
                        payload: frame,
                    })
                    .is_err()
                {
                    break;
                }
            }
            super::SubscriberMsg::Close(reason) => {
                let _ = out_tx.send(LocalMessage::StreamClosed { stream_id, reason });
                break;
            }
        }
    }
    super::cleanup_stream(stream_id, pty_index, &streams, &sessions);
}
