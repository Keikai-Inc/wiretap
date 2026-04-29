//! `hop-tap-probe` — minimal hop-side simulator for `hop-tap-d`.
//!
//! Reads a `hop-tap-d` bootstrap file, performs the
//! Hello/HelloAck handshake, sends a single `TapRequest`, prints the
//! `TapResponse`. Used in lieu of running a real hop daemon during
//! Phase 1.7 development; production CLI integration lives in
//! `hop-cli` (separate repo) once the Hop-side `tap` verb is wired.
//!
//! The bootstrap file is a TOML document hop-tap-d writes on startup
//! when invoked with `--bootstrap`:
//!
//! ```toml
//! server_name = "/tmp/.ipc-channel-…"
//! pid         = 12345
//! version     = "0.1.0"
//! ```

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hop_tap_d::extension::{Bootstrap, ExtMessage};
use hop_tap_d::protocol::{TapRequest, TapResponse, TapStreamFrame, TapStreamRequest};
use ipc_channel::ipc::{IpcOneShotServer, IpcReceiver, IpcSender};
use std::io::Write;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "hop-tap protocol probe (stand-in for the hop daemon)")]
struct Args {
    /// Path to the bootstrap rendezvous file written by hop-tap-d.
    #[arg(long)]
    bootstrap: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Send `TapRequest::List` and pretty-print the session table.
    List,
    /// Send `TapRequest::Snapshot { pty_index }` and pretty-print
    /// the row-by-row screen contents.
    Snapshot {
        #[arg(long = "pty")]
        pty_index: i32,
    },
    /// Subscribe to a session's live byte stream. Replays recent
    /// history first, then writes each captured chunk to stdout
    /// verbatim — your terminal interprets the escape sequences
    /// natively, so the session renders the same way it would for
    /// the original user.
    Watch {
        #[arg(long = "pty")]
        pty_index: i32,
    },
}

fn main() -> Result<()> {
    // Logs go to stderr so `watch` can stream raw session bytes to
    // stdout without log lines interleaving them.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();

    let bs_text = std::fs::read_to_string(&args.bootstrap)
        .with_context(|| format!("reading bootstrap {}", args.bootstrap.display()))?;
    let bs: Bootstrap = toml::from_str(&bs_text).context("parsing bootstrap TOML")?;
    info!(
        path = %args.bootstrap.display(),
        ext_pid = bs.pid,
        ext_version = %bs.version,
        "read bootstrap"
    );

    // Reverse server: ext → hop direction. We bind first, then pass
    // the name in Hello so the extension can connect back.
    let (reverse_server, reverse_name) =
        IpcOneShotServer::<ExtMessage>::new().context("creating reverse server")?;

    // hop → ext direction: connect to ext's published server name and
    // immediately send Hello as the first (one-shot) message.
    let tx_to_ext: IpcSender<ExtMessage> =
        IpcSender::connect(bs.server_name).context("connecting to extension")?;
    tx_to_ext
        .send(ExtMessage::Hello {
            hop_version: format!("hop-tap-probe/{}", env!("CARGO_PKG_VERSION")),
            reverse_name,
        })
        .context("sending Hello")?;

    // Wait for HelloAck on the reverse channel. The first message
    // accept() returns IS the HelloAck.
    let (rx_from_ext, hello_ack) =
        reverse_server.accept().context("waiting for HelloAck")?;
    match hello_ack {
        ExtMessage::HelloAck { ext_version } => {
            info!(%ext_version, "handshake complete");
        }
        other => bail!("expected HelloAck, got {:?}", other),
    }

    let cfg = bincode::config::standard();
    match args.cmd {
        Cmd::List => one_shot(tx_to_ext, rx_from_ext, TapRequest::List),
        Cmd::Snapshot { pty_index } => {
            one_shot(tx_to_ext, rx_from_ext, TapRequest::Snapshot { pty_index })
        }
        Cmd::Watch { pty_index } => {
            // Send the StreamOpen, render frames as they arrive.
            let payload = bincode::serde::encode_to_vec(
                &TapStreamRequest::Subscribe { pty_index },
                cfg,
            )
            .context("encoding TapStreamRequest")?;
            let request_id = 1;
            tx_to_ext
                .send(ExtMessage::StreamOpen {
                    request_id,
                    peer_id: "probe".into(),
                    peer_username: Some("probe".into()),
                    peer_role: "creator".into(),
                    payload,
                })
                .context("sending StreamOpen")?;
            watch_loop(rx_from_ext, request_id)
        }
    }
}

fn one_shot(
    tx_to_ext: IpcSender<ExtMessage>,
    rx_from_ext: IpcReceiver<ExtMessage>,
    req: TapRequest,
) -> Result<()> {
    let cfg = bincode::config::standard();
    let payload = bincode::serde::encode_to_vec(&req, cfg).context("encoding TapRequest")?;
    let request_id = 1;
    tx_to_ext
        .send(ExtMessage::Request {
            request_id,
            peer_id: "probe".into(),
            peer_username: Some("probe".into()),
            peer_role: "creator".into(),
            payload,
        })
        .context("sending Request")?;

    loop {
        let msg = rx_from_ext.recv().context("recv from extension")?;
        match msg {
            ExtMessage::Response {
                request_id: rid,
                ok,
                payload,
            } if rid == request_id => {
                if !ok {
                    warn!("extension returned ok=false");
                }
                let (resp, _): (TapResponse, _) = bincode::serde::decode_from_slice(&payload, cfg)
                    .context("decoding TapResponse")?;
                print_response(&resp);
                return Ok(());
            }
            other => warn!(?other, "ignoring non-matching message"),
        }
    }
}

/// Live-watch loop. Awaits StreamOpened, then prints each StreamFrame
/// payload to stdout as raw bytes. Terminates on StreamClosed or
/// receiver disconnect.
///
/// We deliberately don't trap Ctrl-C here — process exit closes the
/// ipc-channel, the daemon notices and removes the subscriber on its
/// next attempt. A polished UI would send `StreamClose` proactively;
/// for the probe we stay minimal.
fn watch_loop(rx_from_ext: IpcReceiver<ExtMessage>, request_id: u64) -> Result<()> {
    let cfg = bincode::config::standard();
    let mut stdout = std::io::stdout().lock();
    let mut stream_id: Option<u64> = None;
    loop {
        let msg = rx_from_ext.recv().context("recv from extension")?;
        match msg {
            ExtMessage::StreamOpened {
                request_id: rid,
                stream_id: sid,
            } if rid == request_id => {
                eprintln!("(stream opened: stream_id={sid})");
                // Clear the operator's terminal so the replay starts
                // clean. ESC [ 2 J = erase entire screen, ESC [ H =
                // home cursor.
                stdout.write_all(b"\x1b[2J\x1b[H").ok();
                stdout.flush().ok();
                stream_id = Some(sid);
            }
            ExtMessage::StreamFrame {
                stream_id: sid,
                payload,
            } if Some(sid) == stream_id => {
                let (frame, _): (TapStreamFrame, _) =
                    bincode::serde::decode_from_slice(&payload, cfg)
                        .context("decoding TapStreamFrame")?;
                match frame {
                    TapStreamFrame::Initial {
                        rows,
                        cols,
                        replay_bytes,
                    } => {
                        eprintln!(
                            "(initial frame: {}x{}, replay={} bytes)",
                            rows,
                            cols,
                            replay_bytes.len()
                        );
                        stdout.write_all(&replay_bytes).ok();
                        stdout.flush().ok();
                    }
                    TapStreamFrame::Output(bytes) => {
                        stdout.write_all(&bytes).ok();
                        stdout.flush().ok();
                    }
                    TapStreamFrame::Resize { rows, cols } => {
                        eprintln!("(resize: {}x{})", rows, cols);
                    }
                }
            }
            ExtMessage::StreamClosed {
                stream_id: sid,
                reason,
            } if Some(sid) == stream_id || stream_id.is_none() => {
                eprintln!("(stream closed: {reason:?})");
                return Ok(());
            }
            other => warn!(?other, "ignoring non-matching message"),
        }
    }
}

fn print_response(resp: &TapResponse) {
    match resp {
        TapResponse::SessionList(sessions) => {
            if sessions.is_empty() {
                println!("(no active sessions)");
                return;
            }
            println!("{} active session(s):", sessions.len());
            for s in sessions {
                let user = match &s.last_username {
                    Some(name) => format!("{}({})", name, s.last_uid),
                    None => format!("uid={}", s.last_uid),
                };
                println!(
                    "  pty={:>3}  user={:<14}  comm={:<10}  pid={:>7}  \
                     out={}b/{}ev  in={}b/{}ev  age={}ms idle={}ms",
                    s.pty_index,
                    user,
                    s.last_comm,
                    s.last_pid,
                    s.output_bytes,
                    s.output_events,
                    s.input_bytes,
                    s.input_events,
                    s.age_ms,
                    s.idle_ms,
                );
            }
        }
        TapResponse::Snapshot {
            pty_index,
            rows,
            cols,
            contents,
        } => {
            println!("snapshot pty={pty_index} ({rows}x{cols})");
            println!("┌{}┐", "─".repeat(*cols as usize));
            for row in contents {
                let trimmed = row.trim_end_matches(' ');
                let padding = (*cols as usize).saturating_sub(trimmed.chars().count());
                println!("│{}{}│", trimmed, " ".repeat(padding));
            }
            println!("└{}┘", "─".repeat(*cols as usize));
        }
        TapResponse::Error(msg) => {
            eprintln!("error: {msg}");
        }
    }
}
