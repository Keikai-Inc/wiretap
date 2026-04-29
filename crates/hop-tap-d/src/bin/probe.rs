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
use hop_tap_d::protocol::{TapRequest, TapResponse};
use ipc_channel::ipc::{IpcOneShotServer, IpcSender};
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
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
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

    // Build, send, receive.
    let req = match args.cmd {
        Cmd::List => TapRequest::List,
        Cmd::Snapshot { pty_index } => TapRequest::Snapshot { pty_index },
    };
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

fn print_response(resp: &TapResponse) {
    match resp {
        TapResponse::SessionList(sessions) => {
            if sessions.is_empty() {
                println!("(no active sessions)");
                return;
            }
            println!("{} active session(s):", sessions.len());
            for s in sessions {
                println!(
                    "  pty={:>3}  comm={:<12}  pid={:>7}  out={}b/{}ev  in={}b/{}ev  \
                     age={}ms idle={}ms",
                    s.pty_index,
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
