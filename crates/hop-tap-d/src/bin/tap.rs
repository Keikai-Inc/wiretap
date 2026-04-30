//! `tap` — local CLI for hop-tap-d.
//!
//! Connects to the daemon's local Unix socket
//! (`/run/hop-tap/local.sock` by default). The daemon authenticates
//! the caller via `SO_PEERCRED`; we don't carry identity claims on
//! the wire. The kernel is the source of truth for "who's connecting."
//!
//! Permission model:
//!   - root (uid 0): sees every session
//!   - non-root: sees only sessions opened by the same user
//!
//! Subcommands:
//!   tap list                 active sessions visible to you
//!   tap snapshot <pty>       current screen (24x80 grid)
//!   tap watch <pty>          live byte stream → your terminal
//!   tap repl                 interactive multi-command session
//!
//! For remote access (`<host> tap ...`), install the hop daemon
//! and use the `hop` CLI instead — this binary is local-only.

use std::io::Write as IoWrite;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hop_tap_protocol::local::LocalMessage;
use hop_tap_protocol::{TapRequest, TapResponse, TapStreamFrame, TapStreamRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "Local CLI for the hop-tap terminal-audit daemon")]
struct Args {
    /// Path to the daemon's local socket. Default
    /// `/run/hop-tap/local.sock`.
    #[arg(long = "socket", default_value = "/run/hop-tap/local.sock")]
    socket: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List sessions you can see.
    List,
    /// Print the current screen for a session.
    Snapshot {
        #[arg(value_name = "PTY")]
        pty: i32,
    },
    /// Stream live byte updates from a session into your terminal.
    Watch {
        #[arg(value_name = "PTY")]
        pty: i32,
    },
    /// Interactive REPL: handshake once, accept multiple commands.
    Repl,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();

    let args = Args::parse();
    let stream = UnixStream::connect(&args.socket).await.with_context(|| {
        format!(
            "connecting to {}\n(is hop-tap-d running?  `sudo systemctl status hop-tap`)",
            args.socket.display()
        )
    })?;
    let mut conn = Conn::new(stream);

    let mut next_id = 1u64;
    match args.cmd {
        Cmd::List => one_shot(&mut conn, &mut next_id, TapRequest::List).await,
        Cmd::Snapshot { pty } => {
            one_shot(&mut conn, &mut next_id, TapRequest::Snapshot { pty_index: pty }).await
        }
        Cmd::Watch { pty } => watch(&mut conn, &mut next_id, pty).await,
        Cmd::Repl => repl(&mut conn, &mut next_id).await,
    }
}

/// Lightweight wrapper around the Unix socket: sends and receives
/// length-prefixed bincode `LocalMessage`s.
struct Conn {
    stream: UnixStream,
}

impl Conn {
    fn new(stream: UnixStream) -> Self {
        Self { stream }
    }

    async fn send(&mut self, msg: LocalMessage) -> Result<()> {
        let cfg = bincode::config::standard();
        let bytes = bincode::serde::encode_to_vec(&msg, cfg).context("encode LocalMessage")?;
        let len = bytes.len() as u32;
        self.stream
            .write_all(&len.to_be_bytes())
            .await
            .context("write len")?;
        self.stream.write_all(&bytes).await.context("write body")?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<LocalMessage> {
        let cfg = bincode::config::standard();
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .context("read len")?;
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await.context("read body")?;
        let (msg, _): (LocalMessage, _) =
            bincode::serde::decode_from_slice(&buf, cfg).context("decode LocalMessage")?;
        Ok(msg)
    }
}

async fn one_shot(conn: &mut Conn, next_id: &mut u64, req: TapRequest) -> Result<()> {
    let request_id = *next_id;
    *next_id += 1;
    conn.send(LocalMessage::Call {
        request_id,
        payload: req,
    })
    .await?;
    loop {
        match conn.recv().await? {
            LocalMessage::Reply {
                request_id: rid,
                payload,
            } if rid == request_id => {
                print_response(&payload);
                return Ok(());
            }
            other => eprintln!("(ignored unexpected: {other:?})"),
        }
    }
}

async fn watch(conn: &mut Conn, next_id: &mut u64, pty: i32) -> Result<()> {
    let request_id = *next_id;
    *next_id += 1;
    conn.send(LocalMessage::Subscribe {
        request_id,
        payload: TapStreamRequest::Subscribe { pty_index: pty },
    })
    .await?;
    let mut stream_id: Option<u64> = None;
    let mut stdout = std::io::stdout().lock();
    loop {
        match conn.recv().await? {
            LocalMessage::StreamOpened {
                request_id: rid,
                stream_id: sid,
            } if rid == request_id => {
                eprintln!("(stream opened: stream_id={sid})");
                stdout.write_all(b"\x1b[2J\x1b[H").ok();
                stdout.flush().ok();
                stream_id = Some(sid);
            }
            LocalMessage::StreamFrame {
                stream_id: sid,
                payload,
            } if Some(sid) == stream_id => match payload {
                TapStreamFrame::Initial {
                    rows,
                    cols,
                    replay_bytes,
                } => {
                    eprintln!(
                        "(initial frame: {rows}x{cols}, replay={} bytes)",
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
                    eprintln!("(resize: {rows}x{cols})");
                }
            },
            LocalMessage::StreamClosed {
                stream_id: sid,
                reason,
            } if Some(sid) == stream_id || stream_id.is_none() => {
                eprintln!("(stream closed: {reason:?})");
                return Ok(());
            }
            other => eprintln!("(ignored: {other:?})"),
        }
    }
}

async fn repl(conn: &mut Conn, next_id: &mut u64) -> Result<()> {
    use std::io::{BufRead, Write as _};
    eprintln!("tap REPL — commands: list | snapshot N | watch N | exit");
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut line = String::new();
    loop {
        eprint!("> ");
        std::io::stderr().flush().ok();
        line.clear();
        if stdin.read_line(&mut line).context("read stdin")? == 0 {
            eprintln!();
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let arg = parts.next();
        match cmd {
            "list" => {
                if let Err(e) = one_shot(conn, next_id, TapRequest::List).await {
                    eprintln!("error: {e}");
                }
            }
            "snapshot" => match arg.and_then(|s| s.parse::<i32>().ok()) {
                Some(pty) => {
                    if let Err(e) =
                        one_shot(conn, next_id, TapRequest::Snapshot { pty_index: pty }).await
                    {
                        eprintln!("error: {e}");
                    }
                }
                None => eprintln!("usage: snapshot <pty>"),
            },
            "watch" => match arg.and_then(|s| s.parse::<i32>().ok()) {
                Some(pty) => {
                    if let Err(e) = watch(conn, next_id, pty).await {
                        eprintln!("error: {e}");
                    }
                }
                None => eprintln!("usage: watch <pty>"),
            },
            "exit" | "quit" => return Ok(()),
            "help" | "?" => eprintln!("commands: list | snapshot N | watch N | exit"),
            other => eprintln!("unknown command: {other}  (try `help`)"),
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
                let opener = format_user(&s.opener_username, s.opener_uid);
                let writer = format_user(&s.last_username, s.last_uid);
                let identity = if s.opener_uid == s.last_uid && s.opener_pid == s.last_pid {
                    format!("user={opener:<14} comm={:<10}", s.last_comm)
                } else if s.opener_uid == s.last_uid {
                    format!(
                        "user={opener:<14} comm={:<10} (writer={})",
                        s.last_comm, s.last_pid
                    )
                } else {
                    format!(
                        "opener={opener:<14} writer={writer:<14} comm={:<10}",
                        s.last_comm
                    )
                };
                println!(
                    "  pty={:>3}  {identity}  out={}b/{}ev  in={}b/{}ev  age={}ms idle={}ms",
                    s.pty_index,
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
        TapResponse::Error(msg) => eprintln!("error: {msg}"),
    }
}

fn format_user(username: &Option<String>, uid: u32) -> String {
    match username {
        Some(name) => format!("{}({})", name, uid),
        None => format!("uid={}", uid),
    }
}
