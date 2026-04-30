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
//!   tap                      session picker (no args)
//!   tap list                 active sessions visible to you
//!   tap connect <pty>        attach: live output + your stdin →
//!                            session input. Detach with Ctrl-T.
//!
//! For remote access (`<host> tap ...`), install the hop daemon
//! and use the `hop` CLI instead — this binary is local-only.

use std::io::Write as IoWrite;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hop_tap_protocol::local::LocalMessage;
use hop_tap_protocol::{TapRequest, TapResponse, TapStreamFrame, TapStreamRequest};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "Local CLI for the hop-tap terminal-audit daemon")]
struct Args {
    /// Path to the daemon's local socket. Default
    /// `/run/hop-tap/local.sock`.
    #[arg(long = "socket", default_value = "/run/hop-tap/local.sock")]
    socket: PathBuf,

    /// When omitted, `tap` opens a tmux-style session picker:
    /// arrows to select, Enter = connect, w = watch read-only,
    /// s = snapshot, q = quit.
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// List sessions you can see.
    List,
    /// Attach to a session bidirectionally: live output to your
    /// terminal, your keystrokes injected into the session. Detach
    /// with Ctrl-T.
    Connect {
        #[arg(value_name = "PTY")]
        pty: i32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
        .init();

    let args = Args::parse();

    // No subcommand → loop the picker: pick a session, run the
    // chosen action, when it returns (Ctrl-B d / Esc / etc) re-enter
    // the picker. The user only leaves by pressing q in the picker
    // itself. Direct subcommands (`tap watch 3`) bypass the loop and
    // dispatch once like before.
    if args.cmd.is_none() {
        return picker_loop(&args.socket).await;
    }

    let cmd = args.cmd.unwrap();
    let stream = UnixStream::connect(&args.socket).await.with_context(|| {
        format!(
            "connecting to {}\n(is hop-tap-d running?  `sudo systemctl status hop-tap`)",
            args.socket.display()
        )
    })?;

    let mut next_id = 1u64;
    match cmd {
        // For direct invocation (no picker to return to) every
        // attach outcome collapses to clean exit.
        Cmd::Connect { pty } => connect(stream, &mut next_id, pty).await.map(|_| ()),
        Cmd::List => {
            let mut conn = Conn::new(stream);
            one_shot(&mut conn, &mut next_id, TapRequest::List).await
        }
    }
}

/// Loop: pick a session in the TUI → connect to it → on detach
/// (Ctrl-T or session ended) re-enter the picker. Exits cleanly when
/// the user presses q (or Esc) in the picker. Errors from a single
/// connect (e.g. pty went away mid-attach) are surfaced briefly and
/// don't break the loop.
async fn picker_loop(socket: &std::path::Path) -> Result<()> {
    loop {
        let pty = match run_tui(socket).await? {
            Some(TuiAction::Connect(pty)) => pty,
            None => return Ok(()),
        };

        let stream = match UnixStream::connect(socket).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("\r\n[connection error: {e}]\r");
                continue;
            }
        };

        let mut next_id = 1u64;
        match connect(stream, &mut next_id, pty).await {
            Ok(_) => {} // Detached or SessionClosed — both re-enter the picker.
            Err(e) => {
                eprintln!("\r\n[connect error: {e}]\r");
                tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            }
        }
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
        TapResponse::Injected {
            pty_index,
            bytes_written,
        } => {
            println!("injected {bytes_written} byte(s) into pty={pty_index}");
        }
        TapResponse::Killed {
            pty_index,
            pid,
            signal,
        } => {
            println!("sent signal {signal} to pid {pid} (pty={pty_index})");
        }
        TapResponse::MessageDelivered {
            pty_index,
            bytes_written,
        } => {
            println!("delivered admin message to pty={pty_index} ({bytes_written} bytes)");
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

/// Bytes the stdin reader thread sends back to the connect loop.
enum StdinEvent {
    /// User typed these bytes — forward to the session via Inject.
    Bytes(Vec<u8>),
    /// User pressed Ctrl-T — leave the attach. The caller (picker
    /// loop or direct dispatch) decides what to do next; from the
    /// picker we re-enter the menu, from a direct `tap connect 3`
    /// we just exit to the shell.
    Detach,
}

/// Outcome of an attach. The caller (picker loop) re-enters the
/// menu on Detached / SessionClosed; for a direct `tap connect`
/// invocation both collapse to clean exit.
#[derive(Debug)]
enum AttachOutcome {
    /// User pressed Ctrl-T.
    Detached,
    /// Server closed the stream (session ended, forbidden, etc.).
    SessionClosed,
}

/// RAII guard that disables raw mode when dropped. Ensures the
/// terminal returns to cooked mode on every exit path — normal
/// return, panic, error propagation.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Encode and send a `LocalMessage` over an owned write half. Same
/// length-prefixed bincode framing as `Conn::send`, but works on an
/// `OwnedWriteHalf` so the connect path can split the stream.
async fn send_local(write: &mut OwnedWriteHalf, msg: &LocalMessage) -> Result<()> {
    let cfg = bincode::config::standard();
    let bytes = bincode::serde::encode_to_vec(msg, cfg).context("encode LocalMessage")?;
    let len = bytes.len() as u32;
    write
        .write_all(&len.to_be_bytes())
        .await
        .context("write len")?;
    write.write_all(&bytes).await.context("write body")?;
    Ok(())
}

/// Read one length-prefixed bincode `LocalMessage` from an owned
/// read half.
async fn recv_local(read: &mut OwnedReadHalf) -> Result<LocalMessage> {
    let cfg = bincode::config::standard();
    let mut len_buf = [0u8; 4];
    read.read_exact(&mut len_buf).await.context("read len")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    read.read_exact(&mut buf).await.context("read body")?;
    let (msg, _): (LocalMessage, _) =
        bincode::serde::decode_from_slice(&buf, cfg).context("decode LocalMessage")?;
    Ok(msg)
}

/// Modes the connect main loop alternates between based on user input.
enum ConnectMode {
    /// Default: forward bytes to the captured session via Inject.
    Normal,
    /// User pressed Ctrl-G — bytes are accumulated into a message and
    /// rendered on the bottom row instead of forwarded. Enter sends,
    /// Esc cancels.
    Compose(String),
}

/// Snapshot of a session's identity that fits into the bottom status
/// bar. Fetched once at connect time via `tap list`; we don't try to
/// keep it live since the picker handles that.
#[derive(Clone)]
struct StatusInfo {
    pty: i32,
    user: String,
    comm: String,
}

/// `tap connect <pty>` — attach to a session bidirectionally with a
/// tmux-style bottom status bar.
///
/// We deliberately *don't* set DECSTBM to reserve the bottom row.
/// Absolute cursor positioning ignores the scroll region anyway, so
/// it doesn't reliably protect the bar; worse, when the captured
/// session's cursor lands on the bottom row, every Output byte
/// arrived there and our re-paint clobbered it — so output looked
/// like it wasn't refreshing. Instead: paint the bar once after the
/// Initial replay, then refresh only on a 1s timer. Chatty sessions
/// will overdraw the bar briefly, but the timer brings it back. In
/// Compose mode we paint after every Output so the input prompt
/// stays visible while the user types.
///
/// Keys:
///   Ctrl-T → detach
///   Ctrl-G → compose admin message (replaces status bar with input
///            prompt; Enter sends via TapRequest::AdminMessage, which
///            the daemon writes to /dev/pts/N as terminal output;
///            Esc cancels)
async fn connect(
    stream: UnixStream,
    next_id: &mut u64,
    pty: i32,
) -> Result<AttachOutcome> {
    let (mut read_half, mut write_half) = stream.into_split();

    // Fetch the session's identity for the status bar before we
    // subscribe — this keeps the Subscribe path symmetric with the
    // existing flow and the List call uses a separate request_id.
    let info = fetch_status_info(&mut read_half, &mut write_half, next_id, pty).await?;

    // 1. Subscribe to the watch stream and confirm the daemon
    //    accepted it before we touch the local terminal. If the
    //    server rejects (no such pty, forbidden), we want a clean
    //    error rather than a tornado of raw-mode chaos.
    let sub_request_id = *next_id;
    *next_id += 1;
    send_local(
        &mut write_half,
        &LocalMessage::Subscribe {
            request_id: sub_request_id,
            payload: TapStreamRequest::Subscribe { pty_index: pty },
        },
    )
    .await?;

    let stream_id = loop {
        match recv_local(&mut read_half).await? {
            LocalMessage::StreamOpened {
                request_id: rid,
                stream_id: sid,
            } if rid == sub_request_id => break sid,
            LocalMessage::StreamClosed { reason, .. } => {
                bail!(
                    "connect: server rejected subscription: {}",
                    reason.unwrap_or_else(|| "(no reason)".into())
                );
            }
            _ => continue,
        }
    };

    // 2. Raw mode + Drop-guarded restore. The DECSTBM scroll-region
    //    setup happens after the first Initial frame.
    crossterm::terminal::enable_raw_mode().context("enable raw mode")?;
    let _raw = RawModeGuard;

    // 3. Blocking stdin reader on a dedicated thread. Single hot key
    //    is Ctrl-T (detach); other special handling — including
    //    Ctrl-G for compose mode — happens in the main loop where
    //    we have the mode state.
    let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<StdinEvent>();
    std::thread::spawn(move || {
        stdin_reader_loop(stdin_tx);
    });

    let (mut term_cols, mut term_rows) = match crossterm::terminal::size() {
        Ok((c, r)) => (c, r),
        Err(_) => (80, 24),
    };

    let mut stdout = std::io::stdout().lock();
    let mut mode = ConnectMode::Normal;

    // Will become true once we've received the first Initial frame —
    // we hold off on configuring DECSTBM and painting the status bar
    // until the captured session's screen is rendered, otherwise the
    // status bar gets immediately overwritten by the Initial replay.
    let mut session_ready = false;
    let mut admin_id: u64 = sub_request_id.wrapping_add(1_000_000);
    let mut inject_id: u64 = sub_request_id.wrapping_add(1);

    let mut status_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    status_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let outcome = loop {
        tokio::select! {
            biased;
            evt = stdin_rx.recv() => {
                let event = match evt {
                    Some(e) => e,
                    None => break AttachOutcome::Detached,
                };
                match event {
                    StdinEvent::Detach => {
                        break AttachOutcome::Detached;
                    }
                    StdinEvent::Bytes(bytes) => {
                        match handle_stdin_bytes(
                            bytes,
                            &mut mode,
                            &mut stdout,
                            term_rows,
                            term_cols,
                            &info,
                            &mut write_half,
                            &mut inject_id,
                            &mut admin_id,
                            pty,
                        ).await {
                            Ok(()) => {}
                            Err(e) => {
                                eprintln!("\r\n[connect: send failed: {e}]\r");
                                break AttachOutcome::SessionClosed;
                            }
                        }
                    }
                }
            }
            msg = recv_local(&mut read_half) => {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("\r\n[connect: server closed: {e}]\r");
                        break AttachOutcome::SessionClosed;
                    }
                };
                match msg {
                    LocalMessage::StreamFrame { stream_id: sid, payload } if sid == stream_id => {
                        match payload {
                            TapStreamFrame::Initial { replay_bytes, .. } => {
                                let _ = stdout.write_all(b"\x1b[2J\x1b[H");
                                let _ = stdout.write_all(&replay_bytes);
                                paint_status_bar(&mut stdout, term_rows, term_cols, &info, &mode);
                                let _ = stdout.flush();
                                session_ready = true;
                            }
                            TapStreamFrame::Output(b) => {
                                let _ = stdout.write_all(&b);
                                // Only re-paint the status bar when the
                                // user is actively composing — otherwise
                                // we'd overwrite the captured session's
                                // own bottom-row content on every frame.
                                // The 1s timer below brings the bar back
                                // for normal mode.
                                if session_ready && matches!(mode, ConnectMode::Compose(_)) {
                                    paint_status_bar(&mut stdout, term_rows, term_cols, &info, &mode);
                                }
                                let _ = stdout.flush();
                            }
                            // Captured session resized. Don't propagate
                            // to the local terminal — the user's
                            // terminal dims are what they care about.
                            TapStreamFrame::Resize { .. } => {}
                        }
                    }
                    LocalMessage::StreamClosed { stream_id: sid, reason }
                        if sid == stream_id =>
                    {
                        eprintln!(
                            "\r\n[session ended: {}]\r",
                            reason.unwrap_or_else(|| "(no reason)".into())
                        );
                        break AttachOutcome::SessionClosed;
                    }
                    // Inject / AdminMessage acks: fire-and-forget.
                    LocalMessage::Reply { .. } => {}
                    _ => {}
                }
            }
            _ = status_timer.tick() => {
                // Periodic re-paint brings the bar back if the captured
                // session has scrolled / overwritten it since the last
                // tick. Also re-fetches terminal size in case the user
                // resized.
                if let Ok((c, r)) = crossterm::terminal::size() {
                    if (c, r) != (term_cols, term_rows) {
                        term_cols = c;
                        term_rows = r;
                    }
                }
                if session_ready {
                    paint_status_bar(&mut stdout, term_rows, term_cols, &info, &mode);
                    let _ = stdout.flush();
                }
            }
        }
    };

    // Tear down: erase the status row so it doesn't linger on the
    // user's terminal once the picker (or shell prompt) takes over.
    let _ = write!(stdout, "\x1b[{};1H\x1b[K", term_rows);
    let _ = stdout.flush();
    drop(stdout);
    eprintln!("\r\n[detached]\r");
    Ok(outcome)
}

/// One-shot `List` over the connect socket so we can fill in the
/// status bar with the session's user/comm. Uses the same read/write
/// halves the connect main loop will use afterward — we issue this
/// before subscribing so there's no concurrent traffic to filter.
async fn fetch_status_info(
    read: &mut OwnedReadHalf,
    write: &mut OwnedWriteHalf,
    next_id: &mut u64,
    pty: i32,
) -> Result<StatusInfo> {
    let request_id = *next_id;
    *next_id += 1;
    send_local(
        write,
        &LocalMessage::Call {
            request_id,
            payload: TapRequest::List,
        },
    )
    .await?;
    loop {
        match recv_local(read).await? {
            LocalMessage::Reply {
                request_id: rid,
                payload: TapResponse::SessionList(list),
            } if rid == request_id => {
                let info = list
                    .into_iter()
                    .find(|s| s.pty_index == pty)
                    .map(|s| StatusInfo {
                        pty,
                        user: format_user(&s.opener_username, s.opener_uid),
                        comm: s.last_comm,
                    })
                    .unwrap_or_else(|| StatusInfo {
                        pty,
                        user: String::from("?"),
                        comm: String::from("?"),
                    });
                return Ok(info);
            }
            _ => continue,
        }
    }
}

/// Process bytes from stdin. In Normal mode, scan for Ctrl-G — if
/// present, split: forward bytes-before via Inject, switch to Compose
/// for what follows. In Compose mode, accumulate bytes into the
/// message buffer, watching for Enter (send), Esc (cancel), and
/// Backspace.
async fn handle_stdin_bytes(
    bytes: Vec<u8>,
    mode: &mut ConnectMode,
    stdout: &mut std::io::StdoutLock<'static>,
    rows: u16,
    cols: u16,
    info: &StatusInfo,
    write: &mut OwnedWriteHalf,
    inject_id: &mut u64,
    admin_id: &mut u64,
    pty: i32,
) -> Result<()> {
    const CTRL_G: u8 = 0x07;
    const ENTER_CR: u8 = 0x0D;
    const ENTER_LF: u8 = 0x0A;
    const ESC: u8 = 0x1B;
    const BACKSPACE_DEL: u8 = 0x7F;
    const BACKSPACE_BS: u8 = 0x08;

    // Walk bytes one at a time, since each byte may transition modes.
    // Buffer a "to inject" run and flush it when we hit a transition,
    // so we don't issue an Inject RPC per keystroke.
    let mut to_inject: Vec<u8> = Vec::with_capacity(bytes.len());

    for &b in &bytes {
        match mode {
            ConnectMode::Normal => {
                if b == CTRL_G {
                    if !to_inject.is_empty() {
                        send_inject(write, inject_id, pty, std::mem::take(&mut to_inject)).await?;
                    }
                    *mode = ConnectMode::Compose(String::new());
                    paint_compose_prompt(stdout, rows, cols, "");
                    let _ = stdout.flush();
                } else {
                    to_inject.push(b);
                }
            }
            ConnectMode::Compose(buf) => {
                match b {
                    ENTER_CR | ENTER_LF => {
                        // Send (if non-empty) and exit compose.
                        let msg = std::mem::take(buf);
                        *mode = ConnectMode::Normal;
                        paint_status_bar(stdout, rows, cols, info, mode);
                        let _ = stdout.flush();
                        if !msg.trim().is_empty() {
                            *admin_id = admin_id.wrapping_add(1);
                            let from = local_username();
                            send_local(
                                write,
                                &LocalMessage::Call {
                                    request_id: *admin_id,
                                    payload: TapRequest::AdminMessage {
                                        pty_index: pty,
                                        message: msg,
                                        from,
                                    },
                                },
                            )
                            .await?;
                        }
                    }
                    ESC | CTRL_G => {
                        // Cancel.
                        buf.clear();
                        *mode = ConnectMode::Normal;
                        paint_status_bar(stdout, rows, cols, info, mode);
                        let _ = stdout.flush();
                    }
                    BACKSPACE_BS | BACKSPACE_DEL => {
                        buf.pop();
                        paint_compose_prompt(stdout, rows, cols, buf);
                        let _ = stdout.flush();
                    }
                    b if b.is_ascii_control() => {
                        // Drop other control bytes silently — keep
                        // the buffer plain text.
                    }
                    b => {
                        buf.push(b as char);
                        paint_compose_prompt(stdout, rows, cols, buf);
                        let _ = stdout.flush();
                    }
                }
            }
        }
    }
    if !to_inject.is_empty() {
        send_inject(write, inject_id, pty, to_inject).await?;
    }
    Ok(())
}

async fn send_inject(
    write: &mut OwnedWriteHalf,
    inject_id: &mut u64,
    pty: i32,
    bytes: Vec<u8>,
) -> Result<()> {
    *inject_id = inject_id.wrapping_add(1);
    send_local(
        write,
        &LocalMessage::Call {
            request_id: *inject_id,
            payload: TapRequest::Inject {
                pty_index: pty,
                bytes,
            },
        },
    )
    .await
}

/// Paint the bottom-row status bar. Saves and restores cursor so the
/// captured session sees no apparent disturbance.
fn paint_status_bar(
    stdout: &mut std::io::StdoutLock<'static>,
    rows: u16,
    cols: u16,
    info: &StatusInfo,
    mode: &ConnectMode,
) {
    if let ConnectMode::Compose(buf) = mode {
        // Compose mode owns the bottom row — skip status painting.
        paint_compose_prompt(stdout, rows, cols, buf);
        return;
    }
    let left = format!(" tap pty={} {} {} ", info.pty, info.user, info.comm);
    let right = " Ctrl-T menu  Ctrl-G msg ";
    let cols = cols as usize;
    let mut bar = if left.len() + right.len() <= cols {
        let pad = cols - left.len() - right.len();
        format!("{}{}{}", left, " ".repeat(pad), right)
    } else if left.len() <= cols {
        // Fall back: just left side, truncate right to fit.
        let pad = cols - left.len();
        format!("{}{}", left, " ".repeat(pad))
    } else {
        // Even the left side doesn't fit — chop it.
        left.chars().take(cols).collect()
    };
    bar.truncate(bar.char_indices().nth(cols).map(|(i, _)| i).unwrap_or(bar.len()));

    // \x1b 7 = save cursor (incl. attrs); \x1b 8 = restore.
    // \x1b[<rows>;1H positions to bottom-left.
    let _ = write!(
        stdout,
        "\x1b7\x1b[{};1H\x1b[K\x1b[7m{}\x1b[0m\x1b8",
        rows, bar
    );
}

/// Paint the Compose-mode input prompt on the bottom row. Cursor is
/// left at the input position so the user sees what they're typing.
fn paint_compose_prompt(
    stdout: &mut std::io::StdoutLock<'static>,
    rows: u16,
    cols: u16,
    buf: &str,
) {
    let prefix = " admin > ";
    let suffix = "  [Enter=send Esc=cancel] ";
    let cols = cols as usize;
    let avail = cols.saturating_sub(prefix.len() + suffix.len());
    let shown: String = buf.chars().rev().take(avail).collect::<String>().chars().rev().collect();
    let pad = avail.saturating_sub(shown.chars().count());
    let _ = write!(
        stdout,
        "\x1b[{rows};1H\x1b[K\x1b[1;33;7m{prefix}\x1b[0m\x1b[1;33m{shown}\x1b[0m{padding}\x1b[1;33;7m{suffix}\x1b[0m\x1b[{rows};{col}H",
        rows = rows,
        prefix = prefix,
        shown = shown,
        padding = " ".repeat(pad),
        suffix = suffix,
        col = prefix.len() + shown.chars().count() + 1,
    );
}

/// Best-effort local username, used as the `from:` field on admin
/// messages. Falls back to "admin" if the env doesn't have one.
fn local_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "admin".into())
}

/// What the TUI picker returns to `main` after the user picks a
/// session. Only one action today: connect. The wrapper enum keeps
/// the call sites symmetric and leaves room for future picker-level
/// actions without changing the run_tui signature.
enum TuiAction {
    Connect(i32),
}

/// Run the no-args session picker: a ratatui table of active
/// sessions that refreshes every ~1.5s. Returns:
///   - `Ok(Some(action))` if the user picked a session
///   - `Ok(None)` if the user pressed `q` to quit cleanly
///
/// Errors out only on irrecoverable problems (socket gone, terminal
/// can't enter raw mode, etc.) — refresh failures are surfaced as a
/// status line, not a hard error.
async fn run_tui(socket: &std::path::Path) -> Result<Option<TuiAction>> {
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};
    use crossterm::execute;
    use crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
    use ratatui::backend::CrosstermBackend;
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::style::{Modifier, Style};
    use ratatui::text::{Line, Text};
    use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
    use ratatui::Terminal;
    use std::io::stdout;
    use std::time::{Duration, Instant};

    // Open one connection to the daemon for List polling. Reused for
    // every refresh — the TUI doesn't reopen on each tick.
    let stream = UnixStream::connect(socket).await.with_context(|| {
        format!(
            "connecting to {}\n(is hop-tap-d running?  `sudo systemctl status hop-tap`)",
            socket.display()
        )
    })?;
    let mut conn = Conn::new(stream);
    let mut next_id = 1u64;

    // Set up the alt-screen + raw-mode + ratatui terminal. Drop guard
    // restores the user's terminal even on panic / early return.
    enable_raw_mode().context("enable raw mode")?;
    execute!(stdout(), EnterAlternateScreen).context("enter alt screen")?;
    let _tui_guard = TuiGuard;
    let backend = CrosstermBackend::new(stdout());
    let mut term = Terminal::new(backend).context("ratatui::Terminal::new")?;

    // Blocking key reader on a worker thread → tokio mpsc. Same
    // pattern as `connect`'s stdin loop. We send only KeyEvents;
    // resize/mouse are ignored for the picker.
    let (key_tx, mut key_rx) = mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || loop {
        match crossterm::event::read() {
            Ok(Event::Key(k)) => {
                if key_tx.send(k).is_err() {
                    return;
                }
            }
            Ok(_) => continue,
            Err(_) => return,
        }
    });

    let mut sessions: Vec<hop_tap_protocol::SessionInfo> = Vec::new();
    let mut state = TableState::default();
    state.select(Some(0));
    let mut status_line: String = String::from("loading…");
    let mut last_refresh = Instant::now() - Duration::from_secs(10);
    let refresh_interval = Duration::from_millis(1500);

    // Live preview cache: which pty's screen we're currently showing,
    // plus the (rows, cols, contents) of its last fetched snapshot. We
    // refetch when the highlighted pty changes (so navigation feels
    // instant) and again on every periodic refresh so a still-selected
    // session updates as it produces output.
    let mut preview_pty: Option<i32> = None;
    let mut preview: Option<(u16, u16, Vec<String>)> = None;

    // Pending kill confirmation: when the user presses 'x', we stash
    // the highlighted pty here and override the status line. The next
    // keystroke either confirms ('y') and fires the Kill RPC, or
    // cancels (anything else).
    let mut pending_kill: Option<i32> = None;
    // Brief flash message: shows above the status line for one render
    // cycle to confirm or report errors. Cleared on the next refresh.
    let mut flash: Option<String> = None;

    loop {
        // Periodic refresh of the session list.
        if last_refresh.elapsed() >= refresh_interval {
            match refresh_sessions(&mut conn, &mut next_id).await {
                Ok(s) => {
                    sessions = s;
                    if let Some(sel) = state.selected() {
                        if !sessions.is_empty() && sel >= sessions.len() {
                            state.select(Some(sessions.len() - 1));
                        } else if sessions.is_empty() {
                            state.select(None);
                        }
                    } else if !sessions.is_empty() {
                        state.select(Some(0));
                    }
                    status_line = format!(
                        "{} session(s) — ↑/↓ select  Enter=connect  x=kill  q=quit",
                        sessions.len()
                    );
                }
                Err(e) => {
                    status_line = format!("refresh error: {e}");
                }
            }
            // Drop the cached preview so the periodic refresh below
            // grabs a fresh one for the current selection. This is what
            // makes the preview feel "live."
            preview_pty = None;
            last_refresh = Instant::now();
        }

        // Refresh the preview if our cache doesn't match the current
        // selection (highlight changed, or we just invalidated it).
        let target_pty = state.selected().and_then(|i| sessions.get(i)).map(|s| s.pty_index);
        if target_pty != preview_pty {
            preview_pty = target_pty;
            preview = match target_pty {
                Some(pty) => match refresh_snapshot(&mut conn, &mut next_id, pty).await {
                    Ok(p) => Some(p),
                    Err(_) => None,
                },
                None => None,
            };
        }

        // Render.
        term.draw(|f| {
            let area = f.area();
            let outer = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                    Constraint::Length(1),
                ])
                .split(area);

            let header = Paragraph::new("tap — terminal session picker")
                .block(Block::default().borders(Borders::ALL).title("hop-tap"));
            f.render_widget(header, outer[0]);

            // Split the middle region: session table on the left, live
            // preview of the highlighted session on the right. 60/40
            // split is roomy enough for the table at ~80 cols and gives
            // the preview enough width to be useful.
            let body = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(outer[1]);

            let header_row = Row::new(vec![
                Cell::from("pty"),
                Cell::from("user"),
                Cell::from("comm"),
                Cell::from("age"),
                Cell::from("idle"),
            ])
            .style(Style::default().add_modifier(Modifier::BOLD));

            let rows: Vec<Row> = sessions
                .iter()
                .map(|s| {
                    let opener = format_user(&s.opener_username, s.opener_uid);
                    Row::new(vec![
                        Cell::from(format!("{}", s.pty_index)),
                        Cell::from(opener),
                        Cell::from(s.last_comm.clone()),
                        Cell::from(format!("{}ms", s.age_ms)),
                        Cell::from(format!("{}ms", s.idle_ms)),
                    ])
                })
                .collect();

            let widths = [
                Constraint::Length(5),
                Constraint::Length(20),
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(10),
            ];
            let table = Table::new(rows, widths)
                .header(header_row)
                .block(Block::default().borders(Borders::ALL).title("sessions"))
                .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            f.render_stateful_widget(table, body[0], &mut state);

            // Preview pane: render the cached snapshot rows. Truncate
            // each row to fit the inner width (the Block borders eat
            // 2 cols), and show the bottom-most rows that fit (most
            // recent activity is at the bottom of a terminal). If we
            // don't have a snapshot yet, show a placeholder.
            let preview_block = Block::default()
                .borders(Borders::ALL)
                .title(match preview_pty {
                    Some(pty) => format!("preview (pty {pty})"),
                    None => "preview".into(),
                });
            let preview_inner = preview_block.inner(body[1]);
            let inner_w = preview_inner.width as usize;
            let inner_h = preview_inner.height as usize;
            let lines: Vec<Line> = match (&preview, inner_w, inner_h) {
                (Some((_, _, contents)), w, h) if w > 0 && h > 0 => {
                    // Find the last non-blank row. That's typically where
                    // the action is — the active prompt for a shell, the
                    // last line of output for `ps aux`, etc. Anchoring on
                    // this row (instead of the literal bottom of the
                    // grid) means a fresh shell with its prompt at row 0
                    // shows that prompt, not the empty rows below it.
                    let last_meaningful = contents
                        .iter()
                        .rposition(|row| !row.chars().all(|c| c.is_whitespace()));

                    match last_meaningful {
                        None => {
                            // Whole grid is whitespace — daemon has nothing
                            // captured for this session yet. Tell the user
                            // explicitly so a blank pane doesn't look like
                            // a UI bug.
                            vec![
                                Line::from(""),
                                Line::from("  (no captured output yet)"),
                                Line::from(""),
                                Line::from("  This session has been idle since"),
                                Line::from("  hop-tap-d started — its screen"),
                                Line::from("  populates as soon as it produces"),
                                Line::from("  output. Press Enter to attach"),
                                Line::from("  and interact with it."),
                            ]
                        }
                        Some(last_row) => {
                            // Slice from (last_row - h + 1) to last_row+1,
                            // bounded by the grid. Then bottom-align inside
                            // the preview pane: pad above with empty Lines
                            // if the slice is shorter than h, so content
                            // sits where it actually appears on the
                            // captured terminal (vs. ratatui's default
                            // top-aligned Paragraph rendering).
                            let last = last_row + 1;
                            let start = last.saturating_sub(h);
                            let visible_rows = &contents[start..last];

                            let mut out: Vec<Line> = Vec::with_capacity(h);
                            let pad = h.saturating_sub(visible_rows.len());
                            for _ in 0..pad {
                                out.push(Line::from(""));
                            }
                            for row in visible_rows {
                                let trimmed = row.trim_end_matches(' ');
                                // Truncate by chars (not bytes) to avoid
                                // splitting multi-byte UTF-8.
                                let truncated: String = trimmed.chars().take(w).collect();
                                out.push(Line::from(truncated));
                            }
                            out
                        }
                    }
                }
                _ if preview_pty.is_some() => vec![Line::from("(loading…)")],
                _ => vec![Line::from("(no session selected)")],
            };
            let preview_para = Paragraph::new(Text::from(lines)).block(preview_block);
            f.render_widget(preview_para, body[1]);

            // Status line: pending-kill prompt > flash > normal hint.
            // Each takes precedence in that order.
            let status_text = if let Some(p) = pending_kill {
                format!(
                    "kill pty {p}? press y to confirm (SIGHUP), X to force (SIGKILL), any other key to cancel"
                )
            } else if let Some(msg) = &flash {
                msg.clone()
            } else {
                status_line.clone()
            };
            let status = Paragraph::new(status_text);
            f.render_widget(status, outer[2]);
        })
        .context("ratatui draw")?;

        // Wait for either a key event or the next refresh tick.
        let until_next_refresh = refresh_interval.saturating_sub(last_refresh.elapsed());
        tokio::select! {
            _ = tokio::time::sleep(until_next_refresh) => {
                continue;
            }
            evt = key_rx.recv() => {
                let key = match evt {
                    Some(k) => k,
                    None => return Ok(None),
                };
                // If a kill confirmation is pending, the next keystroke
                // either confirms or cancels — nothing else fires.
                if let Some(target) = pending_kill {
                    pending_kill = None;
                    let force = matches!(key.code, KeyCode::Char('X'));
                    let confirmed = force || matches!(key.code, KeyCode::Char('y'));
                    if confirmed {
                        flash = match send_kill(&mut conn, &mut next_id, target, force).await {
                            Ok(()) => Some(format!(
                                "sent {} to pty {}",
                                if force { "SIGKILL" } else { "SIGHUP" },
                                target,
                            )),
                            Err(e) => Some(format!("kill failed: {e}")),
                        };
                        // Trigger an immediate list refresh so the killed
                        // session disappears (or stops being highlighted)
                        // without waiting for the periodic tick.
                        last_refresh = Instant::now() - refresh_interval;
                    } else {
                        flash = Some(format!("kill of pty {target} cancelled"));
                    }
                    continue;
                }
                // Any keystroke clears a stale flash so old messages
                // don't linger.
                flash = None;
                match (key.code, key.modifiers) {
                    (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => return Ok(None),
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(None),
                    (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                        if let Some(i) = state.selected() {
                            if i > 0 { state.select(Some(i - 1)); }
                        }
                    }
                    (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                        if let Some(i) = state.selected() {
                            if i + 1 < sessions.len() { state.select(Some(i + 1)); }
                        }
                    }
                    (KeyCode::Enter, _) => {
                        if let Some(s) = state.selected().and_then(|i| sessions.get(i)) {
                            return Ok(Some(TuiAction::Connect(s.pty_index)));
                        }
                    }
                    (KeyCode::Char('x'), _) => {
                        // Arm a kill confirmation on the highlighted
                        // session. The next key decides.
                        if let Some(s) = state.selected().and_then(|i| sessions.get(i)) {
                            pending_kill = Some(s.pty_index);
                        }
                    }
                    (KeyCode::Char('r'), _) => {
                        // Force-refresh on demand.
                        last_refresh = Instant::now() - refresh_interval;
                    }
                    _ => {}
                }
            }
        }
    }
}

/// RAII restore for the ratatui TUI. Disables raw mode and leaves
/// the alt screen on every exit path. Errors are intentionally
/// swallowed — the user's terminal is already gone and there's
/// nothing actionable.
struct TuiGuard;

impl Drop for TuiGuard {
    fn drop(&mut self) {
        use crossterm::execute;
        use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

/// Fetch a Snapshot for `pty` and return (rows, cols, contents). Used
/// by the TUI's preview pane. Returns Err if the daemon doesn't have
/// (or won't surface) the session — callers should clear the cache
/// and show a placeholder.
async fn refresh_snapshot(
    conn: &mut Conn,
    next_id: &mut u64,
    pty: i32,
) -> Result<(u16, u16, Vec<String>)> {
    let request_id = *next_id;
    *next_id += 1;
    conn.send(LocalMessage::Call {
        request_id,
        payload: TapRequest::Snapshot { pty_index: pty },
    })
    .await?;
    loop {
        match conn.recv().await? {
            LocalMessage::Reply {
                request_id: rid,
                payload:
                    TapResponse::Snapshot {
                        rows,
                        cols,
                        contents,
                        ..
                    },
            } if rid == request_id => return Ok((rows, cols, contents)),
            LocalMessage::Reply {
                request_id: rid,
                payload: TapResponse::Error(msg),
            } if rid == request_id => bail!("daemon: {msg}"),
            other => {
                tracing::debug!(?other, "tui: ignoring unexpected message during snapshot");
            }
        }
    }
}

/// Send a Kill RPC for `pty` and await the matching reply. Used by
/// the picker's `x` key.
async fn send_kill(
    conn: &mut Conn,
    next_id: &mut u64,
    pty: i32,
    force: bool,
) -> Result<()> {
    let request_id = *next_id;
    *next_id += 1;
    conn.send(LocalMessage::Call {
        request_id,
        payload: TapRequest::Kill { pty_index: pty, force },
    })
    .await?;
    loop {
        match conn.recv().await? {
            LocalMessage::Reply {
                request_id: rid,
                payload: TapResponse::Killed { .. },
            } if rid == request_id => return Ok(()),
            LocalMessage::Reply {
                request_id: rid,
                payload: TapResponse::Error(msg),
            } if rid == request_id => bail!("daemon: {msg}"),
            other => {
                tracing::debug!(?other, "tui: ignoring unexpected message during kill");
            }
        }
    }
}

/// Issue a `List` request and wait for the matching `Reply`. Used by
/// the TUI's periodic poll. Other (e.g. unrelated stream) messages on
/// the same connection would be unexpected here — the TUI's `Conn` is
/// only used for List — so we error if we see one.
async fn refresh_sessions(
    conn: &mut Conn,
    next_id: &mut u64,
) -> Result<Vec<hop_tap_protocol::SessionInfo>> {
    let request_id = *next_id;
    *next_id += 1;
    conn.send(LocalMessage::Call {
        request_id,
        payload: TapRequest::List,
    })
    .await?;
    loop {
        match conn.recv().await? {
            LocalMessage::Reply {
                request_id: rid,
                payload: TapResponse::SessionList(list),
            } if rid == request_id => return Ok(list),
            LocalMessage::Reply {
                request_id: rid,
                payload: TapResponse::Error(msg),
            } if rid == request_id => bail!("daemon: {msg}"),
            other => {
                // Unexpected — log and keep waiting briefly. In practice
                // shouldn't happen because Conn is only used for List.
                tracing::debug!(?other, "tui: ignoring unexpected message during refresh");
            }
        }
    }
}

/// Blocking stdin-byte reader. Runs on its own OS thread.
///
/// Single hot key: **Ctrl-T** detaches. Eaten on the spot — no tmux
/// overlap (tmux uses Ctrl-B), no two-key sequence, no doubling. From
/// the picker, the user reaches the shell with Ctrl-T then `q` in the
/// menu; from a direct `tap connect 3` invocation, Ctrl-T just exits
/// (no picker to fall back to).
///
/// Other bytes — including escape sequences from arrow keys, Alt-*,
/// function keys — pass through unchanged.
fn stdin_reader_loop(tx: mpsc::UnboundedSender<StdinEvent>) {
    const CTRL_T: u8 = 0x14;
    let mut buf = [0u8; 1024];
    loop {
        // SAFETY: read(2) on STDIN with our owned buffer.
        let n = unsafe {
            libc::read(libc::STDIN_FILENO, buf.as_mut_ptr() as *mut _, buf.len())
        };
        if n <= 0 {
            // EOF, error, or signal interrupt — let the channel drop
            // signal the caller.
            return;
        }
        let mut out: Vec<u8> = Vec::with_capacity(n as usize);
        for &b in &buf[..n as usize] {
            if b == CTRL_T {
                if !out.is_empty() {
                    let _ = tx.send(StdinEvent::Bytes(out));
                }
                let _ = tx.send(StdinEvent::Detach);
                return;
            }
            out.push(b);
        }
        if !out.is_empty() && tx.send(StdinEvent::Bytes(out)).is_err() {
            return;
        }
    }
}
