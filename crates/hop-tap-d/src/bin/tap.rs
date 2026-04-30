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
//!   tap connect <pty>        attach: live output + your stdin →
//!                            session input. Detach with Ctrl-B d.
//!   tap repl                 interactive multi-command session
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
    /// Attach to a session bidirectionally: live output to your
    /// terminal, your keystrokes injected into the session. Detach
    /// with Ctrl-B then d (tmux-style); Ctrl-C is forwarded as input.
    Connect {
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

    // No subcommand → run the TUI picker. The picker may return a
    // follow-up action (Connect/Watch/Snapshot a chosen pty) which
    // we run after tearing down the TUI.
    let cmd = match args.cmd {
        Some(c) => c,
        None => match run_tui(&args.socket).await? {
            Some(TuiAction::Connect(pty)) => Cmd::Connect { pty },
            Some(TuiAction::Watch(pty)) => Cmd::Watch { pty },
            Some(TuiAction::Snapshot(pty)) => Cmd::Snapshot { pty },
            None => return Ok(()),
        },
    };

    let stream = UnixStream::connect(&args.socket).await.with_context(|| {
        format!(
            "connecting to {}\n(is hop-tap-d running?  `sudo systemctl status hop-tap`)",
            args.socket.display()
        )
    })?;

    let mut next_id = 1u64;
    match cmd {
        // Connect takes ownership of the stream so it can split it
        // into owned read/write halves and run the bidirectional loop.
        Cmd::Connect { pty } => connect(stream, &mut next_id, pty).await,
        cmd => {
            let mut conn = Conn::new(stream);
            match cmd {
                Cmd::List => one_shot(&mut conn, &mut next_id, TapRequest::List).await,
                Cmd::Snapshot { pty } => {
                    one_shot(
                        &mut conn,
                        &mut next_id,
                        TapRequest::Snapshot { pty_index: pty },
                    )
                    .await
                }
                Cmd::Watch { pty } => watch(&mut conn, &mut next_id, pty).await,
                Cmd::Repl => repl(&mut conn, &mut next_id).await,
                Cmd::Connect { .. } => unreachable!(),
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
        TapResponse::Injected {
            pty_index,
            bytes_written,
        } => {
            println!("injected {bytes_written} byte(s) into pty={pty_index}");
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
    /// User pressed the detach hotkey (Ctrl-B then 'd'). Tear down.
    Detach,
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

/// `tap connect <pty>` — bidirectional attach.
///
/// 1. Open a Subscribe stream so we receive Output frames just like
///    `watch`. The Initial frame gives us a render of the current
///    screen as a "catch up" replay.
/// 2. Put the local terminal into raw mode so keystrokes don't get
///    line-buffered or interpreted by the local shell.
/// 3. Spawn a blocking thread that reads bytes from stdin and pushes
///    them on a channel. The thread also runs the detach state
///    machine (Ctrl-B then 'd' → Detach event; bare Ctrl-B held one
///    keystroke and emitted on the next non-'d' byte).
/// 4. The main task selects between incoming server frames (write to
///    stdout) and stdin events (send Inject Calls). Either side
///    closing or a Detach event ends the loop; the RawModeGuard
///    restores the terminal on the way out.
async fn connect(stream: UnixStream, next_id: &mut u64, pty: i32) -> Result<()> {
    let (mut read_half, mut write_half) = stream.into_split();

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

    // 2. Raw mode + Drop-guarded restore.
    crossterm::terminal::enable_raw_mode().context("enable raw mode")?;
    let _raw = RawModeGuard;
    eprintln!("\r\n[tap connect pty={pty} — detach with Ctrl-B d]\r\n");

    // 3. Blocking stdin reader on a dedicated thread. tokio::io::stdin
    //    is blocking-on-a-thread under the hood anyway, and doing it
    //    ourselves means we control the read buffer and the detach
    //    state machine without an extra layer.
    let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<StdinEvent>();
    std::thread::spawn(move || {
        stdin_reader_loop(stdin_tx);
    });

    // 4. Main multiplex loop. Use a separate request_id space for
    //    Injects so they don't collide with the Subscribe id.
    let mut inject_id: u64 = sub_request_id.wrapping_add(1);
    let mut stdout = std::io::stdout().lock();
    loop {
        tokio::select! {
            biased;
            // Drain stdin first so user keystrokes don't queue up
            // behind a flood of output. Important when watching a
            // chatty session — we want responsive typing.
            evt = stdin_rx.recv() => match evt {
                Some(StdinEvent::Bytes(b)) => {
                    inject_id = inject_id.wrapping_add(1);
                    if let Err(e) = send_local(
                        &mut write_half,
                        &LocalMessage::Call {
                            request_id: inject_id,
                            payload: TapRequest::Inject { pty_index: pty, bytes: b },
                        },
                    ).await {
                        // Connection is gone — break and let the guard restore.
                        eprintln!("\r\n[connect: send failed: {e}]\r");
                        return Ok(());
                    }
                }
                Some(StdinEvent::Detach) | None => {
                    eprintln!("\r\n[detached]\r");
                    return Ok(());
                }
            },
            msg = recv_local(&mut read_half) => {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("\r\n[connect: server closed: {e}]\r");
                        return Ok(());
                    }
                };
                match msg {
                    LocalMessage::StreamFrame { stream_id: sid, payload } if sid == stream_id => {
                        match payload {
                            TapStreamFrame::Initial { replay_bytes, .. } => {
                                let _ = stdout.write_all(b"\x1b[2J\x1b[H");
                                let _ = stdout.write_all(&replay_bytes);
                                let _ = stdout.flush();
                            }
                            TapStreamFrame::Output(b) => {
                                let _ = stdout.write_all(&b);
                                let _ = stdout.flush();
                            }
                            // Resize is informational — we don't propagate
                            // to the local terminal. The user's terminal
                            // size is already what they care about.
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
                        return Ok(());
                    }
                    // Inject ack: TapResponse::Injected. Fire-and-forget;
                    // we don't surface per-keystroke confirmations.
                    LocalMessage::Reply { .. } => {}
                    // Stale frame from a previous stream id, etc.
                    _ => {}
                }
            }
        }
    }
}

/// What the TUI picker returns to `main` so the caller knows which
/// follow-up subcommand to run on a freshly-opened connection. The
/// TUI cleans itself up first; the action is then dispatched through
/// the same path as if the user had typed the subcommand directly.
enum TuiAction {
    Connect(i32),
    Watch(i32),
    Snapshot(i32),
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

    loop {
        // Refresh if it's been long enough. Errors are surfaced into
        // the status line so the picker keeps working with stale data
        // rather than dying.
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
                        "{} session(s) — ↑/↓ select  enter=connect  w=watch  s=snapshot  q=quit",
                        sessions.len()
                    );
                }
                Err(e) => {
                    status_line = format!("refresh error: {e}");
                }
            }
            last_refresh = Instant::now();
        }

        // Render.
        term.draw(|f| {
            let area = f.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(0),
                    Constraint::Length(1),
                ])
                .split(area);

            let header = Paragraph::new("tap — terminal session picker")
                .block(Block::default().borders(Borders::ALL).title("hop-tap"));
            f.render_widget(header, chunks[0]);

            let header_row = Row::new(vec![
                Cell::from("pty"),
                Cell::from("user"),
                Cell::from("comm"),
                Cell::from("out (b/ev)"),
                Cell::from("in (b/ev)"),
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
                        Cell::from(format!("{}/{}", s.output_bytes, s.output_events)),
                        Cell::from(format!("{}/{}", s.input_bytes, s.input_events)),
                        Cell::from(format!("{}ms", s.age_ms)),
                        Cell::from(format!("{}ms", s.idle_ms)),
                    ])
                })
                .collect();

            let widths = [
                Constraint::Length(5),
                Constraint::Length(20),
                Constraint::Length(14),
                Constraint::Length(14),
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(10),
            ];
            let table = Table::new(rows, widths)
                .header(header_row)
                .block(Block::default().borders(Borders::ALL).title("sessions"))
                .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            f.render_stateful_widget(table, chunks[1], &mut state);

            let status = Paragraph::new(status_line.clone());
            f.render_widget(status, chunks[2]);
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
                    (KeyCode::Char('w'), _) => {
                        if let Some(s) = state.selected().and_then(|i| sessions.get(i)) {
                            return Ok(Some(TuiAction::Watch(s.pty_index)));
                        }
                    }
                    (KeyCode::Char('s'), _) => {
                        if let Some(s) = state.selected().and_then(|i| sessions.get(i)) {
                            return Ok(Some(TuiAction::Snapshot(s.pty_index)));
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
/// Reads raw bytes from FD 0 and forwards them as `StdinEvent::Bytes`,
/// except for the detach sequence (Ctrl-B then 'd') which produces
/// `StdinEvent::Detach`. A bare Ctrl-B is held back one keystroke; if
/// the next byte isn't 'd', we emit Ctrl-B followed by that byte —
/// so users who legitimately need Ctrl-B (rare in modern shells) only
/// pay a one-keystroke latency.
fn stdin_reader_loop(tx: mpsc::UnboundedSender<StdinEvent>) {
    const CTRL_B: u8 = 0x02;
    let mut buf = [0u8; 1024];
    let mut detach_armed = false;
    loop {
        // SAFETY: read(2) on a valid fd, into our owned buffer.
        let n = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        };
        if n <= 0 {
            // EOF, error, or signal interrupt — let the channel drop
            // signal the connect task.
            return;
        }
        let mut out: Vec<u8> = Vec::with_capacity(n as usize);
        for &b in &buf[..n as usize] {
            if detach_armed {
                detach_armed = false;
                if b == b'd' {
                    if !out.is_empty() {
                        let _ = tx.send(StdinEvent::Bytes(out));
                    }
                    let _ = tx.send(StdinEvent::Detach);
                    return;
                }
                // Held-back Ctrl-B was a real keystroke — emit it.
                out.push(CTRL_B);
                out.push(b);
            } else if b == CTRL_B {
                detach_armed = true;
            } else {
                out.push(b);
            }
        }
        if !out.is_empty() && tx.send(StdinEvent::Bytes(out)).is_err() {
            return;
        }
    }
}
