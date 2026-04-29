//! `hop-tap-d` — userspace daemon for the hop-tap extension.
//!
//! Loads the kernel-side eBPF program (compiled separately by
//! `hop-tap-ebpf` with vlad's rustc fork), attaches its kprobes /
//! tracepoints, and reads captured TTY events from per-CPU perf
//! arrays. Maintains an off-screen `alacritty_terminal::Term` per
//! session so it can produce a snapshot of the current screen
//! when a peer subscribes (Phase 1.7+).
//!
//! Phase 1.7 wires the daemon up as a Hop extension: with
//! `--bootstrap <path>` it writes a TOML rendezvous file, accepts
//! one hop daemon connection, performs the Hello/HelloAck handshake,
//! and dispatches `ExtMessage::Request`s to a `TapRequest` handler.
//! Without `--bootstrap` it runs standalone (the prior 1.5/1.6
//! behaviour: log a session summary every 5s).

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(version, about = "hop-tap eBPF terminal capture daemon")]
struct Args {
    /// Run as a Hop extension daemon: write a bootstrap rendezvous
    /// file at the given path and serve `ExtMessage` traffic on
    /// the ipc-channel server it advertises.
    ///
    /// Without this flag, hop-tap-d runs standalone (logs per-session
    /// summaries every 5 seconds; useful for development).
    #[arg(long)]
    bootstrap: Option<PathBuf>,

    /// Protocol version advertised in the bootstrap file. Must match
    /// the corresponding hop-side manifest's `version`.
    #[arg(long = "protocol-version", default_value = "0.1.0")]
    protocol_version: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    info!(
        version = env!("CARGO_PKG_VERSION"),
        bootstrap = ?args.bootstrap,
        "hop-tap-d starting"
    );

    #[cfg(target_os = "linux")]
    {
        linux::run(args).await
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!(
            "hop-tap-d only runs on Linux; this build is a workspace-resolution stub. \
             Cross-compile / run inside a Linux host or container."
        )
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Args;
    use hop_tap_d::extension::{write_bootstrap_atomically, ExtMessage};
    use hop_tap_d::protocol::{SessionInfo, TapRequest, TapResponse};
    use alacritty_terminal::{
        event::VoidListener,
        grid::Dimensions,
        index::{Column, Line, Point},
        term::{Config, Term},
        vte::ansi::Processor,
    };
    use anyhow::{bail, Context, Result};
    use aya::{
        include_bytes_aligned, maps::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
        Ebpf,
    };
    use aya_log::EbpfLogger;
    use bytes::BytesMut;
    use hop_tap_ebpf_common::{PtyWriteEvent, COMM_LEN, PTY_TYPE_MASTER, PTY_TYPE_SLAVE};
    use ipc_channel::ipc::{IpcOneShotServer, IpcSender};
    use std::{
        collections::HashMap,
        path::PathBuf,
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };
    use tokio::{signal, task::JoinSet, time::interval};
    use tracing::{debug, info, warn};

    /// Fallback dimensions used only until the first `pty_write`
    /// surfaces real ones. Most sessions will resize within
    /// milliseconds of opening (the shell's stty / SIGWINCH path).
    const FALLBACK_COLS: usize = 80;
    const FALLBACK_ROWS: usize = 24;

    /// Mutable `Dimensions` impl for `Term` construction and resize.
    /// `total_lines == screen_lines` so the grid carries no
    /// scrollback (per-session memory stays bounded; alacritty's
    /// default 10k-line history would inflate it ~400×).
    #[derive(Copy, Clone)]
    struct FixedDims {
        cols: usize,
        lines: usize,
    }
    impl Dimensions for FixedDims {
        fn total_lines(&self) -> usize {
            self.lines
        }
        fn screen_lines(&self) -> usize {
            self.lines
        }
        fn columns(&self) -> usize {
            self.cols
        }
    }

    static EBPF_OBJECT: &[u8] = include_bytes_aligned!(
        "../../hop-tap-ebpf/target/bpfel-unknown-none/release/hop-tap-ebpf"
    );

    struct SessionState {
        pty_index: i32,
        created_at: Instant,
        last_activity: Instant,
        last_pid: u32,
        last_comm: String,
        output_bytes: u64,
        input_bytes: u64,
        output_events: u64,
        input_events: u64,
        processor: Processor,
        term: Term<VoidListener>,
        dims: FixedDims,
    }

    impl SessionState {
        fn new(pty_index: i32, now: Instant, pid: u32, comm: String) -> Self {
            let dims = FixedDims {
                cols: FALLBACK_COLS,
                lines: FALLBACK_ROWS,
            };
            let mut config = Config::default();
            config.scrolling_history = 0;
            let term = Term::new(config, &dims, VoidListener);
            Self {
                pty_index,
                created_at: now,
                last_activity: now,
                last_pid: pid,
                last_comm: comm,
                output_bytes: 0,
                input_bytes: 0,
                output_events: 0,
                input_events: 0,
                processor: Processor::new(),
                term,
                dims,
            }
        }

        /// Resize the off-screen terminal if the kernel-reported
        /// dimensions have changed since our last update. Skips
        /// (0, 0) which the kernel surfaces for ptys that haven't
        /// been sized yet (e.g. immediately after open, before the
        /// terminal emulator issues TIOCSWINSZ).
        fn maybe_resize(&mut self, rows: u16, cols: u16) {
            if rows == 0 || cols == 0 {
                return;
            }
            let new_cols = cols as usize;
            let new_lines = rows as usize;
            if new_cols == self.dims.cols && new_lines == self.dims.lines {
                return;
            }
            self.dims = FixedDims {
                cols: new_cols,
                lines: new_lines,
            };
            self.term.resize(self.dims);
        }

        fn ingest_output(&mut self, bytes: &[u8]) {
            self.processor.advance(&mut self.term, bytes);
        }

        fn snapshot_last_line(&self) -> Option<String> {
            let grid = self.term.grid();
            let cols = self.dims.cols;
            let lines = self.dims.lines as i32;
            for line_idx in (0..lines).rev() {
                let row = self.read_row(grid, line_idx, cols);
                let trimmed = row.trim_end();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
            None
        }

        /// Render every visible row top-to-bottom into a `Vec<String>`.
        /// Trailing whitespace is preserved so the caller can decide
        /// whether to display fixed-width or trim.
        fn snapshot_full_screen(&self) -> Vec<String> {
            let grid = self.term.grid();
            let cols = self.dims.cols;
            let lines = self.dims.lines as i32;
            (0..lines)
                .map(|line_idx| self.read_row(grid, line_idx, cols))
                .collect()
        }

        fn read_row(
            &self,
            grid: &alacritty_terminal::grid::Grid<alacritty_terminal::term::cell::Cell>,
            line_idx: i32,
            cols: usize,
        ) -> String {
            let mut row = String::with_capacity(cols);
            for col in 0..cols {
                let p = Point::new(Line(line_idx), Column(col));
                row.push(grid[p].c);
            }
            row
        }

        fn to_session_info(&self) -> SessionInfo {
            SessionInfo {
                pty_index: self.pty_index,
                last_pid: self.last_pid,
                last_comm: self.last_comm.clone(),
                output_bytes: self.output_bytes,
                input_bytes: self.input_bytes,
                output_events: self.output_events,
                input_events: self.input_events,
                age_ms: self.created_at.elapsed().as_millis() as u64,
                idle_ms: self.last_activity.elapsed().as_millis() as u64,
            }
        }
    }

    type SessionTable = Arc<Mutex<HashMap<i32, SessionState>>>;

    pub async fn run(args: Args) -> Result<()> {
        bump_memlock();

        let mut bpf = Ebpf::load(EBPF_OBJECT).context("loading hop-tap-ebpf bytecode")?;
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            warn!("eBPF logger init failed (no log statements?): {e}");
        }

        attach_kprobes(&mut bpf)?;

        let mut perf: AsyncPerfEventArray<_> = bpf
            .take_map("PTY_EVENTS")
            .context("PTY_EVENTS map missing from bytecode")?
            .try_into()
            .context("PTY_EVENTS is not a PerfEventArray")?;

        let sessions: SessionTable = Arc::new(Mutex::new(HashMap::new()));

        let mut readers: JoinSet<()> = JoinSet::new();
        for cpu_id in online_cpus().map_err(|(_, e)| e).context("online_cpus")? {
            let mut buf = perf.open(cpu_id, Some(128)).context("perf open")?;
            let sessions = sessions.clone();
            readers.spawn(async move {
                let mut bufs =
                    vec![BytesMut::with_capacity(core::mem::size_of::<PtyWriteEvent>()); 16];
                loop {
                    let events = match buf.read_events(&mut bufs).await {
                        Ok(e) => e,
                        Err(e) => {
                            warn!(cpu = cpu_id, "perf read error: {e}");
                            break;
                        }
                    };
                    if events.lost > 0 {
                        warn!(cpu = cpu_id, lost = events.lost, "perf events dropped");
                    }
                    for raw in bufs.iter().take(events.read) {
                        let event = unsafe { &*(raw.as_ptr() as *const PtyWriteEvent) };
                        ingest_event(&sessions, cpu_id, event);
                    }
                }
            });
        }

        let summary_table = sessions.clone();
        let summary = tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(5));
            tick.tick().await; // skip the immediate fire
            loop {
                tick.tick().await;
                log_summary(&summary_table);
            }
        });

        // Extension thread: synchronous (ipc-channel is blocking),
        // owns the hop ↔ extension RPC. Joins through the SessionTable
        // Arc so request handlers can serve the latest state without
        // touching the tokio runtime directly.
        let ext_thread = if let Some(bootstrap) = args.bootstrap.clone() {
            let sessions = sessions.clone();
            let version = args.protocol_version.clone();
            Some(thread::spawn(move || {
                if let Err(e) = run_extension(bootstrap, version, sessions) {
                    warn!(error = %e, "extension thread exited with error");
                }
            }))
        } else {
            None
        };

        info!("hop-tap-d running; Ctrl-C to exit");
        signal::ctrl_c().await.context("ctrl-c")?;
        info!("shutting down");
        summary.abort();
        readers.abort_all();
        log_summary(&sessions);

        if let Some(path) = args.bootstrap.as_ref() {
            // Best-effort cleanup. The thread itself owns the
            // IpcOneShotServer and will tear it down when it exits;
            // we just remove the on-disk bootstrap so a stale entry
            // doesn't trick a future hop into trying to connect.
            let _ = std::fs::remove_file(path);
        }
        // We don't join the extension thread because ipc-channel's
        // recv has no cancellation primitive — exiting the process
        // closes the underlying socket and the thread will unwind.
        let _ = ext_thread;

        Ok(())
    }

    fn run_extension(
        bootstrap_path: PathBuf,
        protocol_version: String,
        sessions: SessionTable,
    ) -> Result<()> {
        let (server, server_name) = IpcOneShotServer::<ExtMessage>::new()
            .context("creating ipc-channel server")?;
        debug!(%server_name, "ipc-channel server bound");

        write_bootstrap_atomically(&bootstrap_path, &server_name, &protocol_version)?;
        info!(path = %bootstrap_path.display(), "bootstrap written; awaiting hop Hello");

        let (rx_from_hop, hello) = server.accept().context("waiting for hop Hello")?;
        let reverse_name = match hello {
            ExtMessage::Hello {
                hop_version,
                reverse_name,
            } => {
                info!(%hop_version, "hop connected");
                reverse_name
            }
            other => bail!("expected Hello from hop, got {:?}", other),
        };

        let tx_to_hop: IpcSender<ExtMessage> =
            IpcSender::connect(reverse_name).context("connecting to hop reverse server")?;
        tx_to_hop
            .send(ExtMessage::HelloAck {
                ext_version: protocol_version,
            })
            .context("sending HelloAck")?;
        info!("extension handshake complete");

        loop {
            let msg = match rx_from_hop.recv() {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = ?e, "ipc-channel recv failed; shutting down");
                    break;
                }
            };
            match msg {
                ExtMessage::Request {
                    request_id,
                    payload,
                    ..
                } => {
                    let response_payload = serve_request(&sessions, &payload);
                    if tx_to_hop
                        .send(ExtMessage::Response {
                            request_id,
                            ok: true,
                            payload: response_payload,
                        })
                        .is_err()
                    {
                        warn!("send to hop failed; shutting down");
                        break;
                    }
                }
                ExtMessage::StreamOpen { request_id, .. } => {
                    let _ = tx_to_hop.send(ExtMessage::StreamClosed {
                        stream_id: request_id,
                        reason: Some("hop-tap streaming not yet implemented".into()),
                    });
                }
                other => debug!(?other, "ignored non-Request message"),
            }
        }

        Ok(())
    }

    /// Decode a `TapRequest` from `payload`, run the handler, encode
    /// the `TapResponse`. Decode failures are surfaced as an error
    /// response so the peer always sees something well-formed.
    fn serve_request(sessions: &SessionTable, payload: &[u8]) -> Vec<u8> {
        let cfg = bincode::config::standard();
        let req: TapRequest = match bincode::serde::decode_from_slice(payload, cfg) {
            Ok((req, _)) => req,
            Err(e) => {
                let err = TapResponse::Error(format!("decode TapRequest: {e}"));
                return bincode::serde::encode_to_vec(&err, cfg).unwrap_or_default();
            }
        };
        let resp = handle_tap_request(sessions, req);
        bincode::serde::encode_to_vec(&resp, cfg).unwrap_or_default()
    }

    fn handle_tap_request(sessions: &SessionTable, req: TapRequest) -> TapResponse {
        match req {
            TapRequest::List => {
                let table = sessions.lock().expect("session table mutex poisoned");
                let mut infos: Vec<SessionInfo> = table.values().map(|s| s.to_session_info()).collect();
                infos.sort_by_key(|i| i.pty_index);
                TapResponse::SessionList(infos)
            }
            TapRequest::Snapshot { pty_index } => {
                let table = sessions.lock().expect("session table mutex poisoned");
                match table.get(&pty_index) {
                    Some(s) => TapResponse::Snapshot {
                        pty_index,
                        rows: s.dims.lines as u16,
                        cols: s.dims.cols as u16,
                        contents: s.snapshot_full_screen(),
                    },
                    None => TapResponse::Error(format!(
                        "no active session with pty_index={pty_index}"
                    )),
                }
            }
        }
    }

    fn ingest_event(sessions: &SessionTable, cpu_id: u32, event: &PtyWriteEvent) {
        let now = Instant::now();
        let comm = comm_to_string(&event.comm);

        let mut table = sessions.lock().expect("session table mutex poisoned");
        let state = table
            .entry(event.pty_index)
            .or_insert_with(|| SessionState::new(event.pty_index, now, event.pid, comm.clone()));
        state.last_activity = now;
        state.last_pid = event.pid;
        state.last_comm = comm;
        // Apply the kernel-reported window size *before* feeding bytes,
        // so escape sequences that depend on dimensions (e.g. cursor
        // positioning to "row N where N is the last row") interpret
        // against the right grid.
        state.maybe_resize(event.rows, event.cols);
        let captured = event.captured_len.min(event.data.len() as u16) as usize;
        match event.subtype {
            PTY_TYPE_SLAVE => {
                state.output_bytes += event.total_len as u64;
                state.output_events += 1;
                state.ingest_output(&event.data[..captured]);
            }
            PTY_TYPE_MASTER => {
                state.input_bytes += event.total_len as u64;
                state.input_events += 1;
            }
            _ => {}
        }
        drop(table);

        let dir = direction_label(event.subtype);
        let captured = event.captured_len.min(event.data.len() as u16) as usize;
        let preview = printable_preview(&event.data[..captured], 48);
        let truncated = event.captured_len as u32 != event.total_len;
        debug!(
            cpu = cpu_id,
            pty = event.pty_index,
            pid = event.pid,
            comm = %comm_to_string(&event.comm),
            dir,
            captured = event.captured_len,
            total = event.total_len,
            truncated,
            "{preview}"
        );
    }

    fn direction_label(subtype: u16) -> &'static str {
        match subtype {
            PTY_TYPE_MASTER => "master→slave (input)",
            PTY_TYPE_SLAVE => "slave→master (output)",
            _ => "unknown",
        }
    }

    fn log_summary(sessions: &SessionTable) {
        let table = sessions.lock().expect("session table mutex poisoned");
        if table.is_empty() {
            info!("session summary: (no active sessions)");
            return;
        }
        info!("session summary: {} active session(s)", table.len());
        let mut rows: Vec<&SessionState> = table.values().collect();
        rows.sort_by_key(|s| s.pty_index);
        for s in rows {
            let idle_ms = s.last_activity.elapsed().as_millis();
            let age_ms = s.created_at.elapsed().as_millis();
            let snapshot = s.snapshot_last_line().unwrap_or_else(|| "(blank)".into());
            info!(
                pty = s.pty_index,
                comm = %s.last_comm,
                last_pid = s.last_pid,
                out_bytes = s.output_bytes,
                in_bytes = s.input_bytes,
                out_events = s.output_events,
                in_events = s.input_events,
                age_ms,
                idle_ms,
                "  session — last screen line: {snapshot}"
            );
        }
    }

    fn comm_to_string(comm: &[u8; COMM_LEN]) -> String {
        let end = comm.iter().position(|&b| b == 0).unwrap_or(COMM_LEN);
        String::from_utf8_lossy(&comm[..end]).into_owned()
    }

    fn bump_memlock() {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) } != 0 {
            warn!("setrlimit(RLIMIT_MEMLOCK, INFINITY) failed; pre-5.11 kernels may reject map allocs");
        }
    }

    fn attach_kprobes(bpf: &mut Ebpf) -> Result<()> {
        let prog: &mut KProbe = bpf
            .program_mut("pty_write_handler")
            .context("pty_write_handler program missing from bytecode")?
            .try_into()?;
        prog.load().context("loading pty_write_handler")?;
        prog.attach("pty_write", 0)
            .context("attaching pty_write_handler to kprobe:pty_write")?;
        Ok(())
    }

    fn printable_preview(bytes: &[u8], max_chars: usize) -> String {
        let mut out = String::with_capacity(bytes.len());
        for &b in bytes {
            if out.len() >= max_chars {
                out.push('…');
                break;
            }
            match b {
                0x20..=0x7e => out.push(b as char),
                b'\n' => out.push_str("\\n"),
                b'\r' => out.push_str("\\r"),
                b'\t' => out.push_str("\\t"),
                0x1b => out.push_str("\\e"),
                _ => out.push_str(&format!("\\x{:02x}", b)),
            }
        }
        out
    }
}
