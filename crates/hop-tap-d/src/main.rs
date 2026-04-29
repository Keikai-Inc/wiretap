//! `hop-tap-d` — userspace daemon for the hop-tap extension.
//!
//! Loads the kernel-side eBPF program (compiled separately by
//! `hop-tap-ebpf` with vlad's rustc fork), attaches its kprobes /
//! tracepoints, and reads captured TTY events from per-CPU perf
//! arrays. Maintains an off-screen `alacritty_terminal::Term` per
//! session so it can produce a snapshot of the current screen
//! when a peer subscribes (Phase 1.7+).
//!
//! Phase 1.6 wires the emulator: each session owns a `Term`
//! (alacritty's full state machine — colors, cursor, alt-screen,
//! scroll regions, the lot). The slave→master byte stream is
//! driven through `vte::ansi::Processor::advance` so all CSI / OSC
//! / ESC sequences land in the right cell-grid mutations.

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "hop-tap-d starting");

    #[cfg(target_os = "linux")]
    {
        linux::run().await
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!(
            "hop-tap-d only runs on Linux; this build is a workspace-resolution stub. \
             Cross-compile / run inside a Linux host or container."
        )
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result};
    use aya::{
        include_bytes_aligned, maps::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
        Ebpf,
    };
    use aya_log::EbpfLogger;
    use bytes::BytesMut;
    use hop_tap_ebpf_common::{PtyWriteEvent, COMM_LEN, PTY_TYPE_MASTER, PTY_TYPE_SLAVE};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use alacritty_terminal::{
        event::VoidListener,
        grid::Dimensions,
        index::{Column, Line, Point},
        term::{Config, Term},
        vte::ansi::Processor,
    };
    use tokio::{signal, task::JoinSet, time::interval};
    use tracing::{debug, info, warn};

    /// Default off-screen terminal dimensions. Real implementations
    /// will track SIGWINCH / TIOCSWINSZ events to learn the actual
    /// shell-side size; for Phase 1.6 we assume the conventional
    /// 80x24 terminal.
    const SURFACE_COLS: usize = 80;
    const SURFACE_ROWS: usize = 24;

    /// Trivial `Dimensions` impl for constructing a `Term` at fixed
    /// rows × cols. We match `screen_lines` and `total_lines` so the
    /// grid has no scrollback (we never read it), reducing per-session
    /// memory footprint.
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

    /// Per-session running state, accumulated from `pty_write`
    /// events as they stream in.
    ///
    /// Keyed by `pty_index` (`tty_struct.index`) — the unit number
    /// the kernel assigns to a pty pair. Both master and slave ends
    /// of a pair share the same index, so input keystrokes (master
    /// → slave) and program output (slave → master) accumulate into
    /// one row.
    ///
    /// `last_*` fields are best-effort; a long-running session may
    /// see many different writers (`bash` → `vim` → `bash` again as
    /// the user runs commands). Phase 1.6 will replace per-event
    /// `comm` snapshots with a real session-lifecycle model that
    /// records the controlling process at session creation.
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
        // Off-screen terminal state. The processor parses the
        // slave→master byte stream and applies actions to the
        // alacritty `Term`'s cell grid — full CSI / OSC / ESC
        // semantics, the same state machine that drives Alacritty.
        processor: Processor,
        term: Term<VoidListener>,
        dims: FixedDims,
    }

    impl SessionState {
        fn new(pty_index: i32, now: Instant, pid: u32, comm: String) -> Self {
            let dims = FixedDims {
                cols: SURFACE_COLS,
                lines: SURFACE_ROWS,
            };
            // Disable scrollback — at 80×24, even a default 10k-line
            // history would multiply per-session memory by ~400×.
            // Phase 1.7+ can reintroduce a small scrollback if/when
            // we expose it to peers.
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

        /// Feed a slave→master chunk through the processor. Every
        /// byte (printable, control, escape) lands in the right
        /// cell-grid mutation via alacritty's `Handler` impl on
        /// `Term`. Kernel-side bytes are *truncated* at MAX_CHUNK so
        /// long writes are partially captured — the emulator stays
        /// well-defined within the captured prefix.
        fn ingest_output(&mut self, bytes: &[u8]) {
            self.processor.advance(&mut self.term, bytes);
        }

        /// Return the most recent non-empty line on screen, trimmed
        /// of trailing whitespace. `None` if the screen is blank.
        fn snapshot_last_line(&self) -> Option<String> {
            let grid = self.term.grid();
            let cols = self.dims.cols;
            let lines = self.dims.lines as i32;
            // Walk bottom-up so we find the most recent line first.
            for line_idx in (0..lines).rev() {
                let mut row = String::with_capacity(cols);
                for col in 0..cols {
                    let p = Point::new(Line(line_idx), Column(col));
                    row.push(grid[p].c);
                }
                let trimmed = row.trim_end();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
            None
        }
    }

    type SessionTable = Arc<Mutex<HashMap<i32, SessionState>>>;

    pub async fn run() -> Result<()> {
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

        // Periodic session summary. Stand-in for the peer-facing
        // `list` command — keeps the operator informed of what's
        // captured without spamming the per-event log.
        let summary_table = sessions.clone();
        let summary = tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(5));
            tick.tick().await; // skip the immediate fire
            loop {
                tick.tick().await;
                log_summary(&summary_table);
            }
        });

        info!("hop-tap-d running; Ctrl-C to exit");
        signal::ctrl_c().await.context("ctrl-c")?;
        info!("shutting down");
        summary.abort();
        readers.abort_all();
        log_summary(&sessions);
        Ok(())
    }

    /// Update the session table for a single decoded event and emit
    /// a debug-level event log line.
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
        let captured = event.captured_len.min(event.data.len() as u16) as usize;
        match event.subtype {
            PTY_TYPE_SLAVE => {
                state.output_bytes += event.total_len as u64;
                state.output_events += 1;
                // Drive the off-screen surface from output bytes only.
                // Master→slave traffic is what the user typed, which
                // doesn't contribute to on-screen state directly (the
                // shell will echo it back through slave→master if
                // appropriate).
                state.ingest_output(&event.data[..captured]);
            }
            PTY_TYPE_MASTER => {
                state.input_bytes += event.total_len as u64;
                state.input_events += 1;
            }
            _ => {}
        }
        drop(table);

        // Detailed event log at debug level so the default-info
        // summary stays readable. Run with `RUST_LOG=hop_tap_d=debug`
        // to see every byte chunk.
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

    /// Snapshot the session table and print one log line per
    /// session, plus a header.
    fn log_summary(sessions: &SessionTable) {
        let table = sessions.lock().expect("session table mutex poisoned");
        if table.is_empty() {
            info!("session summary: (no active sessions)");
            return;
        }
        info!("session summary: {} active session(s)", table.len());
        // Stable order so successive logs are easy to diff.
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

    /// Convert the kernel's NUL-padded 16-byte comm buffer into a
    /// human-readable String. Trims at the first NUL.
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

    /// Render captured bytes as a single-line preview suitable for a
    /// log field. Printable ASCII stays as-is; control codes (CR/LF,
    /// escape sequences, etc.) become `\xNN`. Truncates to `max_chars`
    /// rendered chars and appends an ellipsis on truncation.
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
