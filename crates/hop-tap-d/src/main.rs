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
//! Phase 1.5 wires in: per-CPU perf-array readers feed events into
//! a shared `SessionTable` keyed by `tty_struct.index`. Both ends of
//! a pty pair share the same index, so events from either direction
//! roll up into the same logical session. A periodic task logs a
//! summary every 5s — this stands in for the eventual peer-facing
//! `list` command landing in Phase 1.7.

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
    use tokio::{signal, task::JoinSet, time::interval};
    use tracing::{debug, info, warn};

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
    #[derive(Debug)]
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
            .or_insert_with(|| SessionState {
                pty_index: event.pty_index,
                created_at: now,
                last_activity: now,
                last_pid: event.pid,
                last_comm: comm.clone(),
                output_bytes: 0,
                input_bytes: 0,
                output_events: 0,
                input_events: 0,
            });
        state.last_activity = now;
        state.last_pid = event.pid;
        state.last_comm = comm;
        match event.subtype {
            PTY_TYPE_SLAVE => {
                state.output_bytes += event.total_len as u64;
                state.output_events += 1;
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
                "  session"
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
