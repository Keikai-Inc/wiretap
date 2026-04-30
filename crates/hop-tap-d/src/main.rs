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

    /// Local Unix socket path the `tap` CLI connects to. Mode 0666
    /// — any local user can connect; SO_PEERCRED authenticates the
    /// caller's uid.
    #[arg(long = "local-socket")]
    local_socket: Option<std::path::PathBuf>,
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
    mod local;
    mod master_fd;

    use super::Args;
    use hop_tap_d::extension::{write_bootstrap_atomically, ExtMessage};
    use hop_tap_d::protocol::{
        SessionInfo, TapRequest, TapResponse, TapStreamFrame, TapStreamRequest,
    };
    use tokio::sync::mpsc;
    use alacritty_terminal::{
        event::VoidListener,
        grid::Dimensions,
        index::{Column, Line, Point},
        term::{
            cell::{Cell, Flags},
            Config, Term, TermMode,
        },
        vte::ansi::{Color, Processor},
    };
    use anyhow::{bail, Context, Result};
    use aya::{
        include_bytes_aligned, maps::AsyncPerfEventArray, programs::KProbe, util::online_cpus,
        Ebpf,
    };
    use aya_log::EbpfLogger;
    use bytes::BytesMut;
    use hop_tap_ebpf_common::{
        PtyEndEvent, PtyWriteEvent, COMM_LEN, PTY_TYPE_MASTER, PTY_TYPE_SLAVE,
    };
    use ipc_channel::ipc::{IpcOneShotServer, IpcSender};
    use std::{
        collections::HashMap,
        io::Write as _,
        os::fd::RawFd,
        path::PathBuf,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };
    use tokio::{runtime::Handle, signal, task::JoinSet, time::interval};
    use tracing::{debug, info, warn};

    /// Cross-transport subscriber message carried over per-stream
    /// mpsc channels. Each transport (hop ipc-channel, local unix
    /// socket) owns its own forwarder task that drains the channel
    /// and converts to its wire format. ingest_event and
    /// ingest_end_event are transport-agnostic — they fan out
    /// SubscriberMsgs without caring how each gets to the subscriber.
    #[derive(Debug, Clone)]
    pub(crate) enum SubscriberMsg {
        Frame(TapStreamFrame),
        Close(Option<String>),
    }

    /// Per-subscriber bookkeeping: the channel we forward
    /// SubscriberMsgs to, plus enough context to do cycle detection
    /// when *another* subscriber tries to open against this one's
    /// peer. `peer_controlling_pty` is None for hop callers (their
    /// tty isn't on this host).
    pub(crate) struct StreamRecord {
        pub tx: mpsc::UnboundedSender<SubscriberMsg>,
        pub peer_controlling_pty: Option<i32>,
        pub target_pty: i32,
    }

    /// Daemon-shared registry of active stream subscribers, keyed
    /// by stream_id.
    pub(crate) type StreamsMap = Arc<Mutex<HashMap<u64, StreamRecord>>>;

    // Phase 1.8g replaced the rolling-byte replay buffer with a
    // deterministic grid walk in `render_grid_to_bytes`. The
    // alacritty Term carries the canonical state; we synthesize
    // escape sequences from it when a subscriber attaches. This
    // is strictly better: the byte buffer could start mid-CSI and
    // confuse a fresh terminal, while the grid render is always
    // self-contained.

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
        // The "opener" — sticky values captured the very first time
        // we saw this pty. For sessions that started after the
        // daemon was launched, this is the controlling shell's
        // first writer (typically the bash that printed the
        // prompt). For pre-existing sessions we missed the actual
        // open, so opener_* is just "first writer the daemon
        // observed." Documented limit; future work could capture
        // session-creation specifically via a tty_open hook.
        opener_pid: u32,
        opener_comm: String,
        opener_uid: u32,
        opener_gid: u32,
        // The most recent writer. Diverges from opener_* under
        // sudo, su, or just any time another process exec's into
        // the session.
        last_pid: u32,
        last_comm: String,
        last_uid: u32,
        last_gid: u32,
        output_bytes: u64,
        input_bytes: u64,
        output_events: u64,
        input_events: u64,
        processor: Processor,
        term: Term<VoidListener>,
        dims: FixedDims,
        // stream_ids currently subscribed to live updates from this
        // session. Most sessions have zero subscribers so the fan-out
        // hot path is just an `is_empty()` check.
        subscribers: Vec<u64>,
        // PID that most recently issued a master→slave (input)
        // pty_write — i.e., the process holding a writable copy of
        // the master fd (sshd, tmux server, local terminal emulator).
        // Tracked separately from `last_pid` because `last_pid` is
        // dominated by slave→master writes (the shell's output) and
        // therefore points at the wrong process for fd cloning.
        // 0 means we haven't observed an input event yet for this
        // session — fall back to a /proc scan in that case.
        master_holder_pid: u32,
        // A daemon-owned writable fd cloned from the master holder
        // via `pidfd_getfd`. -1 means "not yet captured" or "stale,
        // re-clone next time". Closed in `Drop` so we don't leak fds
        // when sessions end.
        master_fd: RawFd,
        // Admin-locked: the session's foreground pgrp has been
        // SIGSTOPped. The user's keystrokes pile up in the kernel
        // pty input buffer but the shell isn't reading. Cleared on
        // SetLock(false), which also flushes the input queue and
        // SIGCONTs.
        locked: bool,
        // Admin-quarantined: a sandboxed impostor bash has taken
        // over the captured pty. The real shell is SIGSTOPped in
        // the background. `quarantine_impostor_pid` is the PID of
        // the impostor process the daemon spawned;
        // `quarantine_orig_pgrp` is the pgrp we SIGSTOPped so we
        // know what to SIGCONT on release.
        quarantined: bool,
        quarantine_impostor_pid: Option<u32>,
        quarantine_orig_pgrp: Option<i32>,
    }

    impl Drop for SessionState {
        fn drop(&mut self) {
            if self.master_fd >= 0 {
                unsafe {
                    libc::close(self.master_fd);
                }
            }
        }
    }

    impl SessionState {
        fn new(
            pty_index: i32,
            now: Instant,
            pid: u32,
            comm: String,
            uid: u32,
            gid: u32,
        ) -> Self {
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
                opener_pid: pid,
                opener_comm: comm.clone(),
                opener_uid: uid,
                opener_gid: gid,
                last_pid: pid,
                last_comm: comm,
                last_uid: uid,
                last_gid: gid,
                output_bytes: 0,
                input_bytes: 0,
                output_events: 0,
                input_events: 0,
                processor: Processor::new(),
                term,
                dims,
                subscribers: Vec::new(),
                master_holder_pid: 0,
                master_fd: -1,
                locked: false,
                quarantined: false,
                quarantine_impostor_pid: None,
                quarantine_orig_pgrp: None,
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
                opener_pid: self.opener_pid,
                opener_comm: self.opener_comm.clone(),
                opener_uid: self.opener_uid,
                opener_gid: self.opener_gid,
                opener_username: lookup_username(self.opener_uid),
                last_pid: self.last_pid,
                last_comm: self.last_comm.clone(),
                last_uid: self.last_uid,
                last_gid: self.last_gid,
                last_username: lookup_username(self.last_uid),
                output_bytes: self.output_bytes,
                input_bytes: self.input_bytes,
                output_events: self.output_events,
                input_events: self.input_events,
                age_ms: self.created_at.elapsed().as_millis() as u64,
                idle_ms: self.last_activity.elapsed().as_millis() as u64,
                locked: self.locked,
                quarantined: self.quarantined,
            }
        }
    }

    /// Render the alacritty Term's current grid as a self-contained
    /// byte sequence that, when written to a fresh terminal,
    /// reproduces the screen state with colors and basic attributes.
    ///
    /// Output shape:
    ///   ESC [2J ESC [H ESC [0m              clear, home, reset
    ///   ESC [<row>;1H                       per-row cursor placement
    ///   ESC [0;<flags>;<fg>;<bg>m  <chars>  per-cell SGR + char
    ///   ...
    ///   ESC [0m                              final attribute reset
    ///   ESC [<cy>;<cx>H                     final cursor position
    ///
    /// We emit a fresh `\x1b[0;...m` SGR per attribute change rather
    /// than computing a true diff — slightly more bytes on the wire,
    /// significantly simpler logic, and not on a hot path (only
    /// fires when a subscriber attaches).
    ///
    /// Skips `WIDE_CHAR_SPACER` cells (the placeholder column after
    /// a wide char) and steps the column cursor by 2 on the wide
    /// char itself.
    fn render_grid_to_bytes(state: &SessionState) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(state.dims.cols * state.dims.lines * 8);
        // Always start by resetting the receiver's primary screen.
        out.extend_from_slice(b"\x1b[2J\x1b[H\x1b[0m");

        // If the captured session is currently using the alternate
        // screen (vim, less, htop, mc, fzf — anything that does
        // full-screen "take over the whole window"), put the
        // receiver into the alt screen too before drawing. Otherwise
        // the receiver would render vim's content onto its primary
        // screen, and the eventual `\x1b[?1049l` from the live
        // stream would leave them in a confused state with vim
        // leftovers visible.
        //
        // `\x1b[?1049h` is xterm's combined "save cursor + enter
        // alt screen + clear alt screen". The matching exit will
        // arrive in the live byte stream when the captured session
        // exits alt screen normally.
        let in_alt = state.term.mode().contains(TermMode::ALT_SCREEN);
        if in_alt {
            out.extend_from_slice(b"\x1b[?1049h\x1b[2J\x1b[H");
        }

        let grid = state.term.grid();
        let dims = state.dims;
        let mut last_attrs: Option<(Color, Color, Flags)> = None;

        for line_idx in 0..dims.lines as i32 {
            let _ = write!(out, "\x1b[{};1H", line_idx + 1);
            let mut col = 0usize;
            while col < dims.cols {
                let p = Point::new(Line(line_idx), Column(col));
                let cell = &grid[p];

                // Skip the placeholder column for a wide char; the
                // wide char itself was already emitted in the prior
                // iteration.
                if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                    col += 1;
                    continue;
                }

                let attrs = (cell.fg, cell.bg, cell.flags);
                if last_attrs.as_ref() != Some(&attrs) {
                    emit_sgr(&mut out, cell);
                    last_attrs = Some(attrs);
                }

                let mut buf = [0u8; 4];
                let s = cell.c.encode_utf8(&mut buf);
                out.extend_from_slice(s.as_bytes());

                col += if cell.flags.contains(Flags::WIDE_CHAR) { 2 } else { 1 };
            }
        }

        // Final reset and cursor placement.
        out.extend_from_slice(b"\x1b[0m");
        let cursor_pt = grid.cursor.point;
        let _ = write!(
            out,
            "\x1b[{};{}H",
            cursor_pt.line.0 + 1,
            cursor_pt.column.0 + 1
        );

        out
    }

    /// Emit an SGR sequence that establishes `cell`'s attributes
    /// from a fully-reset state. Always starts with `\x1b[0` so the
    /// receiver doesn't accumulate stale flags from prior cells.
    fn emit_sgr(out: &mut Vec<u8>, cell: &Cell) {
        out.extend_from_slice(b"\x1b[0");
        if cell.flags.contains(Flags::BOLD) {
            out.extend_from_slice(b";1");
        }
        if cell.flags.contains(Flags::DIM) {
            out.extend_from_slice(b";2");
        }
        if cell.flags.contains(Flags::ITALIC) {
            out.extend_from_slice(b";3");
        }
        if cell.flags.intersects(Flags::ALL_UNDERLINES) {
            out.extend_from_slice(b";4");
        }
        if cell.flags.contains(Flags::INVERSE) {
            out.extend_from_slice(b";7");
        }
        if cell.flags.contains(Flags::HIDDEN) {
            out.extend_from_slice(b";8");
        }
        if cell.flags.contains(Flags::STRIKEOUT) {
            out.extend_from_slice(b";9");
        }
        emit_color(out, cell.fg, /* fg = */ true);
        emit_color(out, cell.bg, /* fg = */ false);
        out.extend_from_slice(b"m");
    }

    fn emit_color(out: &mut Vec<u8>, color: Color, is_fg: bool) {
        let base = if is_fg { 30 } else { 40 };
        let bright_base = if is_fg { 90 } else { 100 };
        let default_code = if is_fg { 39 } else { 49 };
        let extended_lead = if is_fg { 38 } else { 48 };
        match color {
            Color::Named(named) => {
                let n = named as u32;
                if n < 8 {
                    let _ = write!(out, ";{}", base + n);
                } else if n < 16 {
                    let _ = write!(out, ";{}", bright_base + (n - 8));
                } else {
                    // Foreground / Background / Cursor / Dim* / etc.
                    // — fall back to "default" for unknown nameds.
                    let _ = write!(out, ";{}", default_code);
                }
            }
            Color::Indexed(idx) if idx < 8 => {
                let _ = write!(out, ";{}", base + idx as u32);
            }
            Color::Indexed(idx) if idx < 16 => {
                let _ = write!(out, ";{}", bright_base + (idx - 8) as u32);
            }
            Color::Indexed(idx) => {
                let _ = write!(out, ";{};5;{}", extended_lead, idx);
            }
            Color::Spec(rgb) => {
                let _ = write!(out, ";{};2;{};{};{}", extended_lead, rgb.r, rgb.g, rgb.b);
            }
        }
    }

    /// One pre-existing session discovered by the /proc walk at
    /// startup. Used to seed [`SessionTable`] so sessions opened
    /// before the daemon got their accurate opener identity (the
    /// actual session leader) rather than the "first writer the
    /// daemon happened to observe" approximation.
    struct SeedRow {
        pty_index: i32,
        pid: u32,
        comm: String,
        uid: u32,
        gid: u32,
    }

    /// Walk `/proc/*/` and find session leaders attached to a pty.
    /// A process is a session leader iff its sid (the 4th field
    /// after the parenthesised comm in `/proc/<pid>/stat`) equals
    /// its pid; that's the canonical way the kernel marks the
    /// process that "owns" a pty for terminal-control purposes.
    ///
    /// We then walk the leader's fd table and report the first
    /// `/dev/pts/N` symlink we find — that's the pts index our
    /// kprobe-side `tty_struct.index` will match.
    ///
    /// Errors on individual processes are silently swallowed
    /// (processes can vanish mid-walk; permission can deny reads
    /// for other-uid procs even with CAP_SYS_PTRACE-less daemons).
    /// Returns the rows we did manage to identify.
    fn walk_proc_for_session_leaders() -> Vec<SeedRow> {
        let mut out = Vec::new();
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return out;
        };
        for entry in dir.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Some((sid, comm)) = parse_proc_stat(pid) else {
                continue;
            };
            if sid != pid {
                continue; // not a session leader
            }
            let Some(pty_index) = pty_index_for_pid(pid) else {
                continue;
            };
            let Some((uid, gid)) = parse_proc_status_uid_gid(pid) else {
                continue;
            };
            out.push(SeedRow {
                pty_index,
                pid,
                comm,
                uid,
                gid,
            });
        }
        out
    }

    /// Parse `/proc/<pid>/stat` for `(sid, comm)`. The comm field is
    /// parenthesised; it can contain spaces, parens, or anything
    /// else, so we locate it via the LAST `)` in the file (the
    /// kernel prints it as `(${task->comm})` with the binary's
    /// raw name).
    fn parse_proc_stat(pid: u32) -> Option<(u32, String)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let comm_start = stat.find('(')?;
        let comm_end = stat.rfind(')')?;
        if comm_end <= comm_start {
            return None;
        }
        let comm = stat[comm_start + 1..comm_end].to_string();
        // After "(comm) " the remaining fields are space-separated:
        //   state, ppid, pgrp, session, tty_nr, ...
        let after = stat.get(comm_end + 2..)?;
        let fields: Vec<&str> = after.split_whitespace().collect();
        // session is field index 3 (0=state, 1=ppid, 2=pgrp, 3=session)
        let sid: u32 = fields.get(3)?.parse().ok()?;
        Some((sid, comm))
    }

    fn parse_proc_status_uid_gid(pid: u32) -> Option<(u32, u32)> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let mut uid: Option<u32> = None;
        let mut gid: Option<u32> = None;
        for line in status.lines() {
            // "Uid:	real	effective	saved	fs"
            if let Some(rest) = line.strip_prefix("Uid:") {
                uid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
            } else if let Some(rest) = line.strip_prefix("Gid:") {
                gid = rest.split_whitespace().next().and_then(|s| s.parse().ok());
            }
            if uid.is_some() && gid.is_some() {
                break;
            }
        }
        Some((uid?, gid?))
    }

    /// Walk `/proc/<pid>/fd/*` and return the first `/dev/pts/N`
    /// symlink target we find. None if the process has no pts fd
    /// open or we can't read the directory (permissions / vanished
    /// process).
    fn pty_index_for_pid(pid: u32) -> Option<i32> {
        let dir = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
        for entry in dir.flatten() {
            let Ok(target) = std::fs::read_link(entry.path()) else {
                continue;
            };
            let Some(s) = target.to_str() else { continue };
            if let Some(rest) = s.strip_prefix("/dev/pts/") {
                if let Ok(n) = rest.parse::<i32>() {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Best-effort uid → username resolution via `getpwuid_r`.
    /// Returns None if the uid isn't in the daemon's view of
    /// /etc/passwd. Container PID/user namespacing routinely makes
    /// this happen — the session uid may not exist on the host
    /// where hop-tap-d runs. We surface that as `None` rather than
    /// fabricating a name; callers display "uid=NNN" instead.
    fn lookup_username(uid: u32) -> Option<String> {
        // Buffer size: passwd entries are typically <256 B; sysconf
        // _SC_GETPW_R_SIZE_MAX is the kernel's recommended ceiling.
        // 4 KiB is a safe upper bound that avoids the EINVAL/ERANGE
        // dance for resizing.
        let mut buf = vec![0u8; 4096];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return None;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
        Some(name.to_string_lossy().into_owned())
    }

    /// Read `/proc/<pid>/stat` and decode the controlling terminal's
    /// pty index, if any. Returns `None` for processes that have no
    /// controlling tty (daemons), processes whose controlling tty is
    /// not a pty slave (e.g. /dev/console), or if /proc isn't
    /// available.
    ///
    /// In `/proc/<pid>/stat`, field 7 (1-indexed) is `tty_nr`, encoded
    /// as `(major << 8) | minor` per the kernel's old_encode_dev. For
    /// /dev/pts/N (UNIX98 pty slaves) major == 136 and minor == N.
    /// We accept any major in the 136..=143 range — the kernel
    /// allocates additional pty-slave majors when /dev/pts is large.
    ///
    /// Parsing the line is a little finicky: field 2 is `comm` and
    /// can contain whitespace + parens, so we anchor on the closing
    /// paren and split the rest by whitespace.
    fn controlling_pty_for_pid(pid: i32) -> Option<i32> {
        let path = format!("/proc/{pid}/stat");
        let stat = std::fs::read_to_string(&path).ok()?;
        let close = stat.rfind(')')?;
        let after = stat.get(close + 1..)?.trim_start();
        let fields: Vec<&str> = after.split_whitespace().collect();
        // After the comm/paren we've stripped:
        //   fields[0] = state (e.g. R)
        //   fields[1] = ppid
        //   fields[2] = pgrp
        //   fields[3] = session
        //   fields[4] = tty_nr  ← we want this one
        let tty_nr: u32 = fields.get(4)?.parse().ok()?;
        if tty_nr == 0 {
            return None; // no controlling tty
        }
        let major = (tty_nr >> 8) & 0xff;
        let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
        if (136..=143).contains(&major) {
            Some(minor as i32)
        } else {
            None
        }
    }

    type SessionTable = Arc<Mutex<HashMap<i32, SessionState>>>;

    /// Identity of the peer making this request, as reported by the
    /// hop daemon in `ExtMessage::Request` / `ExtMessage::StreamOpen`.
    /// We trust these fields — hop authenticated the QUIC connection
    /// before forwarding the call, so the peer_id / peer_username /
    /// peer_role are vouched for by the hop daemon's auth layer.
    #[derive(Debug, Clone)]
    struct PeerContext {
        /// Opaque peer identifier (NodeId). Carried for future audit
        /// logging; not currently used for authorization decisions
        /// (which key off `peer_username` and `peer_role`).
        #[allow(dead_code)]
        peer_id: String,
        peer_username: Option<String>,
        peer_role: String,
        /// Local-socket only: the pty index that this connection's
        /// peer process is itself running on (i.e., the user's own
        /// terminal). Used to:
        ///   - hide that pty from List/Snapshot results so the user
        ///     doesn't see their own shell
        ///   - refuse Subscribe / Inject targeting that pty (would
        ///     be a self-loop)
        ///   - detect 2-cycles when a different connection has the
        ///     reverse subscription open (outer tap on pts/A attached
        ///     to pts/B, inner tap on pts/B asks for pts/A)
        /// `None` for hop extension callers (their tty is on a remote
        /// host, so no local cycle is possible) and for connections
        /// whose /proc lookup failed.
        controlling_pty: Option<i32>,
    }

    impl PeerContext {
        /// Authorization gate. Returns true if `peer` is allowed to
        /// see / interact with `state`.
        ///
        /// Policy:
        /// - `peer_role == "creator"` is the admin tier and sees
        ///   every session.
        /// - Any other role can only see sessions whose
        ///   `opener_username` matches the peer's username. If
        ///   either side is unknown (None), deny — explicit identity
        ///   is required for non-admin access.
        ///
        /// Username comparison is case-sensitive byte equality. We
        /// don't try to resolve container/host UID namespacing
        /// mismatches here; that's a richer policy concern for
        /// later phases.
        fn scope_allows(&self, state: &SessionState) -> bool {
            if self.peer_role == "creator" {
                return true;
            }
            match (&self.peer_username, lookup_username(state.opener_uid)) {
                (Some(peer), Some(opener)) => peer == &opener,
                _ => false,
            }
        }
    }

    /// Daemon-shared handle for sending `ExtMessage` to the connected
    /// hop daemon. Populated once the handshake completes; checked by
    /// both the request-handler thread (to send Responses) and the
    /// per-CPU tokio readers (to fan out live `StreamFrame`s to
    /// subscribers).
    ///
    /// The Mutex is held only across a single `.send()` call. Brief
    /// contention with thousands of events/sec is fine; if it ever
    /// becomes hot we can swap to a dedicated writer thread + mpsc.
    type WriterSlot = Arc<Mutex<Option<IpcSender<ExtMessage>>>>;

    pub async fn run(args: Args) -> Result<()> {
        bump_memlock();

        // Defensive: ignore SIGHUP. The daemon never has a meaningful
        // controlling tty, but if some future code path opens a pty
        // device without O_NOCTTY the kernel could (a) make that pty
        // our controlling tty and (b) deliver SIGHUP to us when its
        // user closes the terminal, killing the daemon. Belt and
        // suspenders alongside the per-open O_NOCTTY flags.
        // SAFETY: signal(2) with a valid signum + SIG_IGN.
        unsafe {
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }

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
        let mut perf_end: AsyncPerfEventArray<_> = bpf
            .take_map("PTY_END_EVENTS")
            .context("PTY_END_EVENTS map missing from bytecode")?
            .try_into()
            .context("PTY_END_EVENTS is not a PerfEventArray")?;

        let sessions: SessionTable = Arc::new(Mutex::new(HashMap::new()));
        let writer: WriterSlot = Arc::new(Mutex::new(None));
        let streams: StreamsMap = Arc::new(Mutex::new(HashMap::new()));
        let next_stream_id: Arc<AtomicU64> = Arc::new(AtomicU64::new(1));

        // Seed pre-existing sessions from /proc before readers start
        // pulling events. This way sessions that opened before the
        // daemon was launched get their actual session-leader
        // identity recorded as `opener_*` rather than whichever
        // sub-process happens to write first.
        //
        // Order matters: we do this AFTER kprobe attach (so events
        // start queueing) but BEFORE spawning the per-CPU readers
        // (so the live event drain doesn't race-create entries with
        // wrong opener metadata). A live event for a pty we seeded
        // will hit `entry().or_insert_with` as a no-op and just
        // update `last_*` — exactly what we want.
        let seeds = walk_proc_for_session_leaders();
        if !seeds.is_empty() {
            let now = Instant::now();
            let mut table = sessions.lock().expect("session table mutex poisoned");
            for s in seeds {
                let comm = s.comm.clone();
                table.entry(s.pty_index).or_insert_with(|| {
                    SessionState::new(s.pty_index, now, s.pid, comm, s.uid, s.gid)
                });
            }
            info!(seeded = table.len(), "seeded pre-existing sessions from /proc");
        }

        let mut readers: JoinSet<()> = JoinSet::new();
        let cpus = online_cpus().map_err(|(_, e)| e).context("online_cpus")?;
        for cpu_id in &cpus {
            let cpu_id = *cpu_id;
            let mut buf = perf.open(cpu_id, Some(128)).context("perf open")?;
            let sessions = sessions.clone();
            let streams = streams.clone();
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
                        ingest_event(&sessions, &streams, cpu_id, event);
                    }
                }
            });
        }
        for cpu_id in &cpus {
            let cpu_id = *cpu_id;
            let mut buf = perf_end.open(cpu_id, Some(8)).context("perf_end open")?;
            let sessions = sessions.clone();
            let streams = streams.clone();
            readers.spawn(async move {
                let mut bufs =
                    vec![BytesMut::with_capacity(core::mem::size_of::<PtyEndEvent>()); 8];
                loop {
                    let events = match buf.read_events(&mut bufs).await {
                        Ok(e) => e,
                        Err(e) => {
                            warn!(cpu = cpu_id, "perf_end read error: {e}");
                            break;
                        }
                    };
                    if events.lost > 0 {
                        warn!(cpu = cpu_id, lost = events.lost, "session-end events dropped");
                    }
                    for raw in bufs.iter().take(events.read) {
                        let event = unsafe { &*(raw.as_ptr() as *const PtyEndEvent) };
                        ingest_end_event(&sessions, &streams, event);
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
            let writer = writer.clone();
            let streams = streams.clone();
            let next_stream_id = next_stream_id.clone();
            let rt_handle = Handle::current();
            let version = args.protocol_version.clone();
            Some(thread::spawn(move || {
                if let Err(e) = run_extension(
                    bootstrap,
                    version,
                    sessions,
                    writer,
                    streams,
                    next_stream_id,
                    rt_handle,
                ) {
                    warn!(error = %e, "extension thread exited with error");
                }
            }))
        } else {
            None
        };

        // Always listen on the local Unix socket so the `tap` CLI
        // works without hop. SO_PEERCRED gives us authoritative
        // caller identity; we don't trust the client's claims.
        let local_socket_path = args
            .local_socket
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("/run/hop-tap/local.sock"));
        let local_sessions = sessions.clone();
        let local_streams = streams.clone();
        let local_next_id = next_stream_id.clone();
        readers.spawn(async move {
            let peer_for_uid = |uid: u32, pid: Option<i32>| -> PeerContext {
                let controlling_pty = pid.and_then(controlling_pty_for_pid);
                if uid == 0 {
                    PeerContext {
                        peer_id: format!("local:uid={uid}"),
                        peer_username: Some("root".to_string()),
                        peer_role: "creator".to_string(),
                        controlling_pty,
                    }
                } else {
                    PeerContext {
                        peer_id: format!("local:uid={uid}"),
                        peer_username: lookup_username(uid),
                        peer_role: "peer".to_string(),
                        controlling_pty,
                    }
                }
            };
            if let Err(e) = local::run_local_listener(
                local_socket_path,
                local_sessions,
                local_streams,
                local_next_id,
                peer_for_uid,
            )
            .await
            {
                warn!(error = %e, "local listener exited");
            }
        });

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
        writer: WriterSlot,
        streams: StreamsMap,
        next_stream_id: Arc<AtomicU64>,
        rt_handle: Handle,
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
        // Publish the sender so tokio-side fan-out (live StreamFrames)
        // can write to the same hop connection.
        *writer.lock().expect("writer mutex poisoned") = Some(tx_to_hop.clone());
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
                    peer_id,
                    peer_username,
                    peer_role,
                    payload,
                } => {
                    let peer = PeerContext {
                        peer_id,
                        peer_username,
                        peer_role,
                        // Hop peers connect from another machine; their
                        // controlling tty isn't on this host, so the
                        // local-cycle / self-tap checks don't apply.
                        controlling_pty: None,
                    };
                    let response_payload = serve_request(&sessions, &peer, &payload);
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
                ExtMessage::StreamOpen {
                    request_id,
                    peer_id,
                    peer_username,
                    peer_role,
                    payload,
                } => {
                    let peer = PeerContext {
                        peer_id,
                        peer_username,
                        peer_role,
                        // Hop peers connect from another machine; their
                        // controlling tty isn't on this host, so the
                        // local-cycle / self-tap checks don't apply.
                        controlling_pty: None,
                    };
                    handle_stream_open(
                        &sessions,
                        &streams,
                        &next_stream_id,
                        &rt_handle,
                        &tx_to_hop,
                        &peer,
                        request_id,
                        &payload,
                    );
                }
                ExtMessage::StreamClose { stream_id } => {
                    handle_stream_close(&sessions, stream_id);
                }
                other => debug!(?other, "ignored unsupported message"),
            }
        }

        // Tear down the writer slot so any tokio readers know not to
        // try sending past this point.
        *writer.lock().expect("writer mutex poisoned") = None;
        Ok(())
    }

    /// Decode the stream-open payload, find the requested session,
    /// register the subscriber, and send `StreamOpened` followed by
    /// the `Initial` frame containing the session's recent byte
    /// history. If the request can't be served (decode failure or
    /// missing pty), reply with `StreamClosed { reason: ... }`.
    /// Result of a successful subscribe: the assigned stream_id
    /// and the receiver each transport's forwarder drains. The
    /// caller (hop extension or local socket handler) is
    /// responsible for sending its transport-specific "stream
    /// opened" message and spawning a forwarder.
    pub(crate) struct SubscribeOk {
        pub stream_id: u64,
        pub rx: mpsc::UnboundedReceiver<SubscriberMsg>,
    }

    /// Validate access, allocate a stream_id, register the
    /// subscriber, queue the Initial frame onto the channel.
    /// Returns Err with a "no session with pty_index=N"-shaped
    /// message on missing session OR forbidden access (same wording
    /// for both, so callers can't enumerate other users' ptys by
    /// probing).
    pub(crate) fn register_subscriber(
        sessions: &SessionTable,
        streams: &StreamsMap,
        next_stream_id: &Arc<AtomicU64>,
        peer: &PeerContext,
        pty_index: i32,
    ) -> Result<SubscribeOk, String> {
        // Self-tap: peer's own controlling tty is the target. Refuse
        // with the same not-found wording so we don't leak whether
        // the session is real but yours vs. simply absent.
        if Some(pty_index) == peer.controlling_pty {
            return Err(format!("no session with pty_index={pty_index}"));
        }

        // Cycle detection. The peer (running on its own pty `peer_pty`)
        // is asking to subscribe to `pty_index`. If some *other*
        // existing subscriber's record says `target_pty == peer_pty
        // && peer_controlling_pty == pty_index`, then attaching here
        // would close a feedback loop:
        //
        //     peer_pty ── attaches to ──> pty_index
        //         ▲                            │
        //         └── attaches to ─── other ───┘
        //
        // That's the "outer tap on pts/A is attached to pts/B; inside
        // pts/B you run another tap and pick pts/A" scenario. Refuse.
        if let Some(peer_pty) = peer.controlling_pty {
            let map = streams.lock().expect("streams mutex poisoned");
            let cycle = map.values().any(|r| {
                r.target_pty == peer_pty && r.peer_controlling_pty == Some(pty_index)
            });
            if cycle {
                return Err(format!(
                    "subscribe would create a tap feedback loop with pty_index={pty_index}"
                ));
            }
        }

        let stream_id = next_stream_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel::<SubscriberMsg>();

        let initial = {
            let mut table = sessions.lock().expect("session table mutex poisoned");
            let Some(state) = table.get_mut(&pty_index) else {
                return Err(format!("no session with pty_index={pty_index}"));
            };
            if !peer.scope_allows(state) {
                return Err(format!("no session with pty_index={pty_index}"));
            }
            state.subscribers.push(stream_id);
            TapStreamFrame::Initial {
                rows: state.dims.lines as u16,
                cols: state.dims.cols as u16,
                replay_bytes: render_grid_to_bytes(state),
            }
        };

        // Pre-queue the Initial frame so the forwarder writes it
        // first. Send is infallible here — we just created the
        // receiver and haven't given it away yet.
        let _ = tx.send(SubscriberMsg::Frame(initial));

        streams
            .lock()
            .expect("streams mutex poisoned")
            .insert(
                stream_id,
                StreamRecord {
                    tx,
                    peer_controlling_pty: peer.controlling_pty,
                    target_pty: pty_index,
                },
            );
        info!(stream_id, pty_index, "stream subscribed");
        Ok(SubscribeOk { stream_id, rx })
    }

    /// Hop-side stream open: decode the TapStreamRequest payload,
    /// register the subscriber, send StreamOpened, then spawn a
    /// forwarder task that drains the SubscriberMsg channel and
    /// converts each message to ExtMessage::StreamFrame /
    /// StreamClosed.
    fn handle_stream_open(
        sessions: &SessionTable,
        streams: &StreamsMap,
        next_stream_id: &Arc<AtomicU64>,
        rt_handle: &Handle,
        tx_to_hop: &IpcSender<ExtMessage>,
        peer: &PeerContext,
        request_id: u64,
        payload: &[u8],
    ) {
        let cfg = bincode::config::standard();
        let req: TapStreamRequest = match bincode::serde::decode_from_slice(payload, cfg) {
            Ok((req, _)) => req,
            Err(e) => {
                // No stream_id allocated yet, but hop expects a
                // close on the request_id. Reuse request_id as the
                // synthetic stream_id for the failure case.
                let _ = tx_to_hop.send(ExtMessage::StreamClosed {
                    stream_id: request_id,
                    reason: Some(format!("decode TapStreamRequest: {e}")),
                });
                return;
            }
        };
        let TapStreamRequest::Subscribe { pty_index } = req;

        match register_subscriber(sessions, streams, next_stream_id, peer, pty_index) {
            Err(reason) => {
                let _ = tx_to_hop.send(ExtMessage::StreamClosed {
                    stream_id: request_id,
                    reason: Some(reason),
                });
            }
            Ok(SubscribeOk { stream_id, rx }) => {
                if tx_to_hop
                    .send(ExtMessage::StreamOpened {
                        request_id,
                        stream_id,
                    })
                    .is_err()
                {
                    // hop hung up before we could open; drop the
                    // subscriber.
                    streams.lock().unwrap().remove(&stream_id);
                    return;
                }
                let tx_clone = tx_to_hop.clone();
                let streams = streams.clone();
                let sessions = sessions.clone();
                rt_handle.spawn(async move {
                    forward_to_hop(stream_id, pty_index, rx, tx_clone, streams, sessions).await;
                });
            }
        }
    }

    /// Hop-side per-stream forwarder. Drains the SubscriberMsg
    /// channel and converts each to ExtMessage::StreamFrame or
    /// StreamClosed. On any send error, exits; on receiver close
    /// (channel dropped), exits with no further wire writes (other
    /// side already saw the StreamClosed via Close path).
    async fn forward_to_hop(
        stream_id: u64,
        pty_index: i32,
        mut rx: mpsc::UnboundedReceiver<SubscriberMsg>,
        tx_to_hop: IpcSender<ExtMessage>,
        streams: StreamsMap,
        sessions: SessionTable,
    ) {
        let cfg = bincode::config::standard();
        while let Some(msg) = rx.recv().await {
            match msg {
                SubscriberMsg::Frame(frame) => {
                    let payload = match bincode::serde::encode_to_vec(&frame, cfg) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(stream_id, "encode TapStreamFrame: {e}");
                            break;
                        }
                    };
                    if tx_to_hop
                        .send(ExtMessage::StreamFrame { stream_id, payload })
                        .is_err()
                    {
                        break;
                    }
                }
                SubscriberMsg::Close(reason) => {
                    let _ = tx_to_hop.send(ExtMessage::StreamClosed { stream_id, reason });
                    break;
                }
            }
        }
        cleanup_stream(stream_id, pty_index, &streams, &sessions);
    }

    /// Remove a finished stream from the daemon's bookkeeping.
    pub(crate) fn cleanup_stream(
        stream_id: u64,
        pty_index: i32,
        streams: &StreamsMap,
        sessions: &SessionTable,
    ) {
        streams
            .lock()
            .expect("streams mutex poisoned")
            .remove(&stream_id);
        if let Ok(mut table) = sessions.lock() {
            if let Some(state) = table.get_mut(&pty_index) {
                state.subscribers.retain(|&id| id != stream_id);
            }
        }
    }

    /// Handle a PtyEndEvent from the kernel. Removes the session
    /// (idempotent — the event fires once per side of a pty pair, so
    /// the second one for the same index naturally finds nothing to
    /// remove) and proactively closes any active stream subscribers
    /// by sending SubscriberMsg::Close on each subscriber's channel.
    /// Each transport's forwarder picks that up and writes the right
    /// wire-level Closed message.
    fn ingest_end_event(sessions: &SessionTable, streams: &StreamsMap, event: &PtyEndEvent) {
        let subscribers: Vec<u64> = {
            let mut table = sessions.lock().expect("session table mutex poisoned");
            match table.remove(&event.pty_index) {
                Some(state) => {
                    info!(
                        pty = event.pty_index,
                        comm = %state.last_comm,
                        out_bytes = state.output_bytes,
                        in_bytes = state.input_bytes,
                        "session ended"
                    );
                    // SessionState now owns a cached master fd that
                    // Drop closes — so we can't move `subscribers`
                    // out of `state`. Clone the small Vec<u64> instead
                    // and let `state` Drop normally as it goes out of
                    // scope.
                    state.subscribers.clone()
                }
                None => return,
            }
        };
        if subscribers.is_empty() {
            return;
        }
        let guard = streams.lock().expect("streams mutex poisoned");
        for stream_id in subscribers {
            if let Some(rec) = guard.get(&stream_id) {
                let _ = rec.tx.send(SubscriberMsg::Close(Some("session ended".into())));
            }
        }
    }

    fn handle_stream_close(sessions: &SessionTable, stream_id: u64) {
        let mut table = sessions.lock().expect("session table mutex poisoned");
        for state in table.values_mut() {
            state.subscribers.retain(|&id| id != stream_id);
        }
        info!(stream_id, "stream closed");
    }

    /// Fan-out payload built inside the sessions lock and applied
    /// outside it (so we never hold sessions + writer locks at the
    /// same time).
    struct FanOut {
        subscribers: Vec<u64>,
        /// Some(bytes) if this event carried slave→master output to
        /// forward; None for input or empty events.
        live_bytes: Option<Vec<u8>>,
        /// Some((rows, cols)) if the kernel-reported dimensions
        /// changed on this event.
        dim_change: Option<(u16, u16)>,
    }

    /// Fan out one event's frames to each subscribed stream. Looks
    /// up each stream_id in the StreamsMap and sends via its
    /// per-stream mpsc channel. Closed channels (subscriber
    /// disconnected) just drop silently — the forwarder task
    /// handles its own cleanup when it exits.
    fn fan_out(streams: &StreamsMap, f: FanOut) {
        if f.subscribers.is_empty() {
            return;
        }
        let mut to_emit: Vec<SubscriberMsg> = Vec::new();
        if let Some((rows, cols)) = f.dim_change {
            to_emit.push(SubscriberMsg::Frame(TapStreamFrame::Resize { rows, cols }));
        }
        if let Some(bytes) = f.live_bytes {
            to_emit.push(SubscriberMsg::Frame(TapStreamFrame::Output(bytes)));
        }
        if to_emit.is_empty() {
            return;
        }
        let guard = streams.lock().expect("streams mutex poisoned");
        for &sid in &f.subscribers {
            if let Some(rec) = guard.get(&sid) {
                for msg in &to_emit {
                    let _ = rec.tx.send(msg.clone());
                }
            }
        }
    }

    /// Decode a `TapRequest` from `payload`, run the handler, encode
    /// the `TapResponse`. Decode failures are surfaced as an error
    /// response so the peer always sees something well-formed.
    fn serve_request(sessions: &SessionTable, peer: &PeerContext, payload: &[u8]) -> Vec<u8> {
        let cfg = bincode::config::standard();
        let req: TapRequest = match bincode::serde::decode_from_slice(payload, cfg) {
            Ok((req, _)) => req,
            Err(e) => {
                let err = TapResponse::Error(format!("decode TapRequest: {e}"));
                return bincode::serde::encode_to_vec(&err, cfg).unwrap_or_default();
            }
        };
        let resp = handle_tap_request(sessions, peer, req);
        bincode::serde::encode_to_vec(&resp, cfg).unwrap_or_default()
    }

    fn handle_tap_request(
        sessions: &SessionTable,
        peer: &PeerContext,
        req: TapRequest,
    ) -> TapResponse {
        match req {
            TapRequest::List => {
                // Filter to only the sessions this peer is allowed
                // to see. `creator` role peers see everything; other
                // roles see only their own sessions.
                //
                // Additionally, hide the peer's *own* controlling tty
                // — running `tap` from pts/N shouldn't surface pts/N
                // in the picker. Self-tap would loop the peer's own
                // terminal output back through itself.
                let self_pty = peer.controlling_pty;
                let table = sessions.lock().expect("session table mutex poisoned");
                let mut infos: Vec<SessionInfo> = table
                    .values()
                    .filter(|s| peer.scope_allows(s))
                    .filter(|s| Some(s.pty_index) != self_pty)
                    .map(|s| s.to_session_info())
                    .collect();
                infos.sort_by_key(|i| i.pty_index);
                TapResponse::SessionList(infos)
            }
            TapRequest::Snapshot { pty_index } => {
                // Self-snapshot would feed the peer's own terminal
                // back to itself. Refuse with the same not-found
                // error used for unauthorized lookups so the result
                // is consistent regardless of why it's denied.
                if Some(pty_index) == peer.controlling_pty {
                    return TapResponse::Error(format!(
                        "no active session with pty_index={pty_index}"
                    ));
                }
                let table = sessions.lock().expect("session table mutex poisoned");
                match table.get(&pty_index) {
                    Some(s) if peer.scope_allows(s) => TapResponse::Snapshot {
                        pty_index,
                        rows: s.dims.lines as u16,
                        cols: s.dims.cols as u16,
                        contents: s.snapshot_full_screen(),
                    },
                    Some(_) => {
                        // Session exists but this peer can't see it.
                        // Surface as the same error as "doesn't exist"
                        // so the response can't be used to enumerate
                        // other users' ptys by probing.
                        TapResponse::Error(format!(
                            "no active session with pty_index={pty_index}"
                        ))
                    }
                    None => TapResponse::Error(format!(
                        "no active session with pty_index={pty_index}"
                    )),
                }
            }
            TapRequest::Inject { pty_index, bytes } => {
                handle_inject(sessions, peer, pty_index, &bytes)
            }
            TapRequest::Kill { pty_index, force } => {
                handle_kill(sessions, peer, pty_index, force)
            }
            TapRequest::AdminMessage {
                pty_index,
                message,
                from,
            } => handle_admin_message(sessions, peer, pty_index, &message, &from),
            TapRequest::SetLock { pty_index, locked } => {
                handle_set_lock(sessions, peer, pty_index, locked)
            }
            TapRequest::SetQuarantine { pty_index, quarantined } => {
                handle_set_quarantine(sessions, peer, pty_index, quarantined)
            }
        }
    }

    /// Transition a session into the honeypot sandbox (or release
    /// it back to the real shell).
    ///
    /// Lock semantics: quarantine implies lock. We SIGSTOP the
    /// foreground pgrp (same primitive as SetLock), open the
    /// captured slave fd, and spawn `tap-honeypot pty-attach` with
    /// that fd as stdin/stdout/stderr. The impostor does setsid +
    /// TIOCSCTTY-steal so it becomes the controlling process of
    /// the captured tty.
    ///
    /// Release: kill the impostor, SIGCONT the original pgrp. The
    /// real shell wakes up. Note: TIOCSCTTY-steal cleared its
    /// controlling-tty pointer (tty_nr=0 in /proc/<pid>/stat), so
    /// `foreground_pgrp_via_tty` won't find it on the next
    /// quarantine attempt — `pgrp_for_session` falls back to
    /// reading the shell's pgrp directly from
    /// /proc/<opener_pid>/stat field 5.
    ///
    /// Authorization: opener-or-creator (same as Inject + Lock).
    fn handle_set_quarantine(
        sessions: &SessionTable,
        peer: &PeerContext,
        pty_index: i32,
        quarantined: bool,
    ) -> TapResponse {
        if Some(pty_index) == peer.controlling_pty {
            return TapResponse::Error(format!(
                "no active session with pty_index={pty_index}"
            ));
        }
        // Scope + write-permission check.
        {
            let table = sessions.lock().expect("session table mutex poisoned");
            let Some(state) = table.get(&pty_index) else {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            };
            if !peer.scope_allows(state) {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            }
            if !peer_can_inject(peer, state) {
                return TapResponse::Error(format!(
                    "forbidden: only the session opener (or a creator-role peer) \
                     may quarantine pty_index={pty_index}"
                ));
            }
        }

        if quarantined {
            quarantine_session(sessions, pty_index)
        } else {
            release_quarantine(sessions, pty_index)
        }
    }

    /// Activate the honeypot for `pty_index`. Idempotent in the
    /// sense that a second call on an already-quarantined session
    /// returns success without spawning another impostor (the
    /// existing one is still alive).
    fn quarantine_session(sessions: &SessionTable, pty_index: i32) -> TapResponse {
        // Snapshot the relevant state under the lock, then drop it
        // so we can do the slow fork+exec without blocking other
        // handlers. We re-acquire to write the result back.
        let (already_quarantined, opener_uid, opener_pid, opener_username) = {
            let table = sessions.lock().expect("session table mutex poisoned");
            let Some(state) = table.get(&pty_index) else {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            };
            (
                state.quarantined,
                state.opener_uid,
                state.opener_pid,
                lookup_username(state.opener_uid)
                    .unwrap_or_else(|| format!("uid{}", state.opener_uid)),
            )
        };
        if already_quarantined {
            // Re-quarantining is a no-op — surface the existing
            // impostor PID so the caller's UI matches reality.
            let impostor_pid = sessions
                .lock()
                .ok()
                .and_then(|t| t.get(&pty_index).and_then(|s| s.quarantine_impostor_pid));
            return TapResponse::QuarantineSet {
                pty_index,
                quarantined: true,
                impostor_pid,
            };
        }

        // SIGSTOP the right pgrp. Use pgrp_for_session so we cope
        // with the post-release case where the original shell has
        // lost its controlling-tty pointer (tty_nr=0 in /proc) but
        // is still alive; the fallback reads its pgrp directly
        // from /proc/<opener_pid>/stat.
        let pgrp = match pgrp_for_session(pty_index, opener_pid) {
            Ok(p) if p > 0 => p,
            Ok(p) => {
                return TapResponse::Error(format!(
                    "pty_index={pty_index} has no foreground process group (pgrp={p})"
                ));
            }
            Err(e) => {
                return TapResponse::Error(format!(
                    "pgrp_for_session for pty_index={pty_index}: {e}"
                ));
            }
        };
        // SAFETY: kill on a real pgrp + valid signal.
        let r = unsafe { libc::kill(-pgrp as libc::pid_t, libc::SIGSTOP) };
        if r != 0 {
            let err = std::io::Error::last_os_error();
            return TapResponse::Error(format!(
                "SIGSTOP on pgrp {pgrp} for pty_index={pty_index}: {err}"
            ));
        }

        // Open the captured slave fd. We hand three clones of it to
        // the impostor as stdin/stdout/stderr via std::process::Command.
        // O_NOCTTY is critical: without it the kernel makes this pty
        // the *daemon's* controlling tty (we're a session leader with
        // none), and any subsequent SIGHUP on that pty kills us.
        let path = format!("/dev/pts/{pty_index}");
        use std::os::unix::fs::OpenOptionsExt as _;
        let slave = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                // Roll back the SIGSTOP — leaving the pgrp frozen
                // when quarantine fails would be an obscure footgun.
                unsafe {
                    libc::kill(-pgrp as libc::pid_t, libc::SIGCONT);
                }
                return TapResponse::Error(format!("open {path}: {e}"));
            }
        };

        // Spawn the impostor.
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};
        let stdin_fd: OwnedFd = match slave.try_clone() {
            Ok(f) => f.into(),
            Err(e) => {
                unsafe {
                    libc::kill(-pgrp as libc::pid_t, libc::SIGCONT);
                }
                return TapResponse::Error(format!("dup slave fd: {e}"));
            }
        };
        let stdout_fd: OwnedFd = match slave.try_clone() {
            Ok(f) => f.into(),
            Err(e) => {
                unsafe {
                    libc::kill(-pgrp as libc::pid_t, libc::SIGCONT);
                }
                return TapResponse::Error(format!("dup slave fd: {e}"));
            }
        };
        let stderr_fd: OwnedFd = slave.into();

        let mut cmd = Command::new("/usr/local/bin/tap-honeypot");
        cmd.arg("pty-attach")
            .arg("--user")
            .arg(&opener_username)
            .arg("--uid")
            .arg(opener_uid.to_string())
            .arg("--gid")
            .arg(opener_uid.to_string()) // best-effort: gid often == uid
            .stdin(Stdio::from(stdin_fd))
            .stdout(Stdio::from(stdout_fd))
            .stderr(Stdio::from(stderr_fd));

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                unsafe {
                    libc::kill(-pgrp as libc::pid_t, libc::SIGCONT);
                }
                return TapResponse::Error(format!("spawn tap-honeypot: {e}"));
            }
        };
        let impostor_pid = child.id();
        // We don't keep the Child handle — Linux will reparent the
        // impostor to PID 1 if the daemon dies, and we'll reap it
        // explicitly on release_quarantine via waitpid(WNOHANG).
        std::mem::forget(child);

        // Persist the state so release_quarantine can find what to
        // kill and what to SIGCONT.
        {
            let mut table = sessions.lock().expect("session table mutex poisoned");
            if let Some(state) = table.get_mut(&pty_index) {
                state.locked = true;
                state.quarantined = true;
                state.quarantine_impostor_pid = Some(impostor_pid);
                state.quarantine_orig_pgrp = Some(pgrp);
            }
        }

        info!(pty_index, impostor_pid, pgrp, "session quarantined");
        TapResponse::QuarantineSet {
            pty_index,
            quarantined: true,
            impostor_pid: Some(impostor_pid),
        }
    }

    /// Release a session from quarantine: kill the impostor and
    /// SIGCONT the original foreground process group. The user's
    /// real shell wakes up — see the comment on
    /// `handle_set_quarantine` for the job-control caveat.
    fn release_quarantine(sessions: &SessionTable, pty_index: i32) -> TapResponse {
        let (impostor_pid, orig_pgrp, was_quarantined) = {
            let table = sessions.lock().expect("session table mutex poisoned");
            let Some(state) = table.get(&pty_index) else {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            };
            (
                state.quarantine_impostor_pid,
                state.quarantine_orig_pgrp,
                state.quarantined,
            )
        };
        if !was_quarantined {
            return TapResponse::QuarantineSet {
                pty_index,
                quarantined: false,
                impostor_pid: None,
            };
        }

        if let Some(pid) = impostor_pid {
            // SIGTERM first; if the impostor catches it, SIGKILL.
            // For an unattended bash inside a sandbox SIGTERM is
            // typically enough.
            // SAFETY: kill(2) on a pid + signal.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            // Reap the zombie. Don't block — if the impostor is
            // slow to exit, we leave the kernel to reap when the
            // daemon eventually does.
            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(
                    pid as libc::pid_t,
                    &mut status as *mut _,
                    libc::WNOHANG,
                );
            }
        }

        // Drain stale input that piled up during the impostor's
        // lifetime so the original shell doesn't replay it.
        if let Err(e) = flush_pty_input(pty_index) {
            warn!(pty_index, error = %e, "TCFLSH on quarantine release failed");
        }

        if let Some(pgrp) = orig_pgrp {
            // SAFETY: kill(2) on -pgrp + valid signal.
            let r = unsafe { libc::kill(-pgrp as libc::pid_t, libc::SIGCONT) };
            if r != 0 {
                let err = std::io::Error::last_os_error();
                warn!(pty_index, pgrp, error = %err, "SIGCONT on release failed");
            }
        }

        // Clear bookkeeping.
        {
            let mut table = sessions.lock().expect("session table mutex poisoned");
            if let Some(state) = table.get_mut(&pty_index) {
                state.locked = false;
                state.quarantined = false;
                state.quarantine_impostor_pid = None;
                state.quarantine_orig_pgrp = None;
            }
        }

        info!(pty_index, ?impostor_pid, ?orig_pgrp, "session released from quarantine");
        TapResponse::QuarantineSet {
            pty_index,
            quarantined: false,
            impostor_pid: None,
        }
    }

    /// Lock or unlock a session by SIGSTOPping / SIGCONTing its
    /// foreground process group.
    ///
    /// "Foreground process group" is the group whose processes are
    /// currently allowed to read from / write to the controlling tty.
    /// We get it via `ioctl(slave_fd, TIOCGPGRP)`. SIGSTOP'ing it
    /// freezes whatever the user is interacting with (the shell at
    /// an idle prompt, or vim, or whatever); other background jobs
    /// in the session keep running.
    ///
    /// On unlock we **flush the pty's input queue first** via
    /// `ioctl(slave_fd, TCFLSH, TCIFLUSH)`. Otherwise the keystrokes
    /// the user hammered against the locked session are still sitting
    /// in the kernel's tty buffer and the shell would replay them as
    /// if they were a single line of input — potentially executing
    /// commands they typed in frustration.
    ///
    /// Authorization: opener-or-creator (same as Inject and Kill).
    /// Self-pty refused like the rest.
    fn handle_set_lock(
        sessions: &SessionTable,
        peer: &PeerContext,
        pty_index: i32,
        locked: bool,
    ) -> TapResponse {
        if Some(pty_index) == peer.controlling_pty {
            return TapResponse::Error(format!(
                "no active session with pty_index={pty_index}"
            ));
        }
        // Scope + write-permission check; bail before touching kernel
        // state if the peer can't act on this session. Also grab the
        // opener_pid so pgrp_for_session can fall back to it if the
        // tty-based lookup fails.
        let opener_pid = {
            let table = sessions.lock().expect("session table mutex poisoned");
            let Some(state) = table.get(&pty_index) else {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            };
            if !peer.scope_allows(state) {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            }
            if !peer_can_inject(peer, state) {
                return TapResponse::Error(format!(
                    "forbidden: only the session opener (or a creator-role peer) \
                     may lock pty_index={pty_index}"
                ));
            }
            state.opener_pid
        };

        let pgrp = match pgrp_for_session(pty_index, opener_pid) {
            Ok(p) => p,
            Err(e) => {
                return TapResponse::Error(format!(
                    "pgrp_for_session for pty_index={pty_index}: {e}"
                ));
            }
        };
        if pgrp <= 0 {
            return TapResponse::Error(format!(
                "pty_index={pty_index} has no foreground process group (pgrp={pgrp})"
            ));
        }

        if !locked {
            // Drain the queued input bytes BEFORE thawing, so the user
            // doesn't get their hammer-typing run as commands when the
            // shell wakes up.
            if let Err(e) = flush_pty_input(pty_index) {
                warn!(pty_index, error = %e, "TCFLSH on unlock failed (continuing)");
            }
        }

        let signal = if locked { libc::SIGSTOP } else { libc::SIGCONT };
        // Negative pid → killpg(2) semantics (signal whole pgrp).
        // SAFETY: kill(2) with a real pgrp and a valid signal.
        let r = unsafe { libc::kill(-pgrp as libc::pid_t, signal) };
        if r != 0 {
            let err = std::io::Error::last_os_error();
            return TapResponse::Error(format!(
                "kill(-{pgrp}, {signal}) for pty_index={pty_index}: {err}"
            ));
        }

        // Update bookkeeping under the sessions lock.
        {
            let mut table = sessions.lock().expect("session table mutex poisoned");
            if let Some(state) = table.get_mut(&pty_index) {
                state.locked = locked;
            }
        }

        info!(pty_index, pgrp, locked, "lock state changed");
        TapResponse::LockSet {
            pty_index,
            locked,
            pgrp,
        }
    }

    /// Pick a pgrp to signal for `pty_index`, with a fallback for
    /// the post-quarantine-release case.
    ///
    /// Strategy 1: walk /proc for any process whose `tty_nr` matches
    /// `pty_index`, return its `tpgid`. Standard "foreground pgrp"
    /// semantics — picks up vim, less, etc. when they're in front.
    ///
    /// Strategy 2 (fallback): read `pgrp` directly from
    /// /proc/<opener_pid>/stat field 5. Necessary after a
    /// quarantine release — the impostor's TIOCSCTTY-steal clears
    /// the original shell's controlling-tty pointer, so its
    /// tty_nr becomes 0 and Strategy 1 finds nothing even though
    /// the shell is alive and the user is happily interacting with
    /// it. The shell's process group is unaffected by the
    /// controlling-tty change.
    fn pgrp_for_session(
        pty_index: i32,
        opener_pid: u32,
    ) -> std::io::Result<libc::pid_t> {
        if let Ok(pgrp) = foreground_pgrp(pty_index) {
            if pgrp > 0 {
                return Ok(pgrp);
            }
        }
        pgrp_via_opener(opener_pid)
    }

    /// Read field 5 (`pgrp`) of /proc/<pid>/stat. Used by
    /// `pgrp_for_session` as a fallback when the tty-based lookup
    /// can't find a controlling process for the captured pty.
    fn pgrp_via_opener(pid: u32) -> std::io::Result<libc::pid_t> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let close = stat.rfind(')').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("/proc/{pid}/stat: no closing comm paren"),
            )
        })?;
        let fields: Vec<&str> = stat
            .get(close + 1..)
            .map(|s| s.split_whitespace().collect())
            .unwrap_or_default();
        // After comm: [0]=state, [1]=ppid, [2]=pgrp, ...
        fields
            .get(2)
            .and_then(|s| s.parse::<libc::pid_t>().ok())
            .filter(|p| *p > 0)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("/proc/{pid}/stat: no usable pgrp field"),
                )
            })
    }

    /// Read the foreground process group of `pty_index` from /proc.
    ///
    /// We can't use `ioctl(fd, TIOCGPGRP)` here: that ioctl requires
    /// the calling process's *own* controlling terminal to match the
    /// fd, and the daemon (running under systemd) has no controlling
    /// tty — the call returns ENOTTY.
    ///
    /// Instead: walk /proc looking for any process whose `tty_nr`
    /// (field 7 of stat) matches our pty_index. Field 8 of that
    /// process's stat is `tpgid` — the foreground pgrp of the tty
    /// it's attached to — which is what we want. Multiple processes
    /// in the same session share a controlling tty so they all
    /// report the same tpgid; finding any one is enough.
    ///
    /// Returns NotFound if no process has the captured pty as its
    /// controlling tty — common after a quarantine release; callers
    /// in that situation should use `pgrp_for_session` instead,
    /// which falls back to the opener's own pgrp.
    fn foreground_pgrp(pty_index: i32) -> std::io::Result<libc::pid_t> {
        let proc_dir = std::fs::read_dir("/proc")?;
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let pid: i32 = match name.to_str().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };
            let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(s) => s,
                Err(_) => continue,
            };
            // Anchor on the rightmost ')' since field 2 (`comm`) can
            // itself contain whitespace and parens.
            let close = match stat.rfind(')') {
                Some(c) => c,
                None => continue,
            };
            let fields: Vec<&str> = stat
                .get(close + 1..)
                .map(|s| s.split_whitespace().collect())
                .unwrap_or_default();
            // After the closing paren of comm:
            //   [0]=state, [1]=ppid, [2]=pgrp, [3]=session,
            //   [4]=tty_nr, [5]=tpgid
            let tty_nr: u32 = match fields.get(4).and_then(|s| s.parse().ok()) {
                Some(n) => n,
                None => continue,
            };
            let major = (tty_nr >> 8) & 0xff;
            let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
            if !(136..=143).contains(&major) || (minor as i32) != pty_index {
                continue;
            }
            let tpgid: libc::pid_t = match fields.get(5).and_then(|s| s.parse().ok()) {
                Some(n) => n,
                None => continue,
            };
            if tpgid > 0 {
                return Ok(tpgid);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no foreground process group found for pty_index={pty_index} in /proc"),
        ))
    }

    /// `ioctl(slave_fd, TCFLSH, TCIFLUSH)` — discard everything in
    /// the pty's input queue. Used on unlock so accumulated keystrokes
    /// don't replay into the shell.
    fn flush_pty_input(pty_index: i32) -> std::io::Result<()> {
        use std::ffi::CString;
        let path = CString::new(format!("/dev/pts/{pty_index}")).unwrap();
        // O_NOCTTY: don't let this open turn /dev/pts/N into our own
        // controlling tty. Without it, the daemon (a session leader
        // with no controlling tty) would acquire the pty as one and
        // then SIGHUP if the user closes their terminal — the daemon
        // dies along with the user's session.
        // SAFETY: open(2) with a valid C string and standard flags.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: ioctl(TCFLSH) takes an int directly, not a pointer.
        let r = unsafe { libc::ioctl(fd, libc::TCFLSH, libc::TCIFLUSH) };
        unsafe {
            libc::close(fd);
        }
        if r < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Display an admin message to the user attached to `pty_index`.
    ///
    /// Implementation: open `/dev/pts/<pty_index>` for writing and emit
    /// a formatted notification. Bytes written this way go to the
    /// terminal *as output* (the captured user sees them on screen)
    /// rather than as input to their shell, so the message can't be
    /// interpreted as a command.
    ///
    /// Authorization is the same opener-or-creator gate Inject uses —
    /// the message names the sender, so the daemon shouldn't let
    /// arbitrary peers spoof admin notifications into anyone's
    /// terminal.
    fn handle_admin_message(
        sessions: &SessionTable,
        peer: &PeerContext,
        pty_index: i32,
        message: &str,
        from: &str,
    ) -> TapResponse {
        if Some(pty_index) == peer.controlling_pty {
            return TapResponse::Error(format!(
                "no active session with pty_index={pty_index}"
            ));
        }

        // Cap message length so a hostile (or buggy) caller can't
        // dump megabytes onto the recipient's screen.
        const MAX_MSG_BYTES: usize = 4096;
        if message.len() > MAX_MSG_BYTES {
            return TapResponse::Error(format!(
                "admin message too long: {} bytes (max {MAX_MSG_BYTES})",
                message.len()
            ));
        }

        // Scope check + write-permission check.
        {
            let table = sessions.lock().expect("session table mutex poisoned");
            let Some(state) = table.get(&pty_index) else {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            };
            if !peer.scope_allows(state) {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            }
            if !peer_can_inject(peer, state) {
                return TapResponse::Error(format!(
                    "forbidden: only the session opener (or a creator-role peer) \
                     may message pty_index={pty_index}"
                ));
            }
        }

        // Strip control characters that could disrupt the recipient's
        // terminal (no embedded ESC sequences in user-supplied content;
        // we add the formatting ourselves).
        let safe_message: String = message
            .chars()
            .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
            .collect();
        let safe_from: String = from
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .filter(|c| !c.is_whitespace() || *c == ' ')
            .take(64)
            .collect();

        // Format: leading bell to get attention, blank line for visual
        // separation, reverse-video header line, then the message in a
        // bright color, then a closing rule.
        let formatted = format!(
            "\r\n\x07\
             \x1b[1;33;7m  admin: {from}  \x1b[0m\r\n\
             \x1b[1;33m  {message}\x1b[0m\r\n\
             \r\n",
            from = safe_from,
            message = safe_message,
        );

        let path = format!("/dev/pts/{pty_index}");
        // O_NOCTTY: see flush_pty_input. Critical to avoid the daemon
        // adopting the user's pty as its controlling tty and dying on
        // SIGHUP when the user closes their terminal.
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                warn!(pty_index, path = %path, error = %e, "open /dev/pts failed");
                return TapResponse::Error(format!(
                    "open {path}: {e}"
                ));
            }
        };
        match std::io::Write::write_all(&mut file, formatted.as_bytes()) {
            Ok(()) => {
                info!(pty_index, from = %safe_from, len = formatted.len(), "admin message delivered");
                TapResponse::MessageDelivered {
                    pty_index,
                    bytes_written: formatted.len(),
                }
            }
            Err(e) => {
                warn!(pty_index, error = %e, "write to /dev/pts failed");
                TapResponse::Error(format!("write {path}: {e}"))
            }
        }
    }

    /// Send a signal to the session's opener PID. SIGHUP by default
    /// (mirrors what a closed terminal emulator sends to its session
    /// — well-behaved shells handle it and exit, propagating to child
    /// processes that don't ignore SIGHUP). SIGKILL when `force`.
    ///
    /// Authorization: same as Inject — opener-or-creator only. Read
    /// scope isn't enough; killing someone's shell is at least as
    /// invasive as typing into it.
    ///
    /// We don't try to kill the master holder (sshd, tmux server,
    /// terminal emulator) — that would log the user out / kill tmux
    /// for everyone, which is rarely what's wanted. The session
    /// leader is the right target; the kernel cleans up the tty
    /// when the leader exits.
    fn handle_kill(
        sessions: &SessionTable,
        peer: &PeerContext,
        pty_index: i32,
        force: bool,
    ) -> TapResponse {
        if Some(pty_index) == peer.controlling_pty {
            return TapResponse::Error(format!(
                "no active session with pty_index={pty_index}"
            ));
        }
        let (target_pid, was_locked, was_quarantined, impostor_pid) = {
            let table = sessions.lock().expect("session table mutex poisoned");
            let Some(state) = table.get(&pty_index) else {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            };
            if !peer.scope_allows(state) {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            }
            if !peer_can_inject(peer, state) {
                return TapResponse::Error(format!(
                    "forbidden: only the session opener (or a creator-role peer) \
                     may kill pty_index={pty_index}"
                ));
            }
            (
                state.opener_pid,
                state.locked,
                state.quarantined,
                state.quarantine_impostor_pid,
            )
        };

        // If the session is quarantined, the impostor is holding
        // /dev/pts/N open as its stdin/stdout/stderr. Killing only
        // the original shell leaves the pty alive in the kernel
        // (pty_close fires on the *last* slave-fd close), so the
        // daemon never gets a session-end event and the entry
        // hangs around in `tap list` forever. Take down the
        // impostor first.
        if was_quarantined {
            if let Some(pid) = impostor_pid {
                // SAFETY: kill on a real pid + valid signal.
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGTERM);
                }
                let mut status: libc::c_int = 0;
                // SAFETY: waitpid with WNOHANG; if the impostor is
                // slow to exit we just leave the kernel to reap it
                // when the daemon eventually does.
                unsafe {
                    libc::waitpid(
                        pid as libc::pid_t,
                        &mut status as *mut _,
                        libc::WNOHANG,
                    );
                }
            }
            // Clear the quarantine bookkeeping. The session itself
            // is being killed; don't leave stale impostor PIDs.
            if let Some(state) = sessions
                .lock()
                .expect("session table mutex poisoned")
                .get_mut(&pty_index)
            {
                state.quarantined = false;
                state.quarantine_impostor_pid = None;
                state.quarantine_orig_pgrp = None;
            }
        }

        // If the session is currently locked (SIGSTOPped), SIGHUP would
        // queue but never get delivered — stopped processes only react
        // to SIGKILL and SIGCONT. Wake the foreground pgrp first.
        // Also flush the pty's input queue so any keystrokes the user
        // hammered in while locked don't replay into the shell during
        // the brief window between SIGCONT and the kill signal.
        if was_locked {
            if let Err(e) = flush_pty_input(pty_index) {
                warn!(pty_index, error = %e, "TCFLSH on kill-while-locked failed (continuing)");
            }
            match pgrp_for_session(pty_index, target_pid) {
                Ok(pgrp) if pgrp > 0 => {
                    // SAFETY: kill(2) with a real pgrp + valid signal.
                    let r = unsafe {
                        libc::kill(-pgrp as libc::pid_t, libc::SIGCONT)
                    };
                    if r != 0 {
                        warn!(
                            pty_index, pgrp,
                            error = %std::io::Error::last_os_error(),
                            "SIGCONT before kill failed (continuing)"
                        );
                    }
                }
                Ok(_) => {
                    warn!(pty_index, "no foreground pgrp to SIGCONT before kill");
                }
                Err(e) => {
                    warn!(pty_index, error = %e, "pgrp_for_session failed before kill (continuing)");
                }
            }
            // Mirror the unlock path: clear the in-memory lock flag.
            // Don't bother if the kill succeeds — the session ends and
            // the entry gets removed — but on error we still want the
            // bookkeeping to reflect the SIGCONT that did happen.
            if let Some(state) = sessions
                .lock()
                .expect("session table mutex poisoned")
                .get_mut(&pty_index)
            {
                state.locked = false;
            }
        }

        let signal = if force { libc::SIGKILL } else { libc::SIGHUP };
        // SAFETY: kill(2) with a real pid and a valid signal number.
        let r = unsafe { libc::kill(target_pid as libc::pid_t, signal) };
        if r != 0 {
            let err = std::io::Error::last_os_error();
            warn!(pty_index, target_pid, signal, error = %err, "kill failed");
            return TapResponse::Error(format!(
                "kill(pid={target_pid}, signal={signal}) for pty_index={pty_index} failed: {err}"
            ));
        }
        info!(pty_index, target_pid, signal, was_locked, "kill sent");
        TapResponse::Killed {
            pty_index,
            pid: target_pid,
            signal,
        }
    }

    /// Handle an `Inject` request. Two-stage: first take the sessions
    /// lock, validate scope and (re-)populate the cached master fd if
    /// needed, then drop the lock and do the blocking write outside
    /// it. Holding the lock across `write(2)` would let one slow
    /// injection stall every other request handler.
    ///
    /// Authorization is **stricter** than `scope_allows`: read scope
    /// gets you `tap watch` and `tap snapshot`, but injection is the
    /// session's opener (matching uid) or a creator-role peer only. A
    /// peer who can see a session shouldn't automatically be able to
    /// type into it.
    fn handle_inject(
        sessions: &SessionTable,
        peer: &PeerContext,
        pty_index: i32,
        bytes: &[u8],
    ) -> TapResponse {
        // Self-inject is a feedback loop: the peer would inject into
        // its own terminal, which would echo through the daemon back
        // to the peer ad infinitum. Refuse early with the same wording
        // as a non-existent pty.
        if Some(pty_index) == peer.controlling_pty {
            return TapResponse::Error(format!(
                "no active session with pty_index={pty_index}"
            ));
        }
        // Cap to a sane upper bound. 64 KiB is well above any realistic
        // single keystroke or pasted line and far below the kernel's
        // pty input buffer cap. Anything larger is almost certainly a
        // bug or abuse.
        const MAX_INJECT_BYTES: usize = 64 * 1024;
        if bytes.len() > MAX_INJECT_BYTES {
            return TapResponse::Error(format!(
                "inject payload too large: {} bytes (max {MAX_INJECT_BYTES})",
                bytes.len()
            ));
        }

        // Stage 1: lock, validate, ensure we have a usable master_fd.
        // Returns the fd to use for the actual write, plus the holder
        // PID for diagnostics. We do NOT write under the lock.
        let (fd, holder_pid) = {
            let mut table = sessions.lock().expect("session table mutex poisoned");
            let state = match table.get_mut(&pty_index) {
                Some(s) => s,
                None => {
                    return TapResponse::Error(format!(
                        "no active session with pty_index={pty_index}"
                    ));
                }
            };

            // Two checks. (a) Read scope — same masking as snapshot:
            // surface a "doesn't exist" error so peers can't enumerate.
            // (b) Write scope — must be opener-or-creator. Failure
            // here is a real "forbidden" so the caller knows the
            // session exists but isn't theirs to type into.
            if !peer.scope_allows(state) {
                return TapResponse::Error(format!(
                    "no active session with pty_index={pty_index}"
                ));
            }
            if !peer_can_inject(peer, state) {
                return TapResponse::Error(format!(
                    "forbidden: only the session opener (or a creator-role peer) \
                     may inject into pty_index={pty_index}"
                ));
            }

            if state.master_fd < 0 {
                match master_fd::clone_master_fd(pty_index, state.master_holder_pid) {
                    Ok(fd) => state.master_fd = fd,
                    Err(e) => {
                        return TapResponse::Error(format!(
                            "cannot acquire master fd for pty_index={pty_index}: {e}"
                        ));
                    }
                }
            }
            (state.master_fd, state.master_holder_pid)
        };

        // Stage 2: blocking write outside the lock. On EBADF/EIO we
        // clear the cache so the next inject re-clones; the user can
        // simply retry.
        match master_fd::write_to_master(fd, bytes) {
            Ok(n) => {
                debug!(pty_index, holder_pid, written = n, "injected bytes");
                TapResponse::Injected {
                    pty_index,
                    bytes_written: n,
                }
            }
            Err(e) => {
                let kind = e.kind();
                let raw = e.raw_os_error();
                let mut table = sessions.lock().expect("session table mutex poisoned");
                if let Some(state) = table.get_mut(&pty_index) {
                    if state.master_fd == fd {
                        unsafe {
                            libc::close(state.master_fd);
                        }
                        state.master_fd = -1;
                    }
                }
                drop(table);
                warn!(pty_index, ?kind, errno = ?raw, "inject write failed; cleared cached fd");
                TapResponse::Error(format!(
                    "inject write failed for pty_index={pty_index}: {e}"
                ))
            }
        }
    }

    /// Tighter authorization for write-side operations (Inject). Read
    /// scope (`scope_allows`) is necessary but not sufficient: a peer
    /// must additionally be the session's opener or a creator-role
    /// peer. Roles in between (e.g. some future "observer" role) get
    /// to look but not type.
    fn peer_can_inject(peer: &PeerContext, state: &SessionState) -> bool {
        if peer.peer_role == "creator" {
            return true;
        }
        match (&peer.peer_username, lookup_username(state.opener_uid)) {
            (Some(p), Some(o)) => p == &o,
            _ => false,
        }
    }

    fn ingest_event(
        sessions: &SessionTable,
        streams: &StreamsMap,
        cpu_id: u32,
        event: &PtyWriteEvent,
    ) {
        let now = Instant::now();
        let comm = comm_to_string(&event.comm);
        let captured = event.captured_len.min(event.data.len() as u16) as usize;

        // Inside the sessions lock: update state, then snapshot the
        // small amount of data the fan-out needs (the live bytes,
        // any dim change, the subscribers list). We deliberately
        // *do not* take the writer lock here — that would mean
        // holding both locks at once and risk a deadlock with the
        // request handler thread (which takes writer then sessions).
        let fanout: Option<FanOut> = {
            let mut table = sessions.lock().expect("session table mutex poisoned");
            let state = table.entry(event.pty_index).or_insert_with(|| {
                SessionState::new(
                    event.pty_index,
                    now,
                    event.pid,
                    comm.clone(),
                    event.uid,
                    event.gid,
                )
            });
            state.last_activity = now;
            state.last_pid = event.pid;
            state.last_comm = comm.clone();
            state.last_uid = event.uid;
            state.last_gid = event.gid;
            // Apply the kernel-reported window size *before* feeding
            // bytes, so escape sequences that depend on dimensions
            // (cursor positioning, scroll regions) interpret against
            // the right grid.
            let prev_dims = state.dims;
            state.maybe_resize(event.rows, event.cols);
            let dim_change = (state.dims.cols != prev_dims.cols
                || state.dims.lines != prev_dims.lines)
                .then_some((state.dims.lines as u16, state.dims.cols as u16));

            let live_bytes: Option<Vec<u8>> = match event.subtype {
                PTY_TYPE_SLAVE => {
                    state.output_bytes += event.total_len as u64;
                    state.output_events += 1;
                    state.ingest_output(&event.data[..captured]);
                    if state.subscribers.is_empty() {
                        None
                    } else {
                        Some(event.data[..captured].to_vec())
                    }
                }
                PTY_TYPE_MASTER => {
                    state.input_bytes += event.total_len as u64;
                    state.input_events += 1;
                    // The PID writing in the master direction is whoever
                    // holds the master fd — sshd, tmux, alacritty. That's
                    // the process we want to clone an fd from for
                    // injection. Update on every input event; if the
                    // current cached fd belongs to a different process,
                    // invalidate it so the next inject re-clones.
                    if state.master_holder_pid != event.pid && state.master_fd >= 0 {
                        unsafe {
                            libc::close(state.master_fd);
                        }
                        state.master_fd = -1;
                    }
                    state.master_holder_pid = event.pid;
                    None
                }
                _ => None,
            };

            // Snapshot subscribers only when we actually have something
            // to forward (live bytes OR a dim change). For sessions
            // with no subscribers the hot path stays a single empty
            // check.
            if state.subscribers.is_empty() {
                None
            } else if live_bytes.is_some() || dim_change.is_some() {
                Some(FanOut {
                    subscribers: state.subscribers.clone(),
                    live_bytes,
                    dim_change,
                })
            } else {
                None
            }
        };

        if let Some(f) = fanout {
            fan_out(streams, f);
        }

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
            let user = lookup_username(s.last_uid)
                .map(|n| format!("{}({})", n, s.last_uid))
                .unwrap_or_else(|| format!("uid={}", s.last_uid));
            info!(
                pty = s.pty_index,
                comm = %s.last_comm,
                user = %user,
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
        // Content capture: every kernel-side pty_write produces one
        // PtyWriteEvent with pid, dimensions, direction, bytes.
        let prog: &mut KProbe = bpf
            .program_mut("pty_write_handler")
            .context("pty_write_handler program missing from bytecode")?
            .try_into()?;
        prog.load().context("loading pty_write_handler")?;
        prog.attach("pty_write", 0)
            .context("attaching pty_write_handler to kprobe:pty_write")?;

        // Session-end signal: tty_release_struct fires once per
        // side of a pty as the kernel tears it down. First firing
        // for a given index is treated as "session gone" by the
        // daemon (subsequent firings are no-ops).
        let prog: &mut KProbe = bpf
            .program_mut("tty_release_handler")
            .context("tty_release_handler program missing from bytecode")?
            .try_into()?;
        prog.load().context("loading tty_release_handler")?;
        prog.attach("tty_release_struct", 0)
            .context("attaching tty_release_handler to kprobe:tty_release_struct")?;
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
