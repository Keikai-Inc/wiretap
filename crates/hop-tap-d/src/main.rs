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
//! Phase 1.4 wires in: load the eBPF object, attach a `pty_write`
//! kprobe, drain `PtyWriteEvent`s from per-CPU perf arrays, and log
//! a printable preview of each captured chunk tagged with direction
//! (master vs slave) and pid.

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
        include_bytes_aligned,
        maps::AsyncPerfEventArray,
        programs::KProbe,
        util::online_cpus,
        Ebpf,
    };
    use aya_log::EbpfLogger;
    use bytes::BytesMut;
    use hop_tap_ebpf_common::{PtyWriteEvent, PTY_TYPE_MASTER, PTY_TYPE_SLAVE};
    use tokio::{signal, task::JoinSet};
    use tracing::{info, warn};

    // Cross-compiled by build.rs. The bytes are aligned via aya's
    // include_bytes_aligned! so the verifier sees a properly-aligned
    // BPF object.
    static EBPF_OBJECT: &[u8] = include_bytes_aligned!(
        "../../hop-tap-ebpf/target/bpfel-unknown-none/release/hop-tap-ebpf"
    );

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

        let mut readers: JoinSet<()> = JoinSet::new();
        for cpu_id in online_cpus().map_err(|(_, e)| e).context("online_cpus")? {
            let mut buf = perf
                .open(cpu_id, Some(128))
                .context("perf open")?;
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
                        let dir = match event.subtype {
                            PTY_TYPE_MASTER => "master→slave (input)",
                            PTY_TYPE_SLAVE => "slave→master (output)",
                            other => {
                                // Non-PTY tty hooked us — shouldn't happen
                                // when attached to pty_write but logged for
                                // diagnosis if it does.
                                warn!(cpu = cpu_id, subtype = other, "unexpected tty subtype");
                                "unknown"
                            }
                        };
                        let captured = event.captured_len.min(event.data.len() as u16) as usize;
                        let preview = printable_preview(&event.data[..captured], 48);
                        let truncated = event.captured_len as u32 != event.total_len;
                        info!(
                            pid = event.pid,
                            ts_ns = event.timestamp_ns,
                            dir,
                            captured = event.captured_len,
                            total = event.total_len,
                            truncated,
                            "{preview}"
                        );
                    }
                }
            });
        }

        info!("hop-tap-d running; Ctrl-C to exit");
        signal::ctrl_c().await.context("ctrl-c")?;
        info!("shutting down");
        readers.abort_all();
        Ok(())
    }

    fn bump_memlock() {
        // Older kernels (pre-5.11) charge BPF maps against RLIMIT_MEMLOCK
        // rather than the memcg. Setting both to RLIM_INFINITY is the
        // conventional aya example pattern; on modern kernels it's a
        // no-op.
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
