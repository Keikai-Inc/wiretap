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
//! Phase 1.2 wires in: load the eBPF object, attach a `tty_write`
//! kprobe, drain `PingEvent`s from per-CPU perf arrays. Real CO-RE
//! field access lands in 1.3, real output capture in 1.4.

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
    use hop_tap_ebpf_common::PingEvent;
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
            .take_map("PING_EVENTS")
            .context("PING_EVENTS map missing from bytecode")?
            .try_into()
            .context("PING_EVENTS is not a PerfEventArray")?;

        let mut readers: JoinSet<()> = JoinSet::new();
        for cpu_id in online_cpus().map_err(|(_, e)| e).context("online_cpus")? {
            let mut buf = perf.open(cpu_id, Some(128)).context("perf open")?;
            readers.spawn(async move {
                let mut bufs = vec![BytesMut::with_capacity(core::mem::size_of::<PingEvent>()); 16];
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
                        let event = unsafe { &*(raw.as_ptr() as *const PingEvent) };
                        info!(
                            cpu = cpu_id,
                            seq = event.seq,
                            pid = event.pid,
                            ts_ns = event.timestamp_ns,
                            "tty_write"
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
            .program_mut("tty_write_handler")
            .context("tty_write_handler program missing from bytecode")?
            .try_into()?;
        prog.load().context("loading tty_write_handler")?;
        prog.attach("tty_write", 0)
            .context("attaching tty_write_handler to kprobe:tty_write")?;
        Ok(())
    }
}
