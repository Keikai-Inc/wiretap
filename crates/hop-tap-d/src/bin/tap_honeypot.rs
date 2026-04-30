//! `tap-honeypot` — standalone test harness for the Phase 2 sandbox
//! module.
//!
//! Drops you into bash inside the same Linux-namespace sandbox the
//! daemon will eventually run a captured user's shell in. Nothing
//! here knows about the daemon, the captured pty, or RPCs — this
//! exists so we can iterate on the impostor environment in
//! isolation, ahead of any tap-side wiring.
//!
//! Usage:
//!   sudo tap-honeypot exec --user alice
//!
//! Why sudo: setting up a Linux user namespace requires either CAP_
//! SYS_ADMIN or unprivileged-user-namespaces enabled in the kernel
//! (the default on most modern distros). The bind-mounting we do
//! after that needs CAP_SYS_ADMIN inside the namespace, which is
//! granted automatically once we set up the uid_map.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tap-honeypot is Linux-only (uses unshare/pivot_root). Build for a Linux target.");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use clap::{Parser, Subcommand};
    use hop_tap_d::honeypot::{enter_sandbox_and_exec, SandboxSpec};
    use tracing_subscriber::EnvFilter;

    #[derive(Parser, Debug)]
    #[command(version, about = "Standalone tester for the hop-tap honeypot sandbox.")]
    struct Args {
        #[command(subcommand)]
        cmd: Cmd,
    }

    #[derive(Subcommand, Debug)]
    enum Cmd {
        /// Set up a sandbox and exec bash inside it. Inherits the
        /// caller's stdin/stdout/stderr — useful for testing the
        /// sandbox interactively from a regular shell.
        Exec {
            /// Pretend username inside the sandbox.
            #[arg(long, default_value = "alice")]
            user: String,
            /// Pretend hostname (defaults to the real one).
            #[arg(long)]
            hostname: Option<String>,
            /// Pretend uid.
            #[arg(long, default_value_t = 1000)]
            uid: u32,
            /// Pretend gid.
            #[arg(long, default_value_t = 1000)]
            gid: u32,
        },
        /// Attach to the inherited stdin/stdout/stderr as our
        /// controlling tty (setsid + TIOCSCTTY-steal), then enter
        /// the sandbox and exec bash. Used by the daemon when it
        /// transitions a captured session into the honeypot —
        /// the daemon opens /dev/pts/N, plumbs it into our stdio
        /// via std::process::Command, and we take it over here.
        ///
        /// Requires CAP_SYS_ADMIN to steal an in-use tty. The
        /// daemon runs as root so this is fine.
        PtyAttach {
            #[arg(long)]
            user: String,
            #[arg(long)]
            hostname: Option<String>,
            #[arg(long, default_value_t = 1000)]
            uid: u32,
            #[arg(long, default_value_t = 1000)]
            gid: u32,
        },
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    match args.cmd {
        Cmd::Exec {
            user,
            hostname,
            uid,
            gid,
        } => {
            let mut spec = SandboxSpec::default_for_user(user);
            if let Some(h) = hostname {
                spec.hostname = h;
            }
            spec.uid = uid;
            spec.gid = gid;
            let _: std::convert::Infallible = enter_sandbox_and_exec(spec)?;
            unreachable!()
        }
        Cmd::PtyAttach {
            user,
            hostname,
            uid,
            gid,
        } => {
            let mut spec = SandboxSpec::default_for_user(user);
            if let Some(h) = hostname {
                spec.hostname = h;
            }
            spec.uid = uid;
            spec.gid = gid;
            // 1. setsid: become our own session leader so TIOCSCTTY
            //    is allowed to bind a controlling tty to us.
            nix::unistd::setsid().map_err(|e| anyhow::anyhow!("setsid: {e}"))?;
            // 2. TIOCSCTTY with arg=1 = "steal" mode: takes the tty
            //    away from the previous controlling session (the
            //    real shell, which the daemon SIGSTOPped before
            //    spawning us). Requires CAP_SYS_ADMIN.
            //    SAFETY: ioctl on STDIN with TIOCSCTTY's int arg.
            let r = unsafe { libc::ioctl(0, libc::TIOCSCTTY, 1) };
            if r != 0 {
                let err = std::io::Error::last_os_error();
                anyhow::bail!("TIOCSCTTY-steal on stdin: {err}");
            }
            let _: std::convert::Infallible = enter_sandbox_and_exec(spec)?;
            unreachable!()
        }
    }
}
