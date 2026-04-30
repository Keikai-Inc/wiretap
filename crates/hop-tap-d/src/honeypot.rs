//! Phase 2: namespace-sandbox honeypot.
//!
//! When the admin marks a captured session as suspicious, we want to
//! freeze their real shell (already done — `SetLock` SIGSTOPs it) and
//! transition the user into an *impostor environment*: a sandboxed
//! Linux that looks like their real one, where they can keep typing,
//! see realistic-ish responses, but their actions can't damage the
//! actual host.
//!
//! Reversibility is the operational point: the real shell stays
//! SIGSTOP'd in the background with all its state (process tree,
//! environment, file descriptors) preserved. If the admin decides
//! the user is legitimate, swap back is just: kill the impostor,
//! SIGCONT the real shell. The user is back exactly where they were
//! (modulo whatever they typed at the impostor — that's lost).
//!
//! ## Architecture
//!
//! 1. Daemon `fork()`s a child to run the impostor.
//! 2. Child: `unshare(2)` into mount, PID, network, UTS, IPC, user
//!    namespaces. Now we have our own private view of the kernel.
//! 3. Child: build a sandbox root in a tmpfs and bind-mount the host's
//!    real `/usr` (read-only) so binaries like `ls`, `cat`, `bash` are
//!    available without copying anything.
//! 4. Child: synthesize `/etc/{passwd,group,hostname,os-release,...}`
//!    with believable contents.
//! 5. Child: `pivot_root(2)` into the sandbox root.
//! 6. Child: `setsid()` + `ioctl(slave_fd, TIOCSCTTY)` so the captured
//!    pty becomes our controlling tty.
//! 7. Child: drop capabilities, set `PR_SET_NO_NEW_PRIVS`.
//! 8. Child: `execve("/bin/bash", ...)` with the user's preserved env
//!    (or as much of it as we can plausibly reconstruct).
//!
//! Phase 1 of this work focuses on steps 2–4 + 7–8: get a sandbox we
//! can spawn `bash` in via the standalone `tap-honeypot` binary, with
//! no captured-pty wiring. The TIOCSCTTY/setsid dance lives in the
//! daemon-integration phase.

use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{chdir, pivot_root, sethostname};

/// What to make the impostor environment look like.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Pretend hostname (UTS namespace). Match the captured session's
    /// real hostname so `uname -n` looks unchanged from the user's POV.
    pub hostname: String,
    /// Pretend username — written into `/etc/passwd`, used as `$USER`,
    /// becomes the home-directory name.
    pub user: String,
    /// Pretend uid the impostor `id` reports.
    pub uid: u32,
    /// Pretend gid.
    pub gid: u32,
    /// Path *inside the sandbox* that becomes the user's HOME and the
    /// working directory bash starts in.
    pub home: PathBuf,
    /// Environment passed to the impostor shell. The daemon will
    /// snapshot the real shell's env from `/proc/<pid>/environ` and
    /// pass it through; the standalone CLI builds a default set.
    pub env: HashMap<String, String>,
    /// What to exec. Typically `["/bin/bash", "-l"]`.
    pub command: Vec<String>,
}

impl SandboxSpec {
    /// Sensible defaults for the standalone `tap-honeypot` binary.
    /// Synthesises a believable user shell with a realistic `$PATH`,
    /// inheriting the caller's `$TERM` so colors/cursor work.
    pub fn default_for_user(user: impl Into<String>) -> Self {
        let user = user.into();
        let home = PathBuf::from(format!("/home/{user}"));
        let mut env = HashMap::new();
        env.insert(
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        );
        env.insert("USER".into(), user.clone());
        env.insert("LOGNAME".into(), user.clone());
        env.insert("HOME".into(), home.to_string_lossy().into_owned());
        env.insert("SHELL".into(), "/bin/bash".into());
        env.insert(
            "TERM".into(),
            std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()),
        );
        // Bash builds `$PS1` from this when it's set; a realistic
        // distro-flavored prompt is one of the strongest "I'm in a
        // real shell" signals the user gets.
        env.insert(
            "PS1".into(),
            format!(r"\[\033[01;32m\]{user}@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "),
        );
        Self {
            hostname: nix::unistd::gethostname()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| "localhost".into()),
            user,
            uid: 1000,
            gid: 1000,
            home,
            env,
            command: vec!["/bin/bash".into(), "--noprofile".into(), "--norc".into()],
        }
    }
}

/// Set up a Linux namespace sandbox per `spec`, then `execve` the
/// configured command. Never returns on success — control transfers
/// to the new program. Returns `Err` only on setup failure before
/// the exec.
///
/// The flow is split across a `fork()` boundary: `unshare(2)` only
/// puts the *children* of the calling process into the new PID
/// namespace, not the caller itself. So mounting `/proc` (which the
/// kernel binds to the calling process's PID namespace) has to
/// happen on the child side. The parent waits on the child; if the
/// parent is killed the child follows via `PR_SET_PDEATHSIG=SIGKILL`.
pub fn enter_sandbox_and_exec(spec: SandboxSpec) -> Result<std::convert::Infallible> {
    let euid = nix::unistd::geteuid().as_raw();
    let egid = nix::unistd::getegid().as_raw();

    // Namespace unshare. Everything except CLONE_NEWPID takes effect
    // on the calling process immediately; CLONE_NEWPID only affects
    // future children (ours, after the fork below).
    unshare(
        CloneFlags::CLONE_NEWUSER
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWPID
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWIPC
            | CloneFlags::CLONE_NEWNET,
    )
    .context("unshare namespaces (need user namespaces enabled in the kernel)")?;

    // After CLONE_NEWUSER we have to populate uid_map / gid_map so
    // we can perform mounts inside the new namespace. Mapping our
    // real euid → sandbox-uid 0 means we're "root" inside the
    // sandbox without any actual elevated privilege on the host.
    write_id_map("/proc/self/uid_map", spec.uid, euid).context("uid_map")?;
    // setgroups must be denied before writing gid_map for unprivileged
    // user namespaces (CVE-2014-8989).
    std::fs::write("/proc/self/setgroups", b"deny").context("setgroups deny")?;
    write_id_map("/proc/self/gid_map", spec.gid, egid).context("gid_map")?;

    // Hostname for the new UTS namespace.
    sethostname(spec.hostname.as_str()).context("sethostname")?;

    // Fork. The child lands in the new PID namespace as PID 1 and
    // does the rest of the sandbox work + exec; the parent stays in
    // the old PID namespace and just waits.
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};
    // SAFETY: tap-honeypot is single-threaded at this point (no
    // tokio runtime, no spawned threads). fork(2) is sound.
    match unsafe { fork() }.context("fork into new PID namespace")? {
        ForkResult::Child => {
            // SIGKILL me when the parent dies, so killing the
            // tap-honeypot process the daemon spawned reliably tears
            // the whole sandbox down.
            // SAFETY: prctl with scalar args.
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            }
            // If the parent died between the fork and the prctl,
            // PR_SET_PDEATHSIG won't fire — bail out manually so we
            // don't leak a sandbox process.
            if unsafe { libc::getppid() } == 1 {
                std::process::exit(1);
            }
            // Build sandbox root + pivot.
            let root = build_sandbox_root(&spec).context("build sandbox root")?;
            pivot_into(&root).context("pivot_root")?;
            chdir(&spec.home).with_context(|| format!("chdir {:?}", spec.home))?;
            no_new_privs().context("PR_SET_NO_NEW_PRIVS")?;
            // Exec replaces this process. Never returns on success.
            exec_command(&spec.command, &spec.env)
        }
        ForkResult::Parent { child } => {
            // Wait for the child. If the child exits cleanly we
            // exit with the same status; if it's killed by signal
            // we propagate.
            match waitpid(child, None).context("waitpid sandbox child")? {
                WaitStatus::Exited(_, code) => std::process::exit(code),
                WaitStatus::Signaled(_, sig, _) => {
                    std::process::exit(128 + sig as i32);
                }
                _ => std::process::exit(1),
            }
        }
    }
}

/// Write a single-line uid/gid map mapping the entire sandbox uid
/// space to the host's real euid (or egid).
///
/// Format: "<inside_id> <outside_id> <length>\n"
fn write_id_map(path: &str, inside: u32, outside: u32) -> Result<()> {
    let line = format!("{inside} {outside} 1\n");
    std::fs::write(path, line.as_bytes()).with_context(|| format!("write {path}"))?;
    Ok(())
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` — drops the ability of
/// the impostor (and its children) to gain new privileges via setuid
/// binaries. Cheap, reversible-with-fork only, and a strong
/// containment baseline before exec.
fn no_new_privs() -> Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) takes scalar
    // arguments and returns 0/-1.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(std::io::Error::last_os_error()).context("prctl");
    }
    Ok(())
}

/// Construct a fake `/` for the sandbox in a tmpfs, bind-mounting
/// what we need from the host (read-only) and synthesizing the rest.
///
/// Layout produced:
///   /                          tmpfs (the sandbox root)
///   /usr                       bind-mount of host /usr (ro)
///   /lib, /lib64, /lib32       bind-mounts if present on host (ro)
///   /bin, /sbin                symlinks to /usr/bin, /usr/sbin
///   /etc                       tmpfs with synthesized passwd/group/etc
///   /home/<user>               tmpfs with .bashrc + .bash_history
///   /tmp, /var/tmp             tmpfs (writable)
///   /proc                      our own procfs (PID-namespaced)
///   /sys                       tmpfs (read-only, mostly empty)
///   /dev                       tmpfs with curated null/zero/random/...
///   /run                       tmpfs
///
/// Returns the path to the new root.
fn build_sandbox_root(spec: &SandboxSpec) -> Result<PathBuf> {
    let root = PathBuf::from("/tmp/hop-tap-honeypot-root");
    let _ = std::fs::create_dir_all(&root);

    // Make every mount we do private to our namespace. Without this,
    // bind-mounts can propagate back to the host.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("recursive private mount on /")?;

    // The sandbox root itself is a fresh tmpfs.
    mount(
        Some("tmpfs"),
        &root,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=755"),
    )
    .with_context(|| format!("tmpfs at {:?}", root))?;

    // Real-binary plumbing: bind-mount the host's /usr read-only so
    // the impostor's bash, ls, cat, etc. are real bash, ls, cat.
    bind_mount_ro(Path::new("/usr"), &root.join("usr"))?;

    // Some distros (Debian-style) keep libs in /lib + /lib64 instead
    // of /usr/lib. Bind-mount them if they exist as real dirs (not
    // symlinks to /usr/lib).
    for lib in &["lib", "lib64", "lib32"] {
        let host = PathBuf::from("/").join(lib);
        if host.is_dir() && !host.is_symlink() {
            bind_mount_ro(&host, &root.join(lib))?;
        }
    }

    // /bin → /usr/bin and /sbin → /usr/sbin as symlinks (the
    // usrmerge layout). PATH still expects /bin, /sbin to exist.
    create_symlink(&root.join("bin"), "usr/bin")?;
    create_symlink(&root.join("sbin"), "usr/sbin")?;

    // Synthesize /etc.
    let etc = root.join("etc");
    std::fs::create_dir_all(&etc).context("mkdir /etc")?;
    write_etc(&etc, spec).context("populate /etc")?;

    // Home directory — minimal believable contents.
    let home_path = root.join(spec.home.strip_prefix("/").unwrap_or(&spec.home));
    std::fs::create_dir_all(&home_path).with_context(|| format!("mkdir {:?}", home_path))?;
    write_home(&home_path, spec).context("populate home")?;

    // Writable scratch dirs.
    for (dir, opts) in &[
        ("tmp", "mode=1777"),
        ("var/tmp", "mode=1777"),
        ("run", "mode=755"),
    ] {
        let p = root.join(dir);
        std::fs::create_dir_all(&p).ok();
        mount(
            Some("tmpfs"),
            &p,
            Some("tmpfs"),
            MsFlags::empty(),
            Some(*opts),
        )
        .with_context(|| format!("tmpfs at {:?}", p))?;
    }

    // /proc — our own (PID-namespaced) procfs. Most of what casual
    // probing reveals (`ps aux`, `cat /proc/cpuinfo`) is reasonable.
    let proc = root.join("proc");
    std::fs::create_dir_all(&proc).ok();
    mount(
        Some("proc"),
        &proc,
        Some("proc"),
        MsFlags::empty(),
        None::<&str>,
    )
    .context("mount procfs")?;

    // /sys — tmpfs placeholder. Mounting the real sysfs leaks host
    // hardware details; a stub is safer for v1.
    let sys = root.join("sys");
    std::fs::create_dir_all(&sys).ok();
    mount(
        Some("tmpfs"),
        &sys,
        Some("tmpfs"),
        MsFlags::MS_RDONLY,
        Some("mode=755"),
    )
    .context("tmpfs at /sys")?;

    // /dev — curated tmpfs with the standard character devices.
    let dev = root.join("dev");
    std::fs::create_dir_all(&dev).ok();
    mount(
        Some("tmpfs"),
        &dev,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=755"),
    )
    .context("tmpfs at /dev")?;
    populate_dev(&dev).context("populate /dev")?;

    Ok(root)
}

fn bind_mount_ro(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("mkdir {:?}", dst))?;
    mount(
        Some(src),
        dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("bind {:?} -> {:?}", src, dst))?;
    // Re-mount with read-only. MS_BIND + MS_RDONLY in a single mount
    // call is silently ignored by the kernel — we have to do a second
    // remount call.
    mount(
        Some(src),
        dst,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .with_context(|| format!("ro-remount {:?}", dst))?;
    Ok(())
}

fn create_symlink(at: &Path, target: &str) -> Result<()> {
    if at.exists() {
        return Ok(());
    }
    std::os::unix::fs::symlink(target, at)
        .with_context(|| format!("symlink {:?} -> {target}", at))?;
    Ok(())
}

/// Write the small handful of `/etc` files that casual probing
/// touches: passwd, group, hostname, hosts, os-release, resolv.conf,
/// shells. Just enough for the impostor to feel like a configured
/// Linux instead of a barren tmpfs.
fn write_etc(etc: &Path, spec: &SandboxSpec) -> Result<()> {
    let SandboxSpec {
        hostname, user, uid, gid, home, ..
    } = spec;

    let passwd = format!(
        "root:x:0:0:root:/root:/bin/bash\n\
         {user}:x:{uid}:{gid}:{user},,,:{home_str}:/bin/bash\n\
         daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
         bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
         nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
        home_str = home.display(),
    );
    std::fs::write(etc.join("passwd"), passwd)?;

    let group = format!(
        "root:x:0:\n\
         {user}:x:{gid}:\n\
         sudo:x:27:\n\
         adm:x:4:\n\
         daemon:x:1:\n\
         nogroup:x:65534:\n",
    );
    std::fs::write(etc.join("group"), group)?;

    // No real password hashes — sudo/su will fail with "incorrect
    // password" without ever granting access.
    let shadow = format!(
        "root:!:19000:0:99999:7:::\n\
         {user}:!:19000:0:99999:7:::\n",
    );
    std::fs::write(etc.join("shadow"), shadow)?;
    // Restrict shadow even though we're "root" inside the sandbox.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(etc.join("shadow"), std::fs::Permissions::from_mode(0o640))?;

    std::fs::write(etc.join("hostname"), format!("{hostname}\n"))?;
    std::fs::write(
        etc.join("hosts"),
        format!(
            "127.0.0.1\tlocalhost\n\
             127.0.1.1\t{hostname}\n\
             ::1\t\tlocalhost ip6-localhost ip6-loopback\n",
        ),
    )?;
    std::fs::write(
        etc.join("resolv.conf"),
        "nameserver 127.0.0.53\noptions edns0 trust-ad\n",
    )?;
    std::fs::write(
        etc.join("os-release"),
        r#"PRETTY_NAME="Ubuntu 22.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.5 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
"#,
    )?;
    std::fs::write(
        etc.join("shells"),
        "/bin/sh\n/usr/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/dash\n/usr/bin/dash\n",
    )?;
    Ok(())
}

/// Write the default home-directory contents — the bare minimum to
/// make `ls -la ~` not look conspicuously empty.
fn write_home(home: &Path, spec: &SandboxSpec) -> Result<()> {
    std::fs::write(
        home.join(".bashrc"),
        format!(
            "# {user}'s .bashrc\n\
             [ -z \"$PS1\" ] && return\n\
             HISTSIZE=1000\n\
             HISTFILESIZE=2000\n\
             alias ll='ls -alF'\n\
             alias la='ls -A'\n\
             alias l='ls -CF'\n",
            user = spec.user
        ),
    )?;
    std::fs::write(home.join(".bash_logout"), "# ~/.bash_logout\nclear\n")?;
    std::fs::write(home.join(".profile"), "# ~/.profile\n")?;
    // A small fake history so `history` and `Up arrow` show
    // believable previous commands. Tweak per-template later.
    std::fs::write(
        home.join(".bash_history"),
        "ls\n\
         ls -la\n\
         pwd\n\
         cd ~\n\
         vim notes.md\n\
         git status\n\
         ssh prod-web\n",
    )?;
    Ok(())
}

/// Populate the sandbox `/dev` with the standard character devices a
/// shell expects. We can't `mknod` from an unprivileged user
/// namespace, so we bind-mount each one from the host instead.
fn populate_dev(dev: &Path) -> Result<()> {
    for name in &[
        "null", "zero", "full", "random", "urandom", "tty",
    ] {
        let host = PathBuf::from("/dev").join(name);
        let target = dev.join(name);
        if !host.exists() {
            continue;
        }
        // Touch the target so the bind has something to mount onto.
        std::fs::write(&target, b"").ok();
        if let Err(e) = mount(
            Some(&host),
            &target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        ) {
            // Non-fatal: a missing /dev entry just means commands that
            // touch it fail in the sandbox the same way they would on
            // a stripped-down container. Don't abort the whole setup.
            tracing::debug!(?host, error = %e, "bind /dev entry failed; skipping");
        }
    }
    // /dev/pts so terminal applications work. Mount a fresh devpts.
    let pts = dev.join("pts");
    std::fs::create_dir_all(&pts).ok();
    if let Err(e) = mount(
        Some("devpts"),
        &pts,
        Some("devpts"),
        MsFlags::empty(),
        Some("ptmxmode=0666,newinstance"),
    ) {
        tracing::debug!(error = %e, "mount devpts failed; skipping");
    }
    create_symlink(&dev.join("ptmx"), "pts/ptmx").ok();
    create_symlink(&dev.join("fd"), "/proc/self/fd").ok();
    create_symlink(&dev.join("stdin"), "/proc/self/fd/0").ok();
    create_symlink(&dev.join("stdout"), "/proc/self/fd/1").ok();
    create_symlink(&dev.join("stderr"), "/proc/self/fd/2").ok();
    Ok(())
}

/// `pivot_root(2)` into `new_root`, then unmount and discard the old
/// root so it can't be reached from inside.
fn pivot_into(new_root: &Path) -> Result<()> {
    // pivot_root requires the new root to be a mount point distinct
    // from the old root. Re-bind it on itself to make it a mount.
    mount(
        Some(new_root),
        new_root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .with_context(|| format!("self-bind {:?}", new_root))?;

    // pivot_root requires a directory inside new_root to receive the
    // old root.
    let put_old = new_root.join(".put_old");
    let _ = std::fs::create_dir(&put_old);

    pivot_root(new_root, &put_old).context("pivot_root syscall")?;

    // We pivoted but our cwd may still refer to the (now hidden) old
    // root — `chdir("/")` to land in the new namespace's "/".
    chdir("/").context("chdir / after pivot_root")?;

    // Discard the old root so the impostor can't escape via it.
    umount2("/.put_old", MntFlags::MNT_DETACH).context("umount old root")?;
    let _ = std::fs::remove_dir("/.put_old");

    Ok(())
}

/// `execve` the configured command, replacing the current process.
fn exec_command(argv: &[String], env: &HashMap<String, String>) -> Result<std::convert::Infallible> {
    if argv.is_empty() {
        bail!("empty command");
    }
    let prog = CString::new(argv[0].as_bytes()).context("CString prog")?;
    let argv_c: Vec<CString> = argv
        .iter()
        .map(|s| CString::new(s.as_bytes()).context("CString arg"))
        .collect::<Result<Vec<_>>>()?;
    let env_c: Vec<CString> = env
        .iter()
        .map(|(k, v)| {
            CString::new(format!("{k}={v}").into_bytes()).context("CString env")
        })
        .collect::<Result<Vec<_>>>()?;

    nix::unistd::execve(&prog, &argv_c, &env_c)
        .with_context(|| format!("execve {:?}", argv[0]))?;
    unreachable!()
}

