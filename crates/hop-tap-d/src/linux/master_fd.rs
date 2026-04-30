//! Master-fd cloning for input injection.
//!
//! A pty has a master and a slave end. The slave is what programs
//! attach to as stdin/stdout/stderr. The master is held by the
//! terminal emulator (sshd for ssh sessions, the tmux server for
//! tmux panes, alacritty/kitty/iTerm/etc. for local shells). When
//! the user types, the terminal writes to the master and the kernel
//! routes those bytes to the slave's read queue.
//!
//! To inject input into a captured session, we need a writable copy
//! of that master fd. The strategy:
//!
//! 1. The eBPF hook records `master_holder_pid` — the PID that most
//!    recently issued a master→slave write. That's the master holder.
//! 2. We walk `/proc/<master_holder_pid>/fdinfo/` looking for an fd
//!    whose `tty-index:` line matches our `pty_index`. (`/proc/<pid>/fd/`
//!    symlinks all show as `/dev/ptmx` — `fdinfo` is the only place
//!    the kernel exposes the resolved pty number.)
//! 3. We open a `pidfd` for the holder and call `pidfd_getfd(2)` to
//!    duplicate that fd into our own table. Requires `CAP_SYS_PTRACE`
//!    on the target — the daemon runs as root, so that's covered.
//! 4. The cloned fd is cached on `SessionState::master_fd` and reused
//!    for every subsequent inject. Closed in `Drop` and invalidated
//!    if the master holder changes.
//!
//! Why not `TIOCSTI`? Modern kernels (5.18+) gate it behind a sysctl
//! because it's a confused-deputy hazard — any process that can
//! write to a tty fd can stuff input into someone else's terminal.
//! `pidfd_getfd` is the same operation we want, with the kernel's
//! permission model (CAP_SYS_PTRACE) instead of a sysctl gate.

use std::ffi::c_int;
use std::fs;
use std::io;
use std::os::fd::RawFd;

use tracing::{debug, warn};

/// `pidfd_open(2)` syscall wrapper.
///
/// libc 0.2 doesn't expose `pidfd_open` as a typed function on all
/// targets, so we issue the syscall directly. The number is stable
/// (since Linux 5.3) and identical across architectures we care
/// about for hop-tap (x86_64=434, aarch64=434).
fn sys_pidfd_open(pid: u32, flags: u32) -> io::Result<RawFd> {
    // SAFETY: syscall(2) with the right argument count. SYS_pidfd_open
    // accepts (pid_t, unsigned int).
    let r = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as c_int, flags as c_int) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as RawFd)
    }
}

/// `pidfd_getfd(2)` syscall wrapper.
///
/// Duplicates `target_fd` from the process referenced by `pidfd` into
/// the calling process's fd table, returning a new fd. Requires
/// CAP_SYS_PTRACE on the target.
fn sys_pidfd_getfd(pidfd: RawFd, target_fd: c_int, flags: u32) -> io::Result<RawFd> {
    // SAFETY: SYS_pidfd_getfd takes (int pidfd, int target_fd, unsigned int flags).
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_getfd,
            pidfd as c_int,
            target_fd,
            flags as c_int,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as RawFd)
    }
}

/// Walk `/proc/<pid>/fdinfo/` looking for an fd that the kernel
/// reports as a pty master pointing at slave number `pty_index`.
///
/// Returns the fd number in the *target* process's table — caller is
/// responsible for cloning it via `pidfd_getfd`.
fn find_master_fd_in(pid: u32, pty_index: i32) -> io::Result<c_int> {
    let dir = format!("/proc/{pid}/fdinfo");
    for entry in fs::read_dir(&dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let fd_str = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let fd: c_int = match fd_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // /proc/<pid>/fdinfo/<n> has lines like:
        //   pos:    0
        //   flags:  0102002
        //   mnt_id: 14
        //   ino:    1059
        //   tty-index:      3
        // The `tty-index:` line is only present for ptmx fds.
        let body = match fs::read_to_string(entry.path()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        for line in body.lines() {
            if let Some(rest) = line.strip_prefix("tty-index:") {
                if let Ok(n) = rest.trim().parse::<i32>() {
                    if n == pty_index {
                        return Ok(fd);
                    }
                }
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no ptmx fd in pid={pid} matches pty_index={pty_index}"),
    ))
}

/// Find the master holder for `pty_index` and clone its master fd
/// into the calling process. Returns the cloned `RawFd`.
///
/// `hint_pid` is the PID we last observed writing in the master
/// direction (recorded in `SessionState::master_holder_pid`). If the
/// hint is 0 or doesn't have a matching fd anymore, we fall back to
/// scanning `/proc/*/fdinfo/` — slower but works for sessions where
/// we never observed an input event before injection was requested.
pub(super) fn clone_master_fd(pty_index: i32, hint_pid: u32) -> io::Result<RawFd> {
    let pid = if hint_pid != 0 {
        match find_master_fd_in(hint_pid, pty_index) {
            Ok(_) => hint_pid,
            Err(_) => match scan_for_master_holder(pty_index) {
                Some(p) => p,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!(
                            "no process holds a master fd for pty_index={pty_index} \
                             (hint_pid={hint_pid} no longer matches; /proc scan empty)"
                        ),
                    ));
                }
            },
        }
    } else {
        match scan_for_master_holder(pty_index) {
            Some(p) => p,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no process holds a master fd for pty_index={pty_index}"),
                ));
            }
        }
    };

    let target_fd = find_master_fd_in(pid, pty_index)?;
    let pidfd = sys_pidfd_open(pid, 0).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("pidfd_open(pid={pid}): {e} (kernel < 5.3? capability missing?)"),
        )
    })?;
    let cloned = sys_pidfd_getfd(pidfd, target_fd, 0);
    // Always close the pidfd; we only needed it to do the getfd.
    unsafe {
        libc::close(pidfd);
    }
    let cloned = cloned.map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("pidfd_getfd(pid={pid}, fd={target_fd}): {e}"),
        )
    })?;
    debug!(pty_index, holder_pid = pid, target_fd, cloned, "cloned master fd");
    Ok(cloned)
}

/// Last-resort scan of every readable /proc/*/fdinfo for a ptmx fd
/// matching `pty_index`. Used when the hint PID has gone stale.
/// Returns the first PID that matches.
fn scan_for_master_holder(pty_index: i32) -> Option<u32> {
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "scan_for_master_holder: cannot read /proc");
            return None;
        }
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let s = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let pid: u32 = match s.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if find_master_fd_in(pid, pty_index).is_ok() {
            return Some(pid);
        }
    }
    None
}

/// Write `bytes` to a cloned master fd. Returns the number of bytes
/// written, or an io::Error. EAGAIN/EWOULDBLOCK is treated as "queue
/// full, try again" — caller decides whether to retry. Other errors
/// (EBADF, EIO) mean the fd is dead and the cache should be cleared.
pub(super) fn write_to_master(fd: RawFd, bytes: &[u8]) -> io::Result<usize> {
    if bytes.is_empty() {
        return Ok(0);
    }
    // SAFETY: write(2) with a valid fd, a real pointer, and a
    // length that's the slice's actual size.
    let r = unsafe { libc::write(fd, bytes.as_ptr() as *const _, bytes.len()) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}
