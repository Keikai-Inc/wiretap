//! Shared types between the kernel-side eBPF programs (`hop-tap-ebpf`)
//! and the userspace daemon (`hop-tap-d`).
//!
//! This crate is `#![no_std]` and compiles under both targets:
//!
//! - For the eBPF target (`bpfel-unknown-none`): default features only.
//! - For userspace: enable `--features user` to get `aya::Pod` impls
//!   so events can be read from perf arrays.
//!
//! Every type that crosses the FFI boundary (kernel → userspace via a
//! `PerfEventByteArray`) must be `#[repr(C)]` and `Copy`.

#![no_std]

// Maximum bytes captured per `pty_write` invocation. Power of two so
// the eBPF side can use a mask-and-bound trick to satisfy the verifier
// when slicing the destination buffer for `bpf_probe_read_kernel_buf`.
// Larger writes are truncated at this length and `PtyWriteEvent::total_len`
// records the original `count` so userspace can flag truncation.
pub const MAX_CHUNK: usize = 128;

// PTY subtype constants from `include/uapi/linux/tty.h`. Matched
// against `tty_struct.driver.subtype` to tag direction:
//   - master = the side held by the terminal emulator (sshd, tmux);
//     a `pty_write` with subtype=master means "user keystrokes
//     forwarded into the slave's input queue" (input).
//   - slave = the side held by the shell; subtype=slave means
//     "shell wrote output that will appear on screen" (output).
pub const PTY_TYPE_MASTER: u16 = 0x0001;
pub const PTY_TYPE_SLAVE: u16 = 0x0002;

// `task_struct.comm` is a fixed 16-byte buffer holding the
// NUL-terminated process name (TASK_COMM_LEN in <linux/sched.h>).
pub const COMM_LEN: usize = 16;

// One captured `pty_write` invocation. The kernel populates `data[..captured_len]`;
// callers must not touch bytes past `captured_len`.
//
// `pty_index` is the unit number of the pty pair (`tty_struct.index`).
// Both ends of a pair share the same value, so events flowing in
// either direction are joinable into one logical session by this key.
//
// `rows`/`cols` are the kernel's current view of the terminal window
// size (from `tty_struct.winsize`). The kernel updates this when the
// terminal emulator issues TIOCSWINSZ. We piggy-back on every
// `pty_write` rather than running a separate resize hook, since
// `pty_write` fires often enough that any session producing output
// will surface the latest dimensions promptly. Dimensions of (0, 0)
// are valid for ptys that haven't been sized yet (rare in practice).
//
// `#[repr(C)]` + `Copy` is the FFI contract for anything that crosses the
// kernel→userspace boundary via `PerfEventByteArray`: the kernel writes
// raw bytes, userspace re-interprets the same memory layout.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PtyWriteEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub pty_index: i32,
    pub subtype: u16,
    pub captured_len: u16,
    pub total_len: u32,
    pub rows: u16,
    pub cols: u16,
    pub comm: [u8; COMM_LEN],
    pub data: [u8; MAX_CHUNK],
}

#[cfg(all(target_os = "linux", feature = "user"))]
unsafe impl aya::Pod for PtyWriteEvent {}
