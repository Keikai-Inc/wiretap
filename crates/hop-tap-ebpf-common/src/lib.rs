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

// One captured `pty_write` invocation. The kernel populates `data[..captured_len]`;
// callers must not touch bytes past `captured_len`.
//
// `#[repr(C)]` + `Copy` is the FFI contract for anything that crosses the
// kernel→userspace boundary via `PerfEventByteArray`: the kernel writes
// raw bytes, userspace re-interprets the same memory layout.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PtyWriteEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub subtype: u16,
    pub captured_len: u16,
    pub total_len: u32,
    pub _pad: u32,
    pub data: [u8; MAX_CHUNK],
}

#[cfg(all(target_os = "linux", feature = "user"))]
unsafe impl aya::Pod for PtyWriteEvent {}
