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

// First event type — a heartbeat the kprobe emits on every tty_write.
// It exists so we can prove the perf-array round trip works before we
// start populating real fields off `task_struct` / `tty_struct` in
// Phase 1.4.
//
// `#[repr(C)]` + `Copy` is the contract for anything that crosses the
// kernel→userspace FFI boundary via `PerfEventByteArray`: the kernel
// writes raw bytes, userspace re-interprets the same memory layout.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PingEvent {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub _pad: u32,
}

// Mark `PingEvent` as a "plain old data" type for aya so that
// `AsyncPerfEventArray::read_events` can hand us a `&PingEvent` cast
// straight off the perf ring. Gated on Linux + the `user` feature so
// the kernel-side build (bpfel-unknown-none, no aya dep) and macOS dev
// builds (no aya dep) both stay green.
#[cfg(all(target_os = "linux", feature = "user"))]
unsafe impl aya::Pod for PingEvent {}
