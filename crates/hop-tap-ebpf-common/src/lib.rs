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

// First event type — placeholder, expanded in subsequent sub-phases.
//
// Tagged with `#[repr(C)]` and Copy so the kernel can write raw bytes
// into a PerfEventByteArray and userspace can re-cast them.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct PingEvent {
    pub seq: u64,
    pub timestamp_ns: u64,
}

// Phase 1.2 will add an `unsafe impl aya::Pod for PingEvent {}` here
// gated on `feature = "user"` and `cfg(target_os = "linux")` so the
// crate stays buildable on non-Linux dev machines.
