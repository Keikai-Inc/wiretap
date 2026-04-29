//! hop-tap eBPF kernel-side programs.
//!
//! Phase 1.2: a single `tty_write` kprobe that emits one `PingEvent`
//! per invocation through a `PerfEventByteArray`. No CO-RE field
//! access yet — that's Phase 1.3, when the user/system pid we record
//! here will become the real pid read off `task_struct` via
//! `#[relocatable]`. For now we use `bpf_get_current_pid_tgid` as a
//! sanity payload so we can prove the kernel→userspace round trip.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{kprobe, map},
    maps::{PerCpuArray, PerfEventByteArray},
    programs::ProbeContext,
};
use hop_tap_ebpf_common::PingEvent;

#[map]
pub static mut PING_EVENTS: PerfEventByteArray = PerfEventByteArray::new(0);

// Per-CPU sequence counter. Each CPU's stream is independently
// monotonic; userspace stitches them by timestamp if it cares about
// global order. For Phase 1.2 we just print them as-is.
#[map]
pub static mut SEQ_COUNTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[kprobe]
pub fn tty_write_handler(ctx: ProbeContext) -> u32 {
    unsafe { try_emit_ping(&ctx) }.unwrap_or(1)
}

unsafe fn try_emit_ping(ctx: &ProbeContext) -> Result<u32, u32> {
    let seq = unsafe { next_seq() }.ok_or(1u32)?;
    let timestamp_ns = unsafe { bpf_ktime_get_ns() };
    let pid = (bpf_get_current_pid_tgid() & 0xFFFF_FFFF) as u32;

    let event = PingEvent {
        seq,
        timestamp_ns,
        pid,
        _pad: 0,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &raw const event as *const u8,
            core::mem::size_of::<PingEvent>(),
        )
    };
    // Edition-2024: avoid taking a shared reference to `static mut`
    // directly. Go through a raw pointer; aya's `output` takes &self,
    // and the auto-borrow happens at the call site off the place expr.
    let p = &raw mut PING_EVENTS;
    unsafe { (*p).output(ctx, bytes, 0) };
    Ok(0)
}

unsafe fn next_seq() -> Option<u64> {
    let p = &raw mut SEQ_COUNTER;
    let slot = unsafe { (*p).get_ptr_mut(0) }?;
    let cur = unsafe { *slot };
    let next = cur.wrapping_add(1);
    unsafe { *slot = next };
    Some(next)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
