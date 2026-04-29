//! hop-tap eBPF kernel-side programs.
//!
//! Phase 1.3: pid is now read off `task_struct` via vlad's
//! `#[relocatable]` instead of the `bpf_get_current_pid_tgid()`
//! helper. The field offset is patched by aya at load time against
//! the running kernel's BTF, so the same `.bpf.o` works on any
//! kernel that has `task_struct.pid` (validated cross-kernel
//! earlier: 5.4 → offset 1336, 6.8 → 1592).
//!
//! Phase 1.4 will replace the `tty_write` heartbeat with a real
//! `pty_write` content hook (see `docs/hop-tap-plan.md` §3.2 for
//! why pty_write over tty_write).

#![no_std]
#![no_main]
#![feature(relocatable_types)]

use aya_ebpf::{
    helpers::{bpf_get_current_task, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, map},
    maps::{PerCpuArray, PerfEventByteArray},
    programs::ProbeContext,
};
use hop_tap_ebpf_common::PingEvent;

mod vmlinux;
use vmlinux::task_struct;

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
    // Read pid off `task_struct` via the CO-RE relocation. The
    // `&raw const (*task).pid` expression compiles down to:
    //   1. a magic global (`@"llvm.task_struct:0:0$0:0"`) that
    //      bpf-linker turns into a CORE_FIELD_BYTE_OFFSET reloc;
    //   2. a getelementptr that bakes the relocated offset into the
    //      kernel-pointer; passed to `bpf_probe_read_kernel` for
    //      the actual safe load.
    let task = unsafe { bpf_get_current_task() } as *const task_struct;
    let pid_field: *const i32 = unsafe { &raw const (*task).pid };
    let pid = unsafe { bpf_probe_read_kernel::<i32>(pid_field) }.map_err(|_| 1u32)? as u32;

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
