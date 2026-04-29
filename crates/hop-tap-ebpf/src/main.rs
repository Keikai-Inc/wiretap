//! hop-tap eBPF kernel-side programs.
//!
//! Phase 1.4: a `pty_write` kprobe captures real terminal content.
//!
//! Why `pty_write` and not `tty_write`: `iterate_tty_write` flattens
//! the `iov_iter` into `tty->write_buf` *before* dispatching to
//! `tty->ops->write`, so by the time `pty_write` is called the
//! buffer is already a flat kernel pointer. One
//! `bpf_probe_read_kernel_buf` and we have the bytes — no
//! union-discriminant walking, no segment chasing. See
//! `docs/hop-tap-plan.md` §3.2 for the full rationale.
//!
//! Direction is tagged via `tty_struct.driver.subtype` (two CO-RE
//! field-offset relocations chasing through the linked struct):
//!   - `subtype == PTY_TYPE_MASTER` → user keystrokes forwarded into
//!     the slave's input queue (input).
//!   - `subtype == PTY_TYPE_SLAVE`  → shell wrote output that will
//!     appear on screen (output).

#![no_std]
#![no_main]
#![feature(relocatable_types)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_task, bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_kernel_buf,
    },
    macros::{kprobe, map},
    maps::{PerCpuArray, PerfEventByteArray},
    programs::ProbeContext,
};
use hop_tap_ebpf_common::{PtyWriteEvent, MAX_CHUNK};

mod vmlinux;
use vmlinux::{task_struct, tty_driver, tty_struct};

#[map]
pub static mut PTY_EVENTS: PerfEventByteArray = PerfEventByteArray::new(0);

// Per-CPU scratch buffer for assembling the event before perf-output.
// Stack would also work for this struct size (~152 B) but going through
// a per-CPU map keeps the kprobe stack budget free for future per-event
// metadata and matches the pattern aya recommends for non-trivial
// payloads.
#[map]
static mut EVENT_SCRATCH: PerCpuArray<PtyWriteEvent> = PerCpuArray::with_max_entries(1, 0);

#[kprobe]
pub fn pty_write_handler(ctx: ProbeContext) -> u32 {
    unsafe { try_pty_write(&ctx) }.unwrap_or(1)
}

unsafe fn try_pty_write(ctx: &ProbeContext) -> Result<u32, u32> {
    // pty_write signature (per drivers/tty/pty.c):
    //   pre-6.6:  int      pty_write(struct tty_struct *, const unsigned char *, int);
    //   6.6+:     ssize_t  pty_write(struct tty_struct *, const u8 *,            size_t);
    //
    // u8 / unsigned char have identical wire representation. The count
    // arg widened from int (32-bit, sign-extended into x2/rdx) to size_t
    // (64-bit). Reading as `usize` is safe both ways: positive `int`
    // sign-extends with zero upper bits, `size_t` is the register
    // verbatim.
    let tty: *const tty_struct = ctx.arg(0).ok_or(1u32)?;
    let buf: *const u8 = ctx.arg(1).ok_or(1u32)?;
    let count: usize = ctx.arg(2).ok_or(1u32)?;

    if count == 0 || tty.is_null() || buf.is_null() {
        return Ok(0);
    }

    // CO-RE chase: tty -> driver -> subtype.
    // Each `&raw const (*p).field` emits a magic global that
    // bpf-linker turns into a CORE_FIELD_BYTE_OFFSET reloc.
    let driver: *const tty_driver =
        unsafe { bpf_probe_read_kernel(&raw const (*tty).driver) }.map_err(|_| 1u32)?;
    if driver.is_null() {
        return Ok(0);
    }
    let subtype_i: i16 =
        unsafe { bpf_probe_read_kernel(&raw const (*driver).subtype) }.map_err(|_| 1u32)?;

    // pid via the relocation we proved in 1.3.
    let task = unsafe { bpf_get_current_task() } as *const task_struct;
    let pid =
        unsafe { bpf_probe_read_kernel::<i32>(&raw const (*task).pid) }.map_err(|_| 1u32)? as u32;

    let timestamp_ns = unsafe { bpf_ktime_get_ns() };

    // Acquire the per-CPU scratch slot, zero its data tail, and fill
    // the header. We own this slot for the duration of the kprobe;
    // re-entry would clobber it but kprobes don't re-enter on the
    // same CPU.
    let p = &raw mut EVENT_SCRATCH;
    let slot: *mut PtyWriteEvent = unsafe { (*p).get_ptr_mut(0) }.ok_or(1u32)?;
    unsafe {
        (*slot).timestamp_ns = timestamp_ns;
        (*slot).pid = pid;
        (*slot).subtype = subtype_i as u16;
        (*slot)._pad = 0;
        (*slot).total_len = if count > u32::MAX as usize {
            u32::MAX
        } else {
            count as u32
        };
    }

    // Bound the read so the verifier can prove `read_len < MAX_CHUNK`.
    // The min(count, MAX_CHUNK-1)+1 form keeps `read_len` in
    // 1..=MAX_CHUNK without losing the boundary case.
    let read_len = if count >= MAX_CHUNK {
        MAX_CHUNK
    } else {
        count
    };
    unsafe {
        (*slot).captured_len = read_len as u16;
    }

    // For variable-length reads the verifier needs a static bound on
    // the slice length. We branch on a constant comparison and use a
    // mask to satisfy that bound — the cost is one extra branch and
    // a guaranteed zero past `captured_len` on short writes.
    // Build the destination slice from a raw byte pointer to avoid the
    // 2024-edition `dangerous_implicit_autorefs` lint that fires when
    // we project through `*mut PtyWriteEvent` to its `data` field.
    let data_ptr: *mut u8 = unsafe { &raw mut (*slot).data } as *mut u8;
    if read_len == MAX_CHUNK {
        let dst: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(data_ptr, MAX_CHUNK) };
        let _ = unsafe { bpf_probe_read_kernel_buf(buf, dst) };
    } else {
        let masked = read_len & (MAX_CHUNK - 1);
        if masked > 0 {
            let dst: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(data_ptr, masked) };
            let _ = unsafe { bpf_probe_read_kernel_buf(buf, dst) };
        }
    }

    let bytes = unsafe {
        core::slice::from_raw_parts(slot as *const u8, core::mem::size_of::<PtyWriteEvent>())
    };
    let evp = &raw mut PTY_EVENTS;
    unsafe { (*evp).output(ctx, bytes, 0) };
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
