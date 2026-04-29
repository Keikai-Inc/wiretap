//! hop-tap eBPF kernel-side programs.
//!
//! For Phase 1.1 (skeleton), this is just a stub that loads but does
//! nothing. Subsequent sub-phases attach real handlers:
//!
//!   1.2: a `tty_write` kprobe that emits a `PingEvent` per call
//!   1.3: `#[relocatable]` types for `task_struct`, `kiocb`, `file`,
//!        `inode`, `tty_struct` — replaces all of Kunai's CO-RE shims
//!   1.4: real output capture (bytes streamed to userspace)
//!   1.5: session tracking via inode
//!   1.6+: integration with the hop-tap-d userspace daemon

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
