//! `#[relocatable]` shadows of kernel structs the eBPF programs need
//! to read.
//!
//! Each type here is a *partial* mirror of a kernel type — we only
//! list the fields we actually access. The `#[relocatable]` attribute
//! (vlad's rustc fork, gated behind `#![feature(relocatable_types)]`
//! at the crate root) marks the type as having no fixed Rust layout:
//! every `(*ptr).field` access goes through a CO-RE field-offset
//! relocation patched by `bpf-linker` into `.BTF.ext`, which aya
//! resolves against the running kernel's vmlinux BTF at load time.
//!
//! Concretely this means:
//! - The order of fields here does **not** have to match the kernel
//!   layout. We can list only `pid` even though the kernel
//!   `task_struct` has hundreds of fields before/after it.
//! - Adding a new field is purely additive — no need to know its
//!   offset, the kernel's BTF and the runtime relocation handle that.
//! - The same `.bpf.o` works on every kernel that has `task_struct`
//!   with a field named `pid` of type `int`. We validated this end-
//!   to-end earlier on the rustc-fork side: same binary, 5.4 →
//!   pid offset 1336, 6.8 → 1592 (256 bytes of drift, transparently
//!   patched).
//!
//! Phase 1.3 starts with the minimum: `task_struct.pid`. Phase 1.4
//! adds `tty_struct` (passed to `pty_write` as arg0), `tty_driver`,
//! and `file`/`inode` for session identification.

#![allow(non_camel_case_types)]

#[relocatable]
#[repr(C)]
pub struct task_struct {
    pub pid: i32,
}
