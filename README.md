# hop-tap

Hop extension that captures every TTY/PTY session on a Linux host via
eBPF and lets remote peers list, view, and (eventually) drive them.

This is a clean-slate rebuild of the prototype `term-capture-ebpf`,
using **vlad's rustc fork** for native `#[relocatable]` CO-RE field
access in pure Rust — no Kunai dependency, no vendored C shims, no
`bindgen`-generated `vmlinux.rs`.

See `docs/hop-tap-plan.md` (in the `hop` repo) for the full design
doc, and `term-capture-ebpf/DESCRIPTION.md` for the original
prototype's architecture (the behavior we're targeting).

## Status

Phase 1.2 — `tty_write` kprobe + perf-array round trip verified
end-to-end on Linux 6.8 (under colima). The userspace daemon loads
the embedded `.bpf.o`, attaches the kprobe, and decodes one
`PingEvent` per kernel-side `tty_write` invocation across per-CPU
perf arrays.

Phase 1.4 will switch the content hook from `tty_write` to
`pty_write` (flat buffer in both pty directions; sidesteps the
`iov_iter` walker entirely — see `docs/hop-tap-plan.md` §3.2).

## Layout

```
hop-tap/
├── Cargo.toml                       # workspace (excludes hop-tap-ebpf)
├── crates/
│   ├── hop-tap-ebpf-common/         # shared no_std types (event structs)
│   ├── hop-tap-ebpf/                # kernel-side; built with vlad's stage1 rustc
│   │   └── .cargo/config.toml       # bpfel-unknown-none + bpf-linker
│   └── hop-tap-d/                   # userspace daemon (stable Rust)
└── manifests/
    └── hop-tap.toml.example         # example Hop extension manifest
```

The `hop-tap-ebpf` crate is intentionally **outside** the workspace
because it must be cross-compiled for `bpfel-unknown-none` with
`-Z build-std=core` on vlad's nightly fork. Putting it in the
workspace would force those constraints onto the userspace crates
too. The `hop-tap-d` build.rs (added in Phase 1.2) drives the
cross-build.

## Building

Userspace:

```bash
cargo build -p hop-tap-d
```

Kernel-side (requires vlad's stage1 rustc linked as `stage1-vlad`):

```bash
cd crates/hop-tap-ebpf
cargo +stage1-vlad build --release
```

## Running

Not yet — see Phase 1.2.

## Phasing

| Sub-phase | What | Status |
|---|---|---|
| 1.1 | Workspace skeleton, three crates that build cleanly | done |
| 1.2 | Minimal eBPF kprobe; userspace reads PingEvents | done |
| 1.3 | `#[relocatable]` types replace all CO-RE shims | ← here |
| 1.4 | Real `pty_write` capture (flat buffer; `iov_iter` walker shelved) | |
| 1.5 | Session tracking by PTS inode | |
| 1.6 | `termwiz` Surface per session; snapshot generation | |
| 1.7 | Hop extension wiring (manifest, bootstrap, ExtMessage) | |
