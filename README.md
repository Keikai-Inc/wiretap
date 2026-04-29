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

Phase 1.6 — off-screen emulation. Each session now owns an
`alacritty_terminal::Term` (80×24, no scrollback) driven through
alacritty's vte `Processor::advance` from the slave→master byte
stream. Full CSI / OSC / ESC / SGR semantics — same state machine
that powers Alacritty proper, so `vim`/`htop` redraws stay
coherent. The periodic summary appends each session's most recent
non-empty screen line; two concurrent script sessions resolve to
the distinct strings they last echoed.

Phase 1.7 wires the Hop extension protocol: ipc-channel
bootstrap, ExtMessage handlers (`list`, `connect`), the
`hop tap` CLI verb, and the per-peer scope check.

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
| 1.3 | `#[relocatable]` types replace all CO-RE shims | done |
| 1.4 | Real `pty_write` capture (flat buffer; `iov_iter` walker shelved) | done |
| 1.5 | Session tracking by `tty_struct.index` | done |
| 1.6 | `alacritty_terminal::Term` per session; snapshot generation | done |
| 1.7 | Hop extension wiring (manifest, bootstrap, ExtMessage) | ← here |
