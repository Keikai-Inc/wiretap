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

Phase 1.7 — Hop extension wiring. With `--bootstrap <path>` the
daemon writes a TOML rendezvous file, accepts one hop daemon
connection, performs the Hello/HelloAck handshake, and dispatches
`ExtMessage::Request`s to a `TapRequest` handler. Subprotocol
covers `List` (active sessions) and `Snapshot { pty_index }`
(full 80×24 grid). A bundled `hop-tap-probe` simulates the hop
side; verified end-to-end on Linux 6.8 — `probe list` returns the
live session table, `probe snapshot --pty 0` reproduces the exact
echoed lines on a fresh terminal grid.

ExtMessage wire types are a local mirror of hop-core's; the dep
on hop-core itself is deliberately avoided to keep hop-tap's
compile fast.

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
| 1.7 | Hop extension wiring (manifest, bootstrap, ExtMessage) | done |
| 1.8a | PTY dimension tracking via `tty_struct.winsize` | done |
| 1.8b | Live byte streaming (`StreamOpen` / replay + Output / Resize) | done |
| 1.8c | Session-end detection via `tty_release_struct` kprobe | done |
