# Agents Guide (hop-tap)

Working guide for the codebase, for humans and AI agents.

## What this is

hop-tap captures every TTY/PTY session on a Linux host with an eBPF program,
renders and streams them, and can lock or quarantine a hostile session. A
userspace daemon (`hop-tap-d`, runs as root under systemd) owns the eBPF program
and serves two front ends: a local Unix socket for the bundled `tap` CLI, and,
when WireHop is present, a WireHop extension for remote peers.

## Workspace layout

```
crates/hop-tap-ebpf-common/  # no_std event structs shared kernel<->user
crates/hop-tap-ebpf/         # kernel-side program; NOT a workspace member
crates/hop-tap-protocol/     # wire types: TapRequest/TapResponse, stream frames
crates/hop-tap-d/            # daemon + `tap` CLI (src/bin/tap.rs) + honeypot
```

`hop-tap-ebpf` is excluded from the workspace on purpose: it targets
`bpfel-unknown-none` with `-Z build-std=core` on a pinned rustc fork, and those
constraints must not reach the userspace crates.

## Building and testing

```bash
HOP_TAP_SKIP_EBPF_BUILD=1 cargo build --release -p wiretap-d
HOP_TAP_SKIP_EBPF_BUILD=1 cargo clippy --all-targets   # must be warning-clean
HOP_TAP_SKIP_EBPF_BUILD=1 cargo test
```

`HOP_TAP_SKIP_EBPF_BUILD=1` tells `hop-tap-d`'s `build.rs` to use the prebuilt
eBPF object instead of cross-building it, so you build with stable Rust. Only
touch the toolchain when you change `crates/hop-tap-ebpf`:

```bash
scripts/build-ebpf-toolchain.sh        # reproduces the pinned rustc + bpf-linker
cd crates/hop-tap-ebpf && cargo +stage1-vlad build --release
```

See `docs/ebpf-toolchain.md` for the exact pinned commits and the rationale.

## The eBPF crate

- Kernel field access uses native `#[relocatable]` CO-RE (RFC 3966), not C shims
  or generated `vmlinux.rs`. `vmlinux.rs` here is a hand-written partial mirror.
- The program is compiled once and relocated per kernel at load time. When you
  add a field access, add it to the relocatable shadow types, not a fixed offset.

## Compatibility rules

- `crates/hop-tap-protocol` is the wire contract between daemon and clients (both
  the local `tap` CLI and the WireHop extension path). Enums are **append-only**;
  do not add or remove fields on an existing variant. A daemon and a client at
  adjacent versions must interoperate.
- The daemon mirrors WireHop's `ExtMessage` types locally rather than depending
  on `hop-core`, to keep the build small. Keep that mirror in sync by hand when
  the WireHop extension protocol changes.

## Security-sensitive areas (change with care, document the reasoning)

- **Socket auth** (`SO_PEERCRED` uid check): the entire local access model.
- **Capture path** (eBPF + buffer handling): decides what is recorded.
- **Quarantine** (`src/honeypot.rs`): namespace sandbox; an escape is a host
  compromise. Preserve capability drop, `no_new_privs`, and `pivot_root`.

## Docs

Update `README.md` (front page + threat model), `SECURITY.md`, and
`docs/ebpf-toolchain.md` when behavior changes. The WireHop-side design doc is
`docs/technical/tap.md` in the wirehop repo.
