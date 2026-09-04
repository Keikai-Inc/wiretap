# hop-tap

Hop extension that captures every TTY/PTY session on a Linux host via
eBPF and lets remote peers list, view, and (eventually) drive them.

The kernel-side program is pure Rust with native `#[relocatable]`
CO-RE field access — no C shims, no `bindgen`-generated `vmlinux.rs`.
That relies on a pinned rustc fork implementing
[RFC 3966](https://github.com/rust-lang/rfcs/pull/3966); see
[`docs/ebpf-toolchain.md`](docs/ebpf-toolchain.md) for exactly what is
pinned and how to build it (`scripts/build-ebpf-toolchain.sh` does it
for you). Only `crates/hop-tap-ebpf` needs it; the daemon and CLI build
with stable Rust.

The design doc is `docs/technical/tap.md` in the
[wirehop](https://github.com/Keikai-Inc/wirehop) repo.

## Status

Phase 1.7 — Hop extension wiring. With `--bootstrap <path>` the
daemon writes a TOML rendezvous file, accepts one hop daemon
connection, performs the Hello/HelloAck handshake, and dispatches
`ExtMessage::Request`s to a `TapRequest` handler. Subprotocol
covers `List` (active sessions) and `Snapshot { pty_index }`
(full 80×24 grid). The bundled `tap` CLI talks to the daemon
over a local Unix socket (SO_PEERCRED authenticates the caller's
uid); `tap list / snapshot / watch` work standalone, no hop
required.

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
│   ├── hop-tap-ebpf/                # kernel-side; pinned rustc fork, see docs/ebpf-toolchain.md
│   │   └── .cargo/config.toml       # bpfel-unknown-none + bpf-linker
│   ├── hop-tap-protocol/            # wire types (TapRequest/Response,
│   │                                #   stream frames). Tiny crate;
│   │                                #   hop-cli depends on it via path.
│   └── hop-tap-d/                   # userspace daemon + bundled `tap` CLI
└── manifests/
    └── tap-terminal.toml.example    # example Hop extension manifest
```

## Install

One-liner for any Linux host:

```bash
curl -fsSL https://tap.keik.ai/install.sh | bash
```

The installer auto-detects whether hop is on the host and picks one
of two modes — both fully working:

### Standalone mode (hop not installed)

`tap` is a fully self-contained local audit utility. The installer
puts down `hop-tap-d` (the daemon, started by systemd as root) and
`tap` (the user-facing CLI) in `/usr/local/bin`, then starts the
daemon. Anyone on the host can use it:

```bash
tap list                # sessions you can see
tap snapshot 0          # current screen for pty=0
tap watch 0             # live byte stream → your terminal
tap repl                # interactive multi-command session
```

**Local permission model.** The daemon listens on a Unix socket
at `/run/hop-tap/local.sock` (mode 0666, world-connectable). On
each accept it reads `SO_PEERCRED` from the kernel — the caller's
uid is authoritative; the wire carries no identity claims.

- **uid 0** (root) → `creator` role → sees every session
- **non-root** → `peer` role → sees only sessions whose opener
  matches the caller's username

The model is "everyone can audit themselves; root can audit
anyone" — a natural local audit boundary, no special groups or
credentials required.

### hop-integrated mode (hop installed and running)

If `hop` is installed and `systemctl is-active hop` returns true at
install time, the installer also drops a manifest at
`/etc/hop/extensions/tap-terminal.toml` and restarts hop so it
picks up the new extension. **Local `tap` works exactly the same.**
What hop adds is *remote* access: peers on the hop network can
now run

```bash
hop <host> ext list                       # tap.terminal listed as available
hop <host> tap list                       # active sessions, with opener vs writer
hop <host> tap snapshot 0                 # 24x80 grid for pty=0
hop <host> tap watch 0                    # live byte stream
```

over hop's authenticated QUIC transport. The remote path uses
hop's existing peer/role permission model (creator sees all;
other roles gated by `opener_username`).

### Switching between modes

Modes are decided at install time, but switching is just re-running
the installer. Install hop after the fact, then re-run
`curl -fsSL https://tap.keik.ai/install.sh | bash` — the
detector now sees hop, drops the manifest, and restarts hop.

The installer never auto-installs hop. If you want hop too:

```bash
curl -fsSL https://hop.keik.ai/install-daemon.sh | bash    # then:
curl -fsSL https://tap.keik.ai/install.sh | bash
```

### Verify

```bash
sudo systemctl status hop-tap                    # daemon up
sudo journalctl -u hop-tap -f                    # tailing logs

# In hop-integrated mode:
hop <host> ext list                              # tap.terminal listed
hop <host> tap list                              # active sessions

# In any mode (local-only, no hop required):
tap list
tap repl
```

## Production usage

Once installed, peers can:

```bash
hop <host> tap list                       # active sessions, with opener vs writer
hop <host> tap snapshot 0                 # 24x80 grid for pty=0
hop <host> tap watch 0                    # live byte stream
```

`hop <host> tap watch <pty>` works end-to-end as of hop's
extension-system commit `0cd6d09` (the streaming dispatcher in
hop-core). Multi-frame `PeerResponse`s flow back over the peer's
QUIC stream until `StreamClosed`; the CLI decodes each
`TapStreamFrame` and writes raw bytes to stdout, so the operator's
terminal renders the captured session in real time without any
client-side emulator round-trip.

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
| 1.8d | Owner attribution (uid/gid → username via `getpwuid_r`) | done |
| 1.8e | Sticky session-opener identity (separate from per-event writer) | done |
| 1.8f | Probe REPL: multiple commands over one daemon connection | done |
| 1.8g | SGR-aware grid replay (vim/htop fidelity on mid-session subscribe) | done |
| 1.8h | `hop &lt;host&gt; tap` verb in hop-cli + extracted `hop-tap-protocol` crate | done |
| 1.8i | Per-peer scope check (creator sees all; others gated by `opener_username`) | done |
| 1.8j | `/proc` walk to seed pre-existing sessions with their session leader's identity | done |
| 1.8k | Alt-screen-aware replay (vim/htop/less subscribers land in the right mode) | done |
| 1.8l | Extension streaming in hop-core: `hop &lt;host&gt; tap watch` end-to-end | done (in hop repo) |
