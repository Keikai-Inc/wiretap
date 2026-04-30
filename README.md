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
│   ├── hop-tap-protocol/            # wire types (TapRequest/Response,
│   │                                #   stream frames). Tiny crate;
│   │                                #   hop-cli depends on it via path.
│   └── hop-tap-d/                   # userspace daemon (stable Rust);
│                                    #   bundles `hop-tap-probe` test client
└── manifests/
    └── tap-terminal.toml.example    # example Hop extension manifest
```

## Install

One-liner for any Linux host:

```bash
curl -fsSL https://hop-tap.keik.ai/install.sh | bash
```

The installer auto-detects whether hop is on the host and picks one
of two modes — both fully working:

### Standalone mode (hop not installed)

The most common case for first-time evaluation. The installer puts
down `hop-tap-d` + `hop-tap-probe` in `/usr/local/bin`, installs the
systemd unit, and starts the daemon. There's no manifest, no peer
auth — just local audit via the bundled probe:

```bash
hop-tap-probe --bootstrap /run/hop-tap/bootstrap repl
> list
> snapshot 0
> watch 0
```

The bootstrap file is root-owned mode 0600, so "you can run the
probe" reduces to "you have root or the daemon's UID." That's the
authorization model in standalone mode — appropriate for local
operator audit, scripted recordings on a dedicated audit host, or
just trying hop-tap out before bringing hop into the picture.

### hop-integrated mode (hop installed and running)

If `hop` is installed and `systemctl is-active hop` returns true at
install time, the installer also drops a manifest at
`/etc/hop/extensions/tap-terminal.toml` and restarts hop so it
picks up the new extension. After that, peers on the hop network
get remote access:

```bash
hop <host> ext list                       # tap.terminal listed as available
hop <host> tap list                       # active sessions, with opener vs writer
hop <host> tap snapshot 0                 # 24x80 grid for pty=0
hop <host> tap watch 0                    # live byte stream
```

The remote path adds peer authentication, the per-peer scope check
(creator role sees all; other roles gated by `opener_username`), and
hop's QUIC transport. The local probe path keeps working unchanged.

### Switching between modes

Modes are decided at install time, but switching is just re-running
the installer. Install hop after the fact, then re-run
`curl -fsSL https://hop-tap.keik.ai/install.sh | bash` — the
detector now sees hop, drops the manifest, and restarts hop.

The installer never auto-installs hop. If you want hop too:

```bash
curl -fsSL https://hop.keik.ai/install-daemon.sh | bash    # then:
curl -fsSL https://hop-tap.keik.ai/install.sh | bash
```

### Verify

```bash
sudo systemctl status hop-tap                    # daemon up
sudo journalctl -u hop-tap -f                    # tailing logs

# In hop-integrated mode:
hop <host> ext list                              # tap.terminal listed
hop <host> tap list                              # active sessions

# In any mode:
hop-tap-probe --bootstrap /run/hop-tap/bootstrap repl
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
