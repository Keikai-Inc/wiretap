# hop-tap

Terminal-session audit for Linux, over eBPF. `hop-tap` captures every
TTY/PTY session on a host straight from the kernel and lets you list them,
snapshot a screen, watch a live byte stream, and — for a session you decide is
hostile — freeze it or divert it into a decoy environment. It runs standalone
as a local audit tool, and, when [WireHop](https://github.com/Keikai-Inc/wirehop)
is present, over WireHop's authenticated peer-to-peer transport so you can do all
of that on a remote host by name.

The kernel-side program is pure Rust with native `#[relocatable]` CO-RE field
access — no C shims, no `bindgen`-generated `vmlinux.rs`. One compiled object
runs across kernel versions because the field offsets are relocated at load
time. That relies on a pinned rustc fork implementing
[RFC 3966](https://github.com/rust-lang/rfcs/pull/3966); see
[`docs/ebpf-toolchain.md`](docs/ebpf-toolchain.md) for exactly what is pinned
and how to build it (`scripts/build-ebpf-toolchain.sh` does it for you). **Only
`crates/hop-tap-ebpf` needs the fork; the daemon and the CLI build with stable
Rust**, and a prebuilt eBPF object ships with releases so userspace contributors
never touch the toolchain.

## What it is for

An operator — or an AI agent acting as one — needs to see what is actually
happening in the shells on a machine: what a session is typing and printing,
who opened it, and whether it is doing something it should not. `hop-tap`
answers that from the kernel, so it sees every PTY regardless of which shell,
multiplexer, or SSH server created it, and it can act on a session without that
session's cooperation.

## Threat model and authorization

Read this before deploying. `hop-tap-d` is a **root daemon that records the
contents of every terminal on the host**, including passwords typed at a prompt
and any secret a program prints. Treat its socket, its logs, and its captured
buffers as containing the most sensitive data on the machine.

**Who may see what — local.** The daemon listens on a Unix socket at
`/run/hop-tap/local.sock` (mode `0666`, world-connectable). On each accept it
reads `SO_PEERCRED` from the kernel: the caller's uid is authoritative and the
wire carries no identity claims. From that uid:

- **uid 0 (root)** → `creator` role → every session on the host.
- **non-root** → `peer` role → only sessions whose opener shares the caller's
  username.

The rule is "anyone may audit their own sessions; root may audit anyone." No
groups, no credentials, no configuration. The `0666` socket is deliberate — the
kernel-verified peer uid, not file permissions, is the access boundary — but it
means any local user can reach the daemon, so the uid check is the whole
security model locally. If you do not want non-root users auditing their own
sessions, do not install `hop-tap`.

**Who may see what — remote.** With WireHop installed, remote access uses
WireHop's existing peer/role model over authenticated QUIC: a creator sees all
sessions, other roles are gated by the session's `opener_username`. There is no
separate remote auth path in `hop-tap`; it inherits WireHop's.

**Acting on a session.** `lock` SIGSTOPs a session's process group; `quarantine`
freezes the real shell and swaps the user into a namespace-sandboxed decoy (see
below). Both are creator-only and both are reversible. They are powerful — a
mistaken quarantine interrupts a legitimate user — so they require confirmation
in the interactive UI.

Report vulnerabilities privately: see [`SECURITY.md`](SECURITY.md).

## Install

```bash
curl -fsSL https://wirehop.org/tap/install.sh | bash
```

The installer auto-detects whether WireHop is on the host and picks a mode; both
are fully working, and switching is just re-running it.

### Standalone mode (WireHop not installed)

`tap` is a self-contained local audit tool. The installer puts `hop-tap-d` (the
daemon, started by systemd as root) and `tap` (the CLI) in `/usr/local/bin` and
starts the daemon. Anyone on the host can use it, subject to the uid rule above:

```bash
tap list                # sessions you can see
tap snapshot 0          # current screen for pty=0
tap watch 0             # live byte stream -> your terminal
tap repl                # interactive TUI: select, connect, lock, quarantine, kill
```

### WireHop-integrated mode (WireHop installed and running)

If `hop` is installed and `systemctl is-active hop` is true at install time, the
installer also drops `/etc/hop/extensions/tap-terminal.toml` and restarts hop so
it loads the extension. Local `tap` is unchanged; what you gain is remote access
over WireHop's transport:

```bash
hop <host> ext list        # tap.terminal listed as available
hop <host> tap list        # active sessions, with opener vs writer
hop <host> tap snapshot 0  # 24x80 grid for pty=0
hop <host> tap watch 0     # live byte stream, rendered in your terminal
```

Multi-frame responses stream back over the peer's QUIC stream until the session
closes; the CLI writes the raw captured bytes to stdout, so a watched session
renders in real time with no client-side emulator round-trip.

To run both, install WireHop first, then `hop-tap`:

```bash
curl -fsSL https://wirehop.org/install-daemon.sh | bash
curl -fsSL https://wirehop.org/tap/install.sh | bash
```

### Verify

```bash
sudo systemctl status hop-tap        # daemon up
sudo journalctl -u hop-tap -f        # logs
tap list                             # any mode, no WireHop required
```

## Quarantine (the decoy environment)

When you mark a captured session suspicious, `hop-tap` freezes the real shell
(SIGSTOP, with its process tree, environment and file descriptors intact) and
moves the user into an impostor environment: a child that `unshare(2)`s into
fresh mount/PID/network/UTS/IPC/user namespaces, builds a sandbox root in tmpfs
with the host's `/usr` bind-mounted read-only, synthesizes believable
`/etc/*` files, `pivot_root(2)`s in, takes the captured PTY as its controlling
terminal, sets `PR_SET_NO_NEW_PRIVS`, and `execve`s a shell as an
unprivileged uid so the kernel clears its capabilities at exec and it
cannot regain them. The user keeps typing and
sees plausible responses, but nothing they do touches the real host.

It is reversible by design: release the quarantine and the daemon kills the
impostor and SIGCONTs the real shell, and the user is back exactly where they
were. Whatever they typed into the decoy is discarded.

## Building

Userspace daemon and CLI (stable Rust):

```bash
HOP_TAP_SKIP_EBPF_BUILD=1 cargo build --release -p hop-tap-d
```

`hop-tap-d`'s `build.rs` normally cross-builds the eBPF object; setting
`HOP_TAP_SKIP_EBPF_BUILD=1` skips that and uses the prebuilt object shipped with
releases. To build the kernel-side crate yourself you need the pinned toolchain
(`scripts/build-ebpf-toolchain.sh` reproduces it; ~30–90 min for the rustc
build). Then:

```bash
cd crates/hop-tap-ebpf
cargo +stage1-vlad build --release      # -> bpfel-unknown-none .bpf.o with BTF
```

`crates/hop-tap-ebpf` is intentionally **outside** the workspace so its
`bpfel-unknown-none` + `-Z build-std=core` + fork-toolchain constraints do not
leak onto the userspace crates.

## Layout

```
crates/
  hop-tap-ebpf-common/   # shared no_std event types
  hop-tap-ebpf/          # kernel-side program (pinned rustc fork; see docs/)
  hop-tap-protocol/      # wire types (TapRequest/Response, stream frames)
  hop-tap-d/             # userspace daemon + the bundled `tap` CLI + honeypot
manifests/               # example WireHop extension manifest
scripts/                 # toolchain build + release
docs/                    # eBPF toolchain reference
```

The WireHop-side design doc is `docs/technical/tap.md` in the
[wirehop](https://github.com/Keikai-Inc/wirehop) repo.

## License

MIT OR Apache-2.0, at your option. See [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE); bundled dependency licenses are in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt).
