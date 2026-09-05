# WireTap

**System-wide tmux for Linux administrators. Manage every shell on the box, not just yours.**

WireTap is tmux-like session management for Linux sysadmins, except it works
across the entire system, including shells nobody started in tmux. List every
active session, watch any of them live, attach and type, lock, quarantine, send
a message, or kill. There is nothing to set up beforehand: the shells were
already running. WireTap sees them straight from the kernel over eBPF, so it
catches every PTY regardless of which shell, multiplexer, or SSH server created
it, and it can act on a session without that session's cooperation. Drive it
from the terminal, over [WireHop](https://github.com/Keikai-Inc/wirehop) by
name, or hand it to an AI agent.

```
$ tap
┌── tap — terminal session picker ────────────────────────────┐
│ pty   user               comm        out (b/ev)   age       │
│   3   alice(1000)        bash        12384/421    82s       │
│ ▶ 4   alice(1000)        vim          2891/14     12s       │
│   5   bob(1001)          psql           830/9      4s       │
└─────────────────────────────────────────────────────────────┘
↑/↓ select   Enter=connect   l=lock   Q=quarantine   x=kill   q=quit
```

## What it does

- **A picker for every shell on the host.** `tap` with no arguments brings up a
  live-refreshing, tmux-style menu of every session you are allowed to see, with
  a side panel showing the highlighted session's screen as it updates. Arrows to
  navigate, Enter to attach, `q` to leave.
- **Attach to anyone's shell.** Press Enter and you are in it like your own
  terminal: live output, your keystrokes go through. One keystroke detaches you
  back to the menu to pick the next one.
- **Lock, kill, or send a message.** One key freezes a session, so the user's
  typing stops working until you release it; another kills it cleanly; another
  sends a visible admin message ("hey, what are you up to?") that lands as
  terminal output, not as commands their shell would run.
- **Quarantine and investigate.** One key drops a suspicious user into a
  sandboxed honeypot shell that looks like a normal Linux while their real shell
  stays frozen behind the scenes. Investigate calmly. If they are legitimate,
  swap them back; if not, you have stalled the damage while you decide.
- **Snapshot for audit.** Snapshot any session's current screen: "show me what
  was on screen at 09:42 when the deploy went sideways." Pair it with a logger
  for byte-faithful records of who saw what, when.

## When it is the right tool

- **"Who's stuck where?"** The build server is slow and five engineers are
  SSH'd in. Flip through their shells in seconds and see who is hung on which
  command, with no "can you describe what you're seeing?" over Slack.
- **Pairing without screen-share.** A junior is debugging on a shared box. Drop
  into their shell, watch, and type a hint into their prompt when they get stuck.
- **Suspicious activity at 2am.** A login from a country you do not recognize.
  Quarantine them into a sandbox; they keep typing into a fake shell while you
  investigate, without being tipped off. Hand them back if it was innocent.
- **A takedown.** An Apache 0-day lands an attacker in a `www-data` worker and a
  privesc drops them into a root shell. You `sudo` to root, run `tap`, see the
  rogue pty next to your own, watch it, quarantine it into a honeypot, and end
  the session.

## Who sees what

The same authority model Linux has always had: no new ACLs, no new keys, no new
accounts.

- **You see what's yours.** As `alice`, `tap` shows alice's shells; you can
  attach, lock, message and kill the sessions you opened, not anyone else's.
  Theirs do not even appear in the list.
- **Root sees everything.** As root you see every shell on the host and have
  every operation against each, the way root can read any file or signal any
  process. WireTap inherits that authority, it does not invent a new one.
- **Identity sticks to the session.** alice's session stays alice's even after
  she `sudo`s, so a user cannot escape your view by escalating, and you always
  know whose terminal you are attached to.

Be clear-eyed about what this is before you deploy it. `hop-tap-d` runs as
**root and records the contents of every terminal on the host**, including
passwords typed at a prompt and any secret a program prints. Mechanically, the
daemon listens on a Unix socket (`/run/hop-tap/local.sock`, mode `0666`) and
authorizes each caller by the kernel's `SO_PEERCRED` uid, not by file
permissions: root gets every session, a non-root uid gets only sessions opened
under its own username, and the wire carries no identity claims. Treat the
socket, the logs and the captured buffers as the most sensitive data on the
machine, and report vulnerabilities privately per [`SECURITY.md`](SECURITY.md).

## Install

```bash
curl -fsSL https://tap.keikai.ai/install.sh | bash
```

One curl, Linux only. It installs in seconds, runs as a service, and needs no
configuration: type `tap` and you are in. The installer auto-detects whether
WireHop is on the host and picks a mode; both fully work, and switching is just
re-running it.

Or install the binaries with cargo and set the service up in one command:

```bash
cargo install hop-tap-d      # installs `tap`, `hop-tap-d`, `tap-honeypot`
sudo tap setup               # writes + enables the systemd unit, starts the daemon
tap                          # you're in
```

`cargo install` builds against a committed, architecture-independent eBPF object,
so it needs neither the pinned toolchain nor root at build time. `sudo tap setup`
is the built-in installer for the daemon: it writes
`/etc/systemd/system/hop-tap.service`, enables it, and starts `hop-tap-d` as
root (idempotent, re-run after an upgrade). If the daemon is not running, `tap`
tells you to run it.

### Standalone mode (WireHop not installed)

`tap` is a self-contained local audit tool. The installer puts `hop-tap-d` (the
daemon, started by systemd as root) and `tap` (the CLI) in `/usr/local/bin` and
starts the daemon. Anyone on the host can use it, subject to the authority model
above:

```bash
tap                     # the tmux-style picker over every session you can see
tap list                # sessions you can see
tap snapshot 0          # current screen for pty=0
tap watch 0             # live byte stream -> your terminal
tap repl                # interactive: select, connect, lock, quarantine, kill
```

### WireHop-integrated mode (WireHop installed and running)

If WireHop is installed and `systemctl is-active hop` is true at install time,
the installer also drops `/etc/hop/extensions/tap-terminal.toml` and restarts
WireHop so it loads the extension. Local `tap` is unchanged; what you gain is
**remote** access over WireHop's authenticated peer-to-peer transport, so you
can do all of it on a remote host by name:

```bash
hop <host> ext list        # tap.terminal listed as available
hop <host> tap list        # active sessions, with opener vs writer
hop <host> tap snapshot 0  # 24x80 grid for pty=0
hop <host> tap watch 0     # live byte stream, rendered in your terminal
```

Remote access inherits WireHop's peer/role model: a creator sees every session,
other roles are gated by the session's `opener_username`. To run both, install
WireHop first, then WireTap:

```bash
curl -fsSL https://wirehop.org/install-daemon.sh | bash
curl -fsSL https://tap.keikai.ai/install.sh | bash
```

### Verify

```bash
sudo systemctl status hop-tap        # daemon up
sudo journalctl -u hop-tap -f        # logs
tap list                             # any mode, no WireHop required
```

## Quarantine (the decoy environment)

When you mark a captured session suspicious, WireTap freezes the real shell
(SIGSTOP, with its process tree, environment and file descriptors intact) and
moves the user into an impostor environment: a child that `unshare(2)`s into
fresh mount/PID/network/UTS/IPC/user namespaces, builds a sandbox root in tmpfs
with the host's `/usr` bind-mounted read-only, synthesizes believable `/etc/*`
files, `pivot_root(2)`s in, takes the captured PTY as its controlling terminal,
sets `PR_SET_NO_NEW_PRIVS`, and `execve`s a shell as an unprivileged uid so the
kernel clears its capabilities at exec and it cannot regain them. The user keeps
typing and sees plausible responses, but nothing they do touches the real host.

It is reversible by design: release the quarantine and the daemon kills the
impostor and SIGCONTs the real shell, and the user is back exactly where they
were. Whatever they typed into the decoy is discarded.
`tests/quarantine-containment.sh` proves the isolation end to end.

## How it works

The kernel-side program is pure Rust with native `#[relocatable]` CO-RE field
access: no C shims, no `bindgen`-generated `vmlinux.rs`. One compiled object runs
across kernel versions because the field offsets are relocated at load time. That
relies on a pinned rustc fork implementing
[RFC 3966](https://github.com/rust-lang/rfcs/pull/3966); see
[`docs/ebpf-toolchain.md`](docs/ebpf-toolchain.md) for exactly what is pinned and
how to build it (`scripts/build-ebpf-toolchain.sh` does it for you). **Only
`crates/hop-tap-ebpf` needs the fork; the daemon and the CLI build with stable
Rust**, and a prebuilt eBPF object ships with releases so userspace contributors
never touch the toolchain.

## Building

The relocatable eBPF object is committed at
`crates/hop-tap-d/ebpf/hop-tap-ebpf.bpf.o`, and `build.rs` embeds it by default,
so the daemon and CLI build with stable Rust and no special setup:

```bash
HOP_TAP_SKIP_EBPF_BUILD=1 cargo build --release -p hop-tap-d
```

To rebuild the object yourself you need the pinned rustc fork + bpf-linker
(`scripts/build-ebpf-toolchain.sh` reproduces the toolchain; the CI image in
`docker/toolchain.Dockerfile` is the same recipe). `build.rs` picks up a fresh
build automatically when the `stage1-vlad` toolchain is installed:

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
[WireHop](https://github.com/Keikai-Inc/wirehop) repo.

## License

MIT OR Apache-2.0, at your option. See [`LICENSE-MIT`](LICENSE-MIT) and
[`LICENSE-APACHE`](LICENSE-APACHE); bundled dependency licenses are in
[`THIRD_PARTY_LICENSES.txt`](THIRD_PARTY_LICENSES.txt).
