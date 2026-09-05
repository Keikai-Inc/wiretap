# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities through GitHub's **private vulnerability
reporting** on this repository (Security → Report a vulnerability). Do not open
public issues for security reports. We aim to acknowledge within 72 hours.
Coordinated disclosure is appreciated; we will credit reporters in release notes
unless you prefer otherwise.

hop-tap does not currently operate a paid bug-bounty program.

## What hop-tap is, so reports are calibrated

hop-tap-d is a **root daemon that records the contents of every terminal on the
host**. That is its purpose, not a flaw. Its captured buffers, its socket and
its logs can contain passwords typed at a prompt and any secret a program
prints. The security-relevant questions are about the *boundaries* on that
capability, and those are where reports are most valuable:

- **Local access boundary.** The daemon socket is `/run/hop-tap/local.sock`,
  mode `0666`, and authorizes each caller by the kernel's `SO_PEERCRED` uid:
  root sees every session, a non-root uid sees only sessions opened by its own
  username. A way for a non-root caller to see another user's session, or to
  forge the peer uid, is a vulnerability.
- **Remote access boundary.** In WireHop-integrated mode, remote access inherits
  WireHop's peer/role model over authenticated QUIC; hop-tap adds no separate
  remote auth. A way to reach sessions a peer's role should not see is a
  vulnerability (report the WireHop-side part to that project).
- **Act-on-session boundary.** `lock` and `quarantine` are creator-only. A way
  for a lesser role to lock, quarantine, or kill a session is a vulnerability.
- **Quarantine escape.** The quarantine sandbox uses Linux namespaces,
  `pivot_root`, capability drop and `no_new_privs`. A way for a quarantined
  shell to reach the real host filesystem, network, or process tree is a
  vulnerability.

## Known, intentional non-vulnerabilities

Scanners and reviewers will flag the following. They are deliberate.

### The `0666` socket

The socket is world-connectable on purpose: the access boundary is the
kernel-verified peer uid read via `SO_PEERCRED`, not filesystem permissions.
"Any local user can `connect()` to the socket" is expected; what matters is that
the uid check then restricts what they can see. If auditing-your-own-sessions is
not acceptable in your environment, do not install hop-tap.

### Captured content at rest

The daemon holds recent terminal output in memory to render snapshots and
replays. This is inherent to the tool. Protect the host accordingly.

### The pinned compiler fork

The eBPF crate builds with a pinned rustc fork (see `docs/ebpf-toolchain.md`).
That is a supply-chain consideration, documented and reproducible; the prebuilt
object shipped with releases is checksummed. Reports about the *provenance* of
that object are welcome; "uses a nightly fork" alone is known.
