#!/usr/bin/env python3
"""
Generate the side-by-side pairing demo casts from a single storyboard.

Produces:
  site/senior.cast — alice (senior, sudo'd to root) running tap
  site/junior.cast — bob (regular user) stuck on a failing nginx reload

Same pattern as build-demo-casts.py but a friendlier scenario: bob is
debugging a failing nginx config. alice gets a slack-ping (off-screen),
sudoes to root, taps into bob's pty, watches briefly, sends a hint
via Ctrl-G ("try nginx -t"), bob fixes it, says thanks.

Run:
  python3 scripts/build-pairing-casts.py
"""

import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from picker_render import render_picker

W, H = 80, 24

random.seed(11)

events = []  # (t: float, side: str, data: str)


def at(t, side, data):
    events.append((t, side, data))


def type_str(t0, side, s, cps=12, jitter=0.45):
    t = t0
    for ch in s:
        at(t, side, ch)
        delay = (1.0 / cps) * (1 + random.uniform(-jitter, jitter))
        t += max(0.02, delay)
    return t


# ───── Color helpers ─────
RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
REV = "\x1b[7m"


def fg(code):
    return f"\x1b[{code}m"


GREEN = fg(32)
RED = fg(31)
BLUE = fg(34)
YELLOW = fg(33)
CYAN = fg(36)
MAGENTA = fg(35)
GREY = fg(90)


def alice_prompt():
    return f"{BOLD}{GREEN}alice@web-prod{RESET}:{BOLD}{BLUE}~{RESET}$ "


def admin_prompt():
    """alice after sudo -i — same as the takedown demo."""
    return f"{BOLD}{RED}root@web-prod{RESET}:{BOLD}{BLUE}~{RESET}# "


def bob_prompt():
    """bob is a regular user. Distinct color (yellow user@) from the
    takedown's red root@ so the two demos read differently at a glance."""
    return f"{BOLD}{YELLOW}bob@web-prod{RESET}:{BOLD}{BLUE}~{RESET}$ "


# ───── Storyboard ─────
#
# Beat list (~26s):
#   t=0..3:   bob tries `sudo systemctl reload nginx`, it fails
#   t=3..7:   bob runs status + journalctl, sees a cryptic emerg line
#   t=4..8:   alice gets paged on slack, sudoes, runs tap
#   t=8..11:  alice picks bob's pty, attaches, watches
#   t=11..14: alice presses Ctrl-G, sends "try nginx -t"
#   t=14..16: bob runs `sudo nginx -t`, sees /etc/nginx/...:42 emerg
#   t=16..20: bob fixes line 42 with sed, reloads, success
#   t=20..23: bob sends thanks via Ctrl-G; alice detaches

SENIOR = "senior"
JUNIOR = "junior"

# Initial prompts. alice has just opened a terminal; bob has been working
# in his shell for a while.
at(0.0, SENIOR, "\x1b[2J\x1b[H" + alice_prompt())
at(0.0, JUNIOR, "\x1b[2J\x1b[H" + bob_prompt())

# ── Junior: tries to reload nginx, fails ──
t = 0.5
t = type_str(t, JUNIOR, "sudo systemctl reload nginx", cps=14)
at(t + 0.20, JUNIOR, "\r\n")
at(t + 0.40, JUNIOR, "[sudo] password for bob: ")
at(t + 1.10, JUNIOR, "\r\n")
at(t + 1.30, JUNIOR,
   f"Job for nginx.service failed because the control process exited with error code.\r\n")
at(t + 1.50, JUNIOR,
   f"See \"systemctl status nginx.service\" and \"journalctl -xeu nginx.service\" for details.\r\n")
at(t + 1.70, JUNIOR, bob_prompt())

# ── Junior: status check ──
t = 4.5
t = type_str(t, JUNIOR, "sudo systemctl status nginx", cps=14)
at(t + 0.20, JUNIOR, "\r\n")
at(t + 0.35, JUNIOR,
   f"{RED}×{RESET} nginx.service - A high performance web server and a reverse proxy server\r\n")
at(t + 0.45, JUNIOR,
   f"     Loaded: loaded (/lib/systemd/system/nginx.service; enabled; preset: enabled)\r\n")
at(t + 0.55, JUNIOR,
   f"     Active: {RED}failed{RESET} (Result: exit-code) since Mon 2026-04-30 14:22:11 UTC\r\n")
at(t + 0.65, JUNIOR,
   f"   Main PID: 4421 (code=exited, status=1/FAILURE)\r\n")
at(t + 0.80, JUNIOR,
   f"\r\nApr 30 14:22:11 web-prod systemd[1]: nginx.service: Control process exited, code=exited, status=1\r\n")
at(t + 0.95, JUNIOR,
   f"Apr 30 14:22:11 web-prod systemd[1]: Reload failed for nginx.service.\r\n")
at(t + 1.10, JUNIOR, bob_prompt())

# ── Junior: journalctl, finds the emerg but the line is buried ──
t = 7.0
t = type_str(t, JUNIOR, "sudo journalctl -u nginx -n 5 --no-pager", cps=14)
at(t + 0.20, JUNIOR, "\r\n")
at(t + 0.35, JUNIOR,
   f"Apr 30 14:22:11 web-prod systemd[1]: Reloading nginx.service...\r\n")
at(t + 0.45, JUNIOR,
   f"Apr 30 14:22:11 web-prod nginx[4421]: nginx: the configuration file /etc/nginx/nginx.conf syntax is\r\n")
at(t + 0.55, JUNIOR,
   f"Apr 30 14:22:11 web-prod nginx[4421]: nginx: [emerg] invalid value \"foo\" in /etc/nginx/conf.d/site.conf:42\r\n")
at(t + 0.65, JUNIOR,
   f"Apr 30 14:22:11 web-prod systemd[1]: nginx.service: Control process exited, code=exited, status=1\r\n")
at(t + 0.75, JUNIOR,
   f"Apr 30 14:22:11 web-prod systemd[1]: Reload failed for nginx.service.\r\n")
at(t + 0.95, JUNIOR, bob_prompt())

# ── Senior: alice gets pinged on slack, sudoes ──
# t_sudo intentionally lands during bob's status output so alice's
# response feels concurrent.
t_sudo = 4.0
t_sudo = type_str(t_sudo, SENIOR, "sudo -i", cps=14)
at(t_sudo + 0.20, SENIOR, "\r\n")
at(t_sudo + 0.40, SENIOR, "[sudo] password for alice: ")
at(t_sudo + 1.10, SENIOR, "\r\n")
at(t_sudo + 1.20, SENIOR, "Last login: Mon Apr 30 14:18:03 2026 from 10.0.0.42\r\n")
at(t_sudo + 1.30, SENIOR, admin_prompt())

# ── Senior: opens picker ──
t_tap = 7.0
t_tap = type_str(t_tap, SENIOR, "tap", cps=10)
at(t_tap + 0.30, SENIOR, "\r\n")

def emit_picker(t, highlight_bob=True, preview_lines=None):
    """Render the picker for the pairing scenario.

    Both rows are non-suspicious: alice is sudo'd to root (expected
    for an operator), bob is a regular uid 1001 user holding his own
    shell. No red, no privesc mismatch — this is the everyday
    'who's-logged-in?' view."""
    sessions = [
        {
            "pty": "3",
            "user": "alice(0)",
            "comm": "tap",
            "age": "3m",
            "idle": "0ms",
        },
        {
            "pty": "7",
            "user": "bob(1001)",
            "comm": "bash",
            "age": "18m",
            "idle": "0ms",
            "user_color": YELLOW,
        },
    ]
    highlight_idx = 1 if highlight_bob else 0
    frame = render_picker(
        sessions=sessions,
        highlight_idx=highlight_idx,
        preview_lines=preview_lines or [],
        preview_label_pty=sessions[highlight_idx]["pty"],
    )
    at(t, SENIOR, frame)


# Picker first appears after the `tap\r\n`.
emit_picker(
    t_tap + 0.45,
    highlight_bob=True,
    preview_lines=[
        f"Apr 30 14:22:11 web-prod nginx[4421]: nginx: [emerg] invalid value",
        f"  \"foo\" in /etc/nginx/conf.d/site.conf:42",
        f"Apr 30 14:22:11 web-prod systemd[1]: nginx.service: Control process",
        f"  exited, code=exited, status=1",
        f"Apr 30 14:22:11 web-prod systemd[1]: Reload failed for nginx.service.",
        bob_prompt(),
    ],
)

# ── Senior: presses Enter to attach ──
# Both panes paint the same content at attach time, sourced from
# one string so they're guaranteed to agree. Bob's pane is "fake
# repainted" here — in real tap bob's terminal doesn't get
# re-rendered when someone attaches. The marketing cast cares about
# pane consistency more than simulating bob's terminal-emulator
# scrollback. Without this, bob's accumulated wrap+scroll
# divergences vs alice's clean snapshot are visible to viewers.
#
# Lines kept short enough to never wrap in 80 cols.
t_attach = 11.5
shared_screen = (
    bob_prompt() + "sudo systemctl reload nginx\r\n"
    + "Job for nginx.service failed (control process exit code).\r\n"
    + "See: journalctl -xeu nginx.service\r\n"
    + bob_prompt() + "sudo systemctl status nginx\r\n"
    + f"{RED}×{RESET} nginx.service - A high performance web server\r\n"
    + f"     Active: {RED}failed{RESET} (Result: exit-code)\r\n"
    + "   Main PID: 4421 (code=exited, status=1/FAILURE)\r\n"
    + bob_prompt() + "sudo journalctl -u nginx -n 3 --no-pager\r\n"
    + "Apr 30 14:22:11 systemd[1]: Reloading nginx.service...\r\n"
    + f"Apr 30 14:22:11 nginx[4421]: nginx: [{RED}emerg{RESET}] invalid value \"foo\" in site.conf:42\r\n"
    + "Apr 30 14:22:11 systemd[1]: Reload failed for nginx.service.\r\n"
    + bob_prompt()
)
# Bob's pane: clear and re-paint to the canonical state.
at(t_attach, JUNIOR, "\x1b[2J\x1b[H")
at(t_attach + 0.02, JUNIOR, shared_screen)
# Alice's pane: same content, prefixed with the connect banner.
attach_snapshot = (
    f"{DIM}[tap connect pty=7 bob@web-prod — Ctrl-T detach  Ctrl-G message]{RESET}\r\n"
    + shared_screen
)
at(t_attach, SENIOR, "\x1b[2J\x1b[H")
at(t_attach + 0.05, SENIOR, attach_snapshot)

# ── Senior: presses Ctrl-G, types a hint message ──
t_compose_open = t_attach + 2.5
at(t_compose_open, SENIOR,
   f"\x1b[24;1H\x1b[K{REV}{BLUE} alice > {RESET}{BLUE}")
t = t_compose_open + 0.3
t = type_str(t, SENIOR, "try `nginx -t` — it points at the bad line", cps=11)
t_send = t + 0.4
at(t_send, SENIOR, RESET + "\x1b[24;1H\x1b[K")

# ── Junior: alice's message flashes onto bob's terminal ──
ALICE_MSG = (
    "\r\n\x07"
    f"{REV}{BLUE}  admin: alice  {RESET}\r\n"
    f"{BLUE}  try `nginx -t` — it points at the bad line{RESET}\r\n"
    "\r\n"
)
at(t_send + 0.05, JUNIOR, ALICE_MSG)
at(t_send + 0.10, JUNIOR, bob_prompt())
# Mirror on senior's side too — alice sees what bob sees.
at(t_send + 0.05, SENIOR, ALICE_MSG)
at(t_send + 0.10, SENIOR, bob_prompt())

# ── Junior: runs nginx -t, sees the line number ──
t = t_send + 1.5
typed = "sudo nginx -t"
for ch in typed:
    at(t, JUNIOR, ch)
    at(t, SENIOR, ch)
    delay = (1.0 / 13) * (1 + random.uniform(-0.4, 0.4))
    t += max(0.02, delay)
at(t + 0.15, JUNIOR, "\r\n"); at(t + 0.15, SENIOR, "\r\n")
at(t + 0.30, JUNIOR,
   "nginx: the configuration file /etc/nginx/nginx.conf syntax is\r\n")
at(t + 0.30, SENIOR,
   "nginx: the configuration file /etc/nginx/nginx.conf syntax is\r\n")
at(t + 0.45, JUNIOR,
   f"nginx: [{RED}emerg{RESET}] invalid value \"foo\" in /etc/nginx/conf.d/site.conf:42\r\n")
at(t + 0.45, SENIOR,
   f"nginx: [{RED}emerg{RESET}] invalid value \"foo\" in /etc/nginx/conf.d/site.conf:42\r\n")
at(t + 0.60, JUNIOR,
   f"nginx: configuration file /etc/nginx/nginx.conf test {RED}failed{RESET}\r\n")
at(t + 0.60, SENIOR,
   f"nginx: configuration file /etc/nginx/nginx.conf test {RED}failed{RESET}\r\n")
at(t + 0.80, JUNIOR, bob_prompt())
at(t + 0.80, SENIOR, bob_prompt())
t_after_check = t + 0.95

# ── Junior: fixes line 42 with sed ──
t = t_after_check + 0.6
typed = "sudo sed -i '42s/foo/on/' /etc/nginx/conf.d/site.conf"
for ch in typed:
    at(t, JUNIOR, ch)
    at(t, SENIOR, ch)
    delay = (1.0 / 14) * (1 + random.uniform(-0.4, 0.4))
    t += max(0.02, delay)
at(t + 0.15, JUNIOR, "\r\n"); at(t + 0.15, SENIOR, "\r\n")
# sed -i is silent on success.
at(t + 0.30, JUNIOR, bob_prompt())
at(t + 0.30, SENIOR, bob_prompt())
t_after_sed = t + 0.45

# ── Junior: reload again, this time it works ──
t = t_after_sed + 0.5
typed = "sudo systemctl reload nginx"
for ch in typed:
    at(t, JUNIOR, ch)
    at(t, SENIOR, ch)
    delay = (1.0 / 13) * (1 + random.uniform(-0.4, 0.4))
    t += max(0.02, delay)
at(t + 0.15, JUNIOR, "\r\n"); at(t + 0.15, SENIOR, "\r\n")
# Successful reload — silent. Show the prompt back.
at(t + 0.45, JUNIOR, bob_prompt())
at(t + 0.45, SENIOR, bob_prompt())
t_after_reload = t + 0.60

# ── Junior: confirms it's running ──
t = t_after_reload + 0.6
typed = "systemctl is-active nginx"
for ch in typed:
    at(t, JUNIOR, ch)
    at(t, SENIOR, ch)
    delay = (1.0 / 13) * (1 + random.uniform(-0.4, 0.4))
    t += max(0.02, delay)
at(t + 0.15, JUNIOR, "\r\n"); at(t + 0.15, SENIOR, "\r\n")
at(t + 0.30, JUNIOR, f"{GREEN}active{RESET}\r\n")
at(t + 0.30, SENIOR, f"{GREEN}active{RESET}\r\n")
at(t + 0.45, JUNIOR, bob_prompt())
at(t + 0.45, SENIOR, bob_prompt())
t_after_active = t + 0.60

# ── Junior: thanks via `tap reply` ──
# Bob doesn't have a hidden "Ctrl-G to chat back" mode (that would
# leak the fact he's being tapped to anyone who hits Ctrl-G in
# their shell). Instead, bob runs `tap reply` — an explicit,
# user-initiated subcommand that fans the message out to whoever
# is observing his session. Available to anyone, no tapper
# privilege required.
t = t_after_active + 0.6
typed = 'tap reply "thanks! 🙏"'
for ch in typed:
    at(t, JUNIOR, ch)
    at(t, SENIOR, ch)
    delay = (1.0 / 13) * (1 + random.uniform(-0.4, 0.4))
    t += max(0.02, delay)
at(t + 0.15, JUNIOR, "\r\n"); at(t + 0.15, SENIOR, "\r\n")
# `tap reply` reports delivery on bob's stdout so he knows the
# message went through.
at(t + 0.30, JUNIOR, "reply delivered to 1 tapper\r\n")
at(t + 0.30, SENIOR, "reply delivered to 1 tapper\r\n")
at(t + 0.45, JUNIOR, bob_prompt())
at(t + 0.45, SENIOR, bob_prompt())
t_thanks_send = t + 0.55

# Alice's tap CLI receives a UserReply frame and renders it as an
# overlay banner — same shape as how bob saw alice's admin
# message earlier, but in cyan so the direction reads at a glance.
BOB_MSG = (
    "\r\n\x07"
    f"{REV}{CYAN}  reply: bob  {RESET}\r\n"
    f"{CYAN}  thanks! 🙏{RESET}\r\n"
    "\r\n"
)
at(t_thanks_send + 0.05, SENIOR, BOB_MSG)
at(t_thanks_send + 0.10, SENIOR, bob_prompt())

# ── Senior: detaches (Ctrl-T, no visible char), picker reappears ──
# Hold on the reply banner for ~3.5s so viewers actually register
# it — 1.4s before picker takeover was below conscious-perception
# threshold for many people, especially at the end of a long demo.
t_detach = t_thanks_send + 3.5
emit_picker(
    t_detach,
    highlight_bob=True,
    preview_lines=[
        f"{GREEN}active{RESET}",
        bob_prompt(),
        f"{REV}{CYAN}  reply: bob  {RESET}",
        f"{CYAN}  thanks! 🙏{RESET}",
        "",
        bob_prompt(),
    ],
)

T_END = t_detach + 2.5
at(T_END, SENIOR, "")
at(T_END, JUNIOR, "")


# ───── Emit cast files ─────
def write_cast(side, path):
    side_events = sorted([(t, d) for (t, s, d) in events if s == side], key=lambda e: e[0])
    header = {
        "version": 2,
        "width": W,
        "height": H,
        "timestamp": 1777573800,
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
    }
    with open(path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for t, data in side_events:
            if not data:
                continue
            f.write(json.dumps([round(t, 4), "o", data]) + "\n")


here = os.path.dirname(os.path.abspath(__file__))
site = os.path.join(here, "..", "site")
write_cast(SENIOR, os.path.join(site, "senior.cast"))
write_cast(JUNIOR, os.path.join(site, "junior.cast"))

duration = max(e[0] for e in events)
print(f"wrote site/senior.cast and site/junior.cast (~{duration:.1f}s total)")
