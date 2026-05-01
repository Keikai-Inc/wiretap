"""
Shared renderer for the tap picker UI.

The real tap picker is a 80x24 TUI with cursor-positioned cells:
  rows 1-3   header box ("┌hop-tap───┐ / │tap — terminal session picker│ / └─┘")
  row  4     top borders of two side-by-side panes:
               left pane (sessions): cols 1-48
               right pane (preview): cols 49-80
  row  5     column header inside left pane
  rows 6-22  session rows (left pane) + preview text (right pane)
  row  23    bottom borders
  row  24    footer hint line

Both demo cast generators (build-demo-casts.py, build-pairing-casts.py)
build their picker frames through render_picker so the demo and the
real tap binary stay visually identical.
"""

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
REV = "\x1b[7m"


def render_picker(
    sessions,
    highlight_idx,
    preview_lines,
    preview_label_pty=None,
    title="tap — terminal session picker",
):
    """Build the full 80x24 picker frame.

    sessions: list of dicts. Each dict has keys:
        pty:        str, displayed in the pty column
        user:       str, the user(uid) display
        comm:       str, the foreground process comm
        age:        str, e.g. "82s"
        idle:       str, e.g. "0ms"
        user_color: optional str, ANSI color for the user cell only
                    (used to flag suspicious entries in red)
        prefix:     optional str, e.g. "🎭" — prepended to the row
                    inside the pty cell (replaces leading spaces)
    highlight_idx: int, which row to render in reverse video.
    preview_lines: list of strings to place inside the preview pane,
                   one per row starting at row 6.
    preview_label_pty: pty number string for the "preview (pty N)" header.
                      Defaults to the highlighted session's pty.
    """
    H = 24
    out = ["\x1b[2J\x1b[H"]

    # --- Header box (rows 1-3) ---
    # Row 1: ┌hop-tap─────────────────────────────────────────────────────────────┐
    label = "hop-tap"
    out.append(
        "\x1b[1;1H┌" + label + "─" * (80 - 2 - len(label)) + "┐"
    )
    # Row 2: │tap — terminal session picker                                                │
    title_padded = title.ljust(80 - 2)
    out.append(f"\x1b[2;1H│{title_padded}│")
    # Row 3: └────...────┘
    out.append("\x1b[3;1H└" + "─" * 78 + "┘")

    # --- Top of sessions + preview boxes (row 4) ---
    if preview_label_pty is None and sessions and 0 <= highlight_idx < len(sessions):
        preview_label_pty = sessions[highlight_idx]["pty"]
    sessions_label = "sessions"
    preview_label = f"preview (pty {preview_label_pty})"
    # Left box: cols 1-48 = 48 wide. Inner is cols 2-47 = 46 chars.
    left_top = "┌" + sessions_label + "─" * (48 - 2 - len(sessions_label)) + "┐"
    # Right box: cols 49-80 = 32 wide. Inner is cols 50-79 = 30 chars.
    right_top = "┌" + preview_label + "─" * (32 - 2 - len(preview_label)) + "┐"
    out.append(f"\x1b[4;1H{left_top}{right_top}")

    # --- Sessions header row (row 5) ---
    # Inner width is 46 chars. Column widths chosen to fit demo values
    # without truncation: "www-data(0)" is 11 chars, so user gets 11.
    #   pty(6) + user(11) + sep(1) + comm(8) + sep(2) + age(6) + sep(4) + idle(8) = 46
    PTY_W, USER_W, COMM_W, AGE_W, IDLE_W = 6, 11, 8, 6, 8
    header = (
        "pty".ljust(PTY_W)
        + "user".ljust(USER_W)
        + " "
        + "comm".ljust(COMM_W)
        + "  "
        + "age".ljust(AGE_W)
        + "    "
        + "idle".ljust(IDLE_W)
    )
    assert len(header) == 46, f"header is {len(header)} not 46"
    out.append(
        f"\x1b[5;1H│{BOLD}{header}{RESET}│"
        f"\x1b[5;49H│"
        f"\x1b[5;80H│"
    )

    # --- Session rows (rows 6+) ---
    def fit(s, n):
        s = str(s)
        return s[:n] if len(s) > n else s + " " * (n - len(s))

    for i, sess in enumerate(sessions):
        row = 6 + i
        if row > 22:
            break
        prefix = sess.get("prefix", "")
        pty_s = sess["pty"]
        user_s = sess["user"]
        comm_s = sess["comm"]
        age_s = sess["age"]
        idle_s = sess["idle"]
        user_color = sess.get("user_color", "")

        # The user_color escape doesn't take screen space, so pad on
        # the visible chars and inject the color around the padded text.
        pty_field = fit(prefix + pty_s, PTY_W) if prefix else fit(pty_s, PTY_W)
        user_padded = fit(user_s, USER_W)
        user_field = (user_color + user_padded + RESET) if user_color else user_padded
        comm_field = fit(comm_s, COMM_W)
        age_field = fit(age_s, AGE_W)
        idle_field = fit(idle_s, IDLE_W)

        content = (
            pty_field
            + user_field
            + " "
            + comm_field
            + "  "
            + age_field
            + "    "
            + idle_field
        )
        # content visible width: 6 + 11 + 1 + 8 + 2 + 6 + 4 + 8 = 46 ✓

        if i == highlight_idx:
            out.append(
                f"\x1b[{row};1H│{REV}{content}{RESET}│"
                f"\x1b[{row};49H│"
                f"\x1b[{row};80H│"
            )
        else:
            out.append(
                f"\x1b[{row};1H│{content}│"
                f"\x1b[{row};49H│"
                f"\x1b[{row};80H│"
            )

    # --- Empty session rows (fill to row 22) ---
    next_row = min(6 + len(sessions), 23)
    for row in range(next_row, 23):
        out.append(
            f"\x1b[{row};1H│" + " " * 46 + "│"
            f"\x1b[{row};49H│"
            f"\x1b[{row};80H│"
        )

    # --- Preview content (rows 6-22, right pane, cols 50-79 = 30 inner) ---
    for j, pline in enumerate(preview_lines[:17]):
        prow = 6 + j
        if prow > 22:
            break
        # Truncate visible width to 30 — but escape sequences don't count.
        # We leave that to the caller; just place at col 50 with a
        # leading space and pad with spaces to col 79.
        # Compute visible length (strip ESC[...m sequences).
        import re
        visible = re.sub(r"\x1b\[[0-9;]*m", "", pline)
        if len(visible) > 28:
            # Crude truncation that doesn't preserve embedded escapes
            # mid-string, but our preview lines are simple.
            pline = visible[:28]
            visible = pline
        pad = 28 - len(visible)
        out.append(f"\x1b[{prow};50H {pline}{' ' * pad} ")

    # --- Bottom borders (row 23) ---
    out.append("\x1b[23;1H└" + "─" * 46 + "┘└" + "─" * 30 + "┘")

    # --- Footer hint (row 24) ---
    footer = (
        f"{DIM}{len(sessions)} session(s) — ↑/↓ select  Enter=connect  "
        f"l=lock  Q=quarantine  x=kill  q=quit{RESET}"
    )
    out.append(f"\x1b[24;1H{footer}")

    return "".join(out)
