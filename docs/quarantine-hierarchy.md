# Quarantine hierarchy: design + status

Goal: when an admin quarantines a session, the picker should show
**both** the impostor (which the user is now talking to) **and** the
original shell (frozen in the background) as separate entries, with
hierarchy in the UI. The admin should be able to perform every normal
operation independently on either side:

- Connect to the impostor's shell (existing).
- Connect to the original shell (admin types into the real shell while
  the user keeps interacting with the honeypot).
- Lock / unlock the impostor.
- Lock / unlock the original.
- Kill the impostor (ends the honeypot, releases back to original).
- Kill the original (destroys the suspect's real session).
- Send admin messages to either.

The point of the hierarchy is dual-track investigation: while the
user is poking around in the honeypot, the admin can drive the real
shell independently — run forensics, look at what they were doing,
inspect history, etc. — without the user noticing.

## Architecture

The capture pty (`/dev/pts/N`) is a single kernel object with one
master and one slave. Two processes can't both interact with it
without colliding. To get independent live access to *both* the
impostor and the original, **the original shell has to be moved to a
new pty** (`/dev/pts/M`) at quarantine activation. After migration:

- `pts/N`: master held by sshd / local terminal emulator (= the user),
  slave held by the impostor bash. User talks to impostor.
- `pts/M`: master held by the daemon, slave held by the original
  shell. Daemon mediates admin's `tap connect` to the original.

Both ptys appear in the daemon's session table as normal sessions.
The picker renders them paired with hierarchy. Admin operations work
on whichever pty the row points at.

```
🎭 N   alice  bash (impostor)        ← live, user is here
  ↳ M   alice  bash (original)       ← live, admin can connect privately
```

Release flow: kill the impostor on N, ptrace-migrate the original
shell back from M to N, free pty M. User is back on N, no idea.

## Phase 1: picker hierarchy + per-row dispatch (no migration yet)

Smallest cut that gives the UI shape and unblocks the plumbing.
Without pty migration, we surface the original as a synthetic child
row and only some operations are real:

- `kill` on the original → `kill(opener_pid, SIGHUP)` (or SIGKILL on
  force). Real and useful immediately.
- `connect` on the original → "needs pty migration — coming next"
  flash; or read-only forensic snapshot of the pre-quarantine screen.
- `lock` on the original → no-op (already SIGSTOPped). Surfaces a
  message.
- admin message → goes to the same `/dev/pts/N` either way.

### Wire shape

```rust
// crates/hop-tap-protocol/src/lib.rs

enum TapRequest {
    // ...
    /// Kill the *original* shell of a quarantined session.
    /// Targets opener_pid directly; impostor stays running.
    KillOriginal { pty_index: i32, force: bool },
}

enum TapResponse {
    // ...
    OriginalKilled { pty_index: i32, pid: u32, signal: i32 },
}

struct SessionInfo {
    // ... existing fields
    /// Populated when this session is quarantined: snapshot of the
    /// original shell's identity + the pre-quarantine screen state,
    /// so the picker can render it as a child row.
    pub original: Option<OriginalRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginalRow {
    pub opener_pid: u32,
    pub opener_comm: String,
    pub opener_uid: u32,
    pub opener_username: Option<String>,
    /// Pre-quarantine snapshot, one string per row. Used in the
    /// preview pane when the admin highlights the child row.
    pub snapshot: Vec<String>,
    pub snapshot_rows: u16,
    pub snapshot_cols: u16,
    /// Phase 2: when migration lands, this carries the original
    /// shell's new pty index. None during phase 1.
    pub migrated_pty: Option<i32>,
}
```

### Daemon

- `SessionState` gains `quarantine_original_snapshot: Option<Vec<String>>`
  + the dims at snapshot time. Captured in `quarantine_session` via
  `state.snapshot_full_screen()` *before* spawning the impostor.
- `to_session_info` populates `original` from those fields when
  `state.quarantined` is true.
- `handle_kill_original`:
  - Self-pty + scope + opener-or-creator checks.
  - `kill(state.opener_pid, signal)`.
  - On success, clear `state.quarantined`, the impostor PID, the
    snapshot, etc., and SIGTERM the impostor too (the original is
    gone, the impostor has nothing to release back to).

### Picker

- The flat-list approach: at render time, walk the `sessions` Vec and
  build a `Vec<RowKey>` where `RowKey = (session_index, RowKind)` and
  `RowKind = Live | Original`. Live rows always present;
  Original rows present iff `sessions[i].original.is_some()`.
- `TableState::selected()` indexes into the flat row list.
- Up/Down navigation moves through the flat list, so the user can
  highlight either the parent or the child.
- Per-row dispatch:
  ```rust
  match (row.kind, key) {
      (Live,     'x')   => send_kill(...),
      (Original, 'x')   => send_kill_original(...),
      (Live,     Enter) => connect(...),
      (Original, Enter) => flash("needs pty migration — phase 2"),
      (Live,     'l')   => send_set_lock(...),
      (Original, 'l')   => flash("original is already locked"),
      // ...
  }
  ```
- Render: parent row prefix `🎭 N`, child row prefix `  ↳ N`. Live row
  shows live preview as today; Original row shows
  `original.snapshot` in the preview pane.

### Tests / verify

- Quarantine a session → picker shows two rows.
- `x` on parent → kills impostor, releases (via existing flow).
- `x` on child → original shell (the suspect's real bash) dies,
  impostor stays. Releasing now is a no-op on the original side; the
  daemon should detect "no original to release back to" and tear down
  the impostor too.
- Picker preview on child → shows the frozen pre-quarantine screen.

## Phase 2: ptrace pty-migration

The expensive but rewarding part. Migrate the original shell off
`pts/N` onto a daemon-owned `pts/M` so the admin's `tap connect` can
drive it independently.

### Algorithm (à la reptyr, but as a one-shot at quarantine time)

```
1. Daemon allocates a fresh pty pair via openpty(3) — keeps both
   master_fd and slave_path.
2. Daemon ptrace_attaches to the SIGSTOPped original shell (already
   stopped, perfect timing for a syscall injection).
3. Find a `syscall` instruction (0x0F 0x05 on x86_64) in the target's
   address space — typically inside libc, usable via PEEKDATA scans
   of the executable mappings.
4. Inject syscall: open(slave_path, O_RDWR) → returns slave_fd inside
   the target's fd table. Save the value.
5. Inject dup2(slave_fd, 0), dup2(slave_fd, 1), dup2(slave_fd, 2),
   close(slave_fd) — original now reads/writes on M.
6. Detach ptrace.
7. Daemon already has master_fd from step 1 — keep it; that's how the
   daemon mediates admin connect to the original shell.
8. Register a synthetic `SessionState` for pts/M, marked as the
   `Original` half of pts/N.
9. SIGCONT the original shell. It resumes on its new pty.
```

Reptyr does this in C in ~1500 lines; a careful Rust port lands
around ~500-700 lines. The `nix` crate covers ptrace / waitpid /
prctl primitives.

### Subtleties to plan for

- **Syscall return value**: after single-stepping the syscall
  instruction, RAX holds the return. We need to PEEKUSER the
  registers each time and detect errors (negative RAX maps to
  -errno).
- **Restore RIP + regs**: every syscall injection has to leave the
  process in exactly the state we found it. Save full register set
  before, restore after the last injection.
- **Address-space holes**: target's libc must be mapped (it almost
  always is for a bash process). Worst case we scan executable
  mappings for `0F 05`.
- **Threads**: bash is single-threaded; doesn't apply, but if we
  later support migrating multi-threaded targets we'd have to ptrace
  every thread.
- **Argument pages**: `open(slave_path, ...)` needs the `slave_path`
  string in the target's address space. Two options: PEEKDATA-scan
  for an existing copy of `/dev/pts/M` (won't find one), or POKEDATA
  the string onto the target's stack temporarily and restore after.
  Reptyr uses the stack approach.
- **Reverse migration on release**: same dance, just dup2'ing back to
  fd-of-N's-slave and closing M's fd. The daemon hands fd-of-N to
  the target via the same trick.

### Wire shape (phase 2 additions)

```rust
struct OriginalRow {
    // ...
    pub migrated_pty: Option<i32>,  // Some(M) once phase 2 lands
}

// Picker dispatches to the migrated pty for live operations:
match (row.kind, key) {
    (Original, Enter) => {
        let target_pty = row.migrated_pty.unwrap();  // pts/M
        connect(target_pty)
    }
    // ...
}
```

The kill / lock / admin-message paths get their target pty from
`migrated_pty` (when present) or fall back to `opener_pid` (phase 1
behavior).

## Where to pick up

1. Apply phase 1 (this doc → code in
   `crates/hop-tap-protocol/src/lib.rs`,
   `crates/hop-tap-d/src/main.rs`, `crates/hop-tap-d/src/bin/tap.rs`).
2. Verify in the picker that quarantining shows two rows + `x` on
   each row hits the right pid.
3. Read `reptyr/main.c` and the ptrace(2) manpage. Have the target
   process running locally so you can stuff bytes into another bash
   for ground-truth testing.
4. Implement the syscall-injection helper in
   `crates/hop-tap-d/src/linux/ptrace_inject.rs` — small, focused
   module with `inject_syscall(pid, nr, args)` as the public entry
   point.
5. Wire migration into `quarantine_session` (after SIGSTOP, before
   spawning impostor) and reverse-migration into
   `release_quarantine`.

## References

- `man 2 ptrace`
- reptyr source: <https://github.com/nelhage/reptyr>
- "Reverse engineering the seemingly impossible" by Nelson Elhage,
  the original reptyr blog post.
- Linux kernel `kernel/ptrace.c` for PTRACE_SETREGS / PEEKDATA /
  POKEDATA semantics on x86_64.
