# Contributing to hop-tap

Thanks for your interest. A few ground rules keep the project healthy.

## Before you start

- For anything beyond a small fix, open an issue first to discuss the change.
- Read `AGENTS.md` — the working guide for the codebase (build, test, the eBPF
  lane, and compatibility constraints), for humans and AI agents alike.
- hop-tap is Linux-first. The userspace crates compile on macOS for development,
  but the daemon only does anything real on Linux.

## Requirements for a mergeable PR

1. `HOP_TAP_SKIP_EBPF_BUILD=1 cargo clippy --all-targets` is clean — zero
   warnings.
2. `HOP_TAP_SKIP_EBPF_BUILD=1 cargo test` passes.
3. Wire-protocol changes (`crates/hop-tap-protocol`) keep backward compatibility:
   enums are append-only, existing message variants keep their fields. A daemon
   and a client at adjacent versions must interoperate.
4. Kernel-side changes (`crates/hop-tap-ebpf`) build with the pinned toolchain
   (`docs/ebpf-toolchain.md`); say in the PR which kernel versions you tested on.
5. Anything touching capture, the socket auth path, or quarantine gets a note in
   the PR describing the security reasoning.

## You do not need the compiler fork

The eBPF object ships prebuilt. Set `HOP_TAP_SKIP_EBPF_BUILD=1` and you can build,
test and run the daemon and CLI with stable Rust. You only need the pinned
toolchain to change the kernel-side program itself.

## Security issues

Do not open public issues for vulnerabilities — see `SECURITY.md`.

## License

By contributing, you agree that your contributions are dual-licensed under
MIT OR Apache-2.0, matching the project.
