# Building the eBPF toolchain

hop-tap's kernel-side program (`crates/hop-tap-ebpf`) reads fields out of
kernel structs (`task_struct`, `tty_struct`, `tty_driver`) whose offsets differ
between kernel versions. It handles that with CO-RE ("compile once, run
everywhere") relocations: the compiler records *which field* was accessed, and
the loader patches the real offset in from the running kernel's BTF at load
time. One `.bpf.o` therefore runs unchanged on kernels from 5.4 to 6.x.

Stable Rust cannot emit those relocations yet. The work to add them is
[RFC 3966](https://github.com/rust-lang/rfcs/pull/3966) with an implementation
PR at [rust-lang/rust#161107](https://github.com/rust-lang/rust/pull/161107),
both still open. hop-tap builds with a pinned commit of that implementation
from its author's fork. This document is the complete recipe. Everything in
it is scripted in [`scripts/build-ebpf-toolchain.sh`](../scripts/build-ebpf-toolchain.sh).

Only the eBPF crate needs this toolchain. The userspace daemon and CLI build
with stable Rust; see [Building without the toolchain](#building-without-the-toolchain).

## What is pinned

| Component | Source | Pin | Notes |
|---|---|---|---|
| rustc | `https://github.com/vadorovsky/rust` | commit `26afb49e7af` (branch `btf-relocations`) | upstream master `2bd7a97871a` (2026-04-01, 1.96.0-nightly) plus three commits |
| LLVM | downloaded by rustc's bootstrap (`download-ci-llvm`) | 22.1.2 | no LLVM build required |
| bpf-linker | `https://github.com/aya-rs/bpf-linker` | commit `a08a2f5` (v0.10.3 + 6) | built against LLVM 22 |
| aya-ebpf | crates.io | 0.1.1 (`crates/hop-tap-ebpf/Cargo.lock`) | |

The three fork commits on top of upstream:

```
30cc9af5623  compiler: Add support for BTF relocations for BPF targets
188b0ed6cc4  compiler: Add `PlaceValue::new_sized_with_llextra` constructor
26afb49e7af  compiler, library: Add `btf_field_byte_offset` intrinsic
```

**Pin the commit, not the branch.** The fork has newer branches
(`btf-relocations-v2`, `-v4`, `vad/btf-relocations`) that track the RFC as it
evolves, and the RFC has since renamed the surface (`#[btf_relocatable]`,
`field_byte_offset!`). hop-tap's `vmlinux.rs` uses the spelling at
`26afb49e7af`: `#![feature(relocatable_types)]` and `#[relocatable]`. A newer
commit will not compile it.

## Prerequisites

- 64-bit Linux (x86_64 or aarch64) or macOS (Apple Silicon or Intel). The
  eBPF object is host-independent, so any of these hosts produces the same
  bytecode.
- `git`, `python3`, `curl`, a C/C++ compiler (`build-essential` on Debian and
  Ubuntu, Xcode command-line tools on macOS), `cmake` and `ninja` (bootstrap
  wants them even when LLVM is downloaded).
- LLVM 22 development libraries for bpf-linker:
  - macOS: `brew install llvm@22`
  - Debian/Ubuntu: `apt install llvm-22-dev libpolly-22-dev` from
    [apt.llvm.org](https://apt.llvm.org)
  - x86_64 Linux only: bpf-linker can instead borrow rustc's own libLLVM
    (`rust-llvm-22` feature); the script uses system LLVM for consistency.
- `rustup` with a stable toolchain (bootstrap downloads its own stage0).
- Roughly 20 GB of disk and 30–90 minutes for the rustc build, depending on
  core count.

## Step 1: build the rustc fork

```bash
git clone --filter=blob:none https://github.com/vadorovsky/rust.git rust-btf
cd rust-btf
git checkout 26afb49e7af

cat > bootstrap.toml <<'TOML'
# hop-tap eBPF toolchain. "compiler" profile: download-ci-llvm = true (no LLVM
# build), download-rustc = false (we are modifying rustc), incremental = true.
profile = "compiler"

[build]
docs = false
compiler-docs = false
TOML

./x build --stage 1 library
```

That produces a sysroot at `build/<host-triple>/stage1` containing `rustc`
and the library source under `lib/rustlib/src/rust`, which
`-Z build-std=core` needs. It has no `cargo`; rustup supplies the one from
your stable toolchain when you invoke `cargo +stage1-vlad`.

Register it with rustup under the name hop-tap expects:

```bash
rustup toolchain link stage1-vlad "$PWD/build/$(rustc -vV | sed -n 's/^host: //p')/stage1"
rustc +stage1-vlad -vV
# rustc 1.96.0-dev
# LLVM version: 22.1.2
```

Any other name works too: set `HOP_TAP_BPF_TOOLCHAIN=<name>` when building
hop-tap.

## Step 2: build bpf-linker

bpf-linker links the LLVM bitcode rustc emits into the final ELF and writes
the `.BTF` / `.BTF.ext` sections that carry the relocations. Its LLVM major
version must match rustc's (22).

```bash
git clone https://github.com/aya-rs/bpf-linker.git
cd bpf-linker
git checkout a08a2f5

# macOS
LLVM_SYS_221_PREFIX="$(brew --prefix llvm@22)" \
  cargo install --path . --no-default-features --features llvm-22 --locked

# Debian/Ubuntu (apt.llvm.org packages)
LLVM_SYS_221_PREFIX=/usr/lib/llvm-22 \
  cargo install --path . --no-default-features --features llvm-22 --locked

bpf-linker --version   # bpf-linker 0.10.3
```

`cargo install` puts it in `~/.cargo/bin`, which is on PATH. rustc's BPF
targets look for a linker literally named `bpf-linker` on PATH, so nothing
else is configured. If you keep it elsewhere, pass
`--config 'target.bpfel-unknown-none.linker="/path/to/bpf-linker"'` to cargo.

## Step 3: build hop-tap

On Linux, the normal workspace build does everything: `hop-tap-d`'s `build.rs`
runs `cargo +stage1-vlad build --release --target bpfel-unknown-none -Z build-std=core`
inside `crates/hop-tap-ebpf`, and `main.rs` embeds the result with
`include_bytes_aligned!`.

```bash
cargo build --release              # userspace + eBPF
```

To build only the eBPF object (any host):

```bash
cd crates/hop-tap-ebpf
cargo +stage1-vlad build --release
ls -l target/bpfel-unknown-none/release/hop-tap-ebpf     # ~85 KB ELF
```

Check that the relocations are present:

```bash
llvm-readelf -S target/bpfel-unknown-none/release/hop-tap-ebpf | grep -E '\.BTF'
#   .BTF        PROGBITS ...
#   .BTF.ext    PROGBITS ...   <- the CO-RE relocation records
```

Environment variables honoured by `build.rs`:

| Variable | Effect |
|---|---|
| `HOP_TAP_BPF_TOOLCHAIN` | rustup toolchain name to use (default `stage1-vlad`) |
| `HOP_TAP_SKIP_EBPF_BUILD` | skip the eBPF cross-build and embed whatever object is already at `crates/hop-tap-ebpf/target/bpfel-unknown-none/release/hop-tap-ebpf` |

## Building without the toolchain

The userspace crates (`hop-tap-d`, the `tap` CLI, `hop-tap-protocol`) are
plain stable Rust. If you are not touching `crates/hop-tap-ebpf`, you do not
need the fork: set `HOP_TAP_SKIP_EBPF_BUILD=1` and place a prebuilt object at
the path above. Each release publishes the exact object it shipped as
`hop-tap-ebpf` next to the binaries, with a `.sha256` sidecar, so a userspace
change can be built and tested against the same bytecode users are running.

On macOS the workspace resolves and builds with the eBPF step skipped
automatically (the loader is `cfg(target_os = "linux")`), which is how the
daemon and CLI are developed; the resulting daemon reports "linux only".

## Releasing

`scripts/release.sh` builds the eBPF object once on the release host with
`stage1-vlad`, then cross-compiles the userspace binaries for both Linux
architectures with `HOP_TAP_SKIP_EBPF_BUILD=1` so every artifact embeds the
same bytecode.

## When upstream lands

Once `rust-lang/rust#161107` merges and the feature reaches nightly, the
plan is to port `vmlinux.rs` to the RFC's final spelling and retire this
document in favour of a plain `nightly` pin. Until then, the commit above is
the only compiler that builds this crate.
