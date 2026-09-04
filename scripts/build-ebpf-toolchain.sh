#!/usr/bin/env bash
# build-ebpf-toolchain.sh — build the pinned rustc fork + bpf-linker that
# compile crates/hop-tap-ebpf. Full rationale and the manual steps are in
# docs/ebpf-toolchain.md; this script is that document, executable.
#
# Usage:
#   ./scripts/build-ebpf-toolchain.sh [--work DIR] [--toolchain NAME]
#                                     [--skip-rustc] [--skip-linker] [--jobs N]
#
#   --work DIR        where to clone and build (default: ~/.hop-tap-toolchain)
#   --toolchain NAME  rustup toolchain name to register (default: stage1-vlad,
#                     which is what build.rs looks for)
#   --skip-rustc      only build bpf-linker
#   --skip-linker     only build rustc
#   --jobs N          parallelism for the rustc bootstrap (default: nproc)
#
# The rustc build downloads a prebuilt LLVM (download-ci-llvm), so no LLVM
# source build happens. bpf-linker needs LLVM 22 development libraries:
#   macOS:          brew install llvm@22
#   Debian/Ubuntu:  apt install llvm-22-dev libpolly-22-dev   (apt.llvm.org)
# Override the prefix with LLVM_SYS_221_PREFIX if it is somewhere else.

set -euo pipefail

# --- pins (keep in sync with docs/ebpf-toolchain.md) -------------------------
RUST_REPO="https://github.com/vadorovsky/rust.git"
RUST_COMMIT="26afb49e7af"          # branch btf-relocations; #[relocatable] spelling
LINKER_REPO="https://github.com/aya-rs/bpf-linker.git"
LINKER_COMMIT="a08a2f5"            # v0.10.3 + 6
LLVM_MAJOR=22

WORK="${HOME}/.hop-tap-toolchain"
TOOLCHAIN="stage1-vlad"
DO_RUSTC=1
DO_LINKER=1
JOBS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --toolchain) TOOLCHAIN="$2"; shift 2 ;;
    --skip-rustc) DO_RUSTC=0; shift ;;
    --skip-linker) DO_LINKER=0; shift ;;
    --jobs) JOBS="$2"; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required" >&2; exit 1; }; }
need git; need rustup; need cargo; need python3; need curl

HOST="$(rustc -vV | sed -n 's/^host: //p')"
case "$HOST" in
  x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|aarch64-apple-darwin|x86_64-apple-darwin) ;;
  *) echo "error: unsupported host '$HOST' (download-ci-llvm has no build for it)" >&2; exit 1 ;;
esac

mkdir -p "$WORK"

# --- rustc fork ---------------------------------------------------------------
if [[ $DO_RUSTC -eq 1 ]]; then
  RUST_DIR="$WORK/rust"
  echo "==> rustc fork: $RUST_REPO @ $RUST_COMMIT -> $RUST_DIR"
  if [[ ! -d "$RUST_DIR/.git" ]]; then
    git clone --filter=blob:none "$RUST_REPO" "$RUST_DIR"
  fi
  git -C "$RUST_DIR" fetch -q origin "$RUST_COMMIT" 2>/dev/null || git -C "$RUST_DIR" fetch -q origin
  git -C "$RUST_DIR" checkout -q "$RUST_COMMIT"

  cat > "$RUST_DIR/bootstrap.toml" <<TOML
# Written by scripts/build-ebpf-toolchain.sh. "compiler" profile:
# download-ci-llvm = true, download-rustc = false, incremental = true.
profile = "compiler"

[build]
docs = false
compiler-docs = false
${JOBS:+jobs = $JOBS}
TOML

  echo "==> ./x build --stage 1 library  (this takes a while)"
  ( cd "$RUST_DIR" && ./x build --stage 1 library )

  SYSROOT="$RUST_DIR/build/$HOST/stage1"
  [[ -x "$SYSROOT/bin/rustc" ]] || { echo "error: no rustc at $SYSROOT/bin" >&2; exit 1; }
  [[ -d "$SYSROOT/lib/rustlib/src/rust/library" ]] \
    || { echo "error: stage1 sysroot lacks library source (needed by -Z build-std)" >&2; exit 1; }

  rustup toolchain link "$TOOLCHAIN" "$SYSROOT"
  echo "==> registered rustup toolchain '$TOOLCHAIN':"
  rustc "+$TOOLCHAIN" -vV | sed -n 's/^\(release\|LLVM version\): /    \1: /p'
fi

# --- bpf-linker -----------------------------------------------------------------
if [[ $DO_LINKER -eq 1 ]]; then
  LINKER_DIR="$WORK/bpf-linker"
  echo "==> bpf-linker: $LINKER_REPO @ $LINKER_COMMIT -> $LINKER_DIR"
  if [[ ! -d "$LINKER_DIR/.git" ]]; then
    git clone "$LINKER_REPO" "$LINKER_DIR"
  fi
  git -C "$LINKER_DIR" fetch -q origin
  git -C "$LINKER_DIR" checkout -q "$LINKER_COMMIT"

  PREFIX_VAR="LLVM_SYS_${LLVM_MAJOR}1_PREFIX"
  if [[ -z "${!PREFIX_VAR:-}" ]]; then
    if command -v brew >/dev/null 2>&1 && brew --prefix "llvm@${LLVM_MAJOR}" >/dev/null 2>&1; then
      export "$PREFIX_VAR=$(brew --prefix "llvm@${LLVM_MAJOR}")"
    elif [[ -d "/usr/lib/llvm-${LLVM_MAJOR}" ]]; then
      export "$PREFIX_VAR=/usr/lib/llvm-${LLVM_MAJOR}"
    else
      echo "error: LLVM ${LLVM_MAJOR} not found; install it and/or set $PREFIX_VAR" >&2
      exit 1
    fi
  fi
  echo "    $PREFIX_VAR=${!PREFIX_VAR}"

  ( cd "$LINKER_DIR" && cargo install --path . --no-default-features \
      --features "llvm-${LLVM_MAJOR}" --locked )
  command -v bpf-linker >/dev/null || { echo "error: bpf-linker not on PATH after install (is ~/.cargo/bin on PATH?)" >&2; exit 1; }
  echo "==> $(bpf-linker --version) at $(command -v bpf-linker)"
fi

cat <<MSG

Done. Build the eBPF object with:

  cd crates/hop-tap-ebpf && cargo +$TOOLCHAIN build --release

or the whole workspace on Linux with plain 'cargo build --release'
(set HOP_TAP_BPF_TOOLCHAIN=$TOOLCHAIN if you used a non-default name).
MSG
