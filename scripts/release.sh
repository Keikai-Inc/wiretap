#!/usr/bin/env bash
#
# Full release script for hop-tap.
#
# Usage:
#   ./scripts/release.sh              # Release current version from Cargo.toml
#   ./scripts/release.sh 0.2.0        # Bump to 0.2.0, commit, tag, and release
#   ./scripts/release.sh --site-only  # (no site in this repo today; reserved)
#
# What it builds (Linux only — hop-tap is eBPF):
#   - hop-tap-d-linux-x86_64,  hop-tap-d-linux-arm64
#   - hop-tap-probe-linux-x86_64, hop-tap-probe-linux-arm64
#   + matching .sha256 files
#
# eBPF wrinkle: the kernel-side crate builds with vlad's stage1-vlad
# rustc + bpfel-unknown-none target. The output is BPF bytecode, host-
# arch-independent, so we build it ONCE on the release host and embed
# the same .bpf.o into every userspace cross-build via
# HOP_TAP_SKIP_EBPF_BUILD=1.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUCKET="${HOP_TAP_RELEASE_BUCKET:-hop-tap-releases}"
CF_DISTRIBUTION_ID="${HOP_TAP_CF_DISTRIBUTION_ID:-}"
DIST_DIR="${PROJECT_ROOT}/target/release-dist"

NEW_VERSION=""

# --- Parse arguments --------------------------------------------------------

for arg in "$@"; do
  case "${arg}" in
    --help|-h)
      echo "Usage: $0 [VERSION]"
      echo ""
      echo "  VERSION   Bump to this version before releasing (e.g. 0.2.0)"
      echo ""
      echo "Environment:"
      echo "  HOP_TAP_RELEASE_BUCKET     S3 bucket (default: hop-tap-releases)"
      echo "  HOP_TAP_CF_DISTRIBUTION_ID CloudFront distribution to invalidate"
      echo "  HOP_TAP_BPF_TOOLCHAIN      Rustc toolchain for eBPF build"
      echo "                             (default: stage1-vlad)"
      exit 0
      ;;
    *)
      if [[ "${arg}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        NEW_VERSION="${arg}"
      else
        echo "Error: Unknown argument '${arg}'"
        echo "Run '$0 --help' for usage."
        exit 1
      fi
      ;;
  esac
done

# --- Preflight --------------------------------------------------------------

check_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: '$1' is not installed."
    exit 1
  fi
}

echo "==> Checking prerequisites"
check_cmd cargo
check_cmd cross
check_cmd aws
check_cmd docker
check_cmd strip
check_cmd shasum

if ! docker info >/dev/null 2>&1; then
  echo "Error: Docker is not running."
  exit 1
fi

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "Error: AWS credentials not configured."
  exit 1
fi

# Verify the eBPF toolchain is available — the eBPF crate cannot build
# without it, and there's no reasonable fallback at release time.
TOOLCHAIN="${HOP_TAP_BPF_TOOLCHAIN:-stage1-vlad}"
if ! rustup toolchain list 2>/dev/null | grep -q "^${TOOLCHAIN}\b"; then
  echo "Error: rustup toolchain '${TOOLCHAIN}' is not installed."
  echo "  This release requires vlad's stage1 rustc fork (or set"
  echo "  HOP_TAP_BPF_TOOLCHAIN to a toolchain that supports"
  echo "  #[relocatable])."
  exit 1
fi

# --- Version bump (optional) ------------------------------------------------

if [[ -n "${NEW_VERSION}" ]]; then
  echo "==> Bumping workspace version to ${NEW_VERSION}"
  # GNU sed vs BSD sed: -i '' on macOS, -i'' on Linux. Pick at runtime.
  if [[ "$(uname -s)" == "Darwin" ]]; then
    sed -i '' "s/^version = \".*\"/version = \"${NEW_VERSION}\"/" "${PROJECT_ROOT}/Cargo.toml"
  else
    sed -i "s/^version = \".*\"/version = \"${NEW_VERSION}\"/" "${PROJECT_ROOT}/Cargo.toml"
  fi
  VERIFY=$(grep -m1 '^version' "${PROJECT_ROOT}/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
  if [[ "${VERIFY}" != "${NEW_VERSION}" ]]; then
    echo "Error: Version bump failed (got '${VERIFY}', expected '${NEW_VERSION}')"
    exit 1
  fi
  echo "==> Committing version bump"
  git -C "${PROJECT_ROOT}" add Cargo.toml
  git -C "${PROJECT_ROOT}" commit -m "Bump version to ${NEW_VERSION}"
fi

VERSION=$(grep -m1 '^version' "${PROJECT_ROOT}/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')
echo ""
echo "============================================"
echo "  Releasing hop-tap v${VERSION}"
echo "============================================"
echo ""

# --- Tests -----------------------------------------------------------------

echo "==> Running userspace tests"
HOP_TAP_SKIP_EBPF_BUILD=1 cargo test --quiet --workspace

# --- Build the eBPF object once --------------------------------------------
#
# BPF bytecode is host-arch-independent, so we build it once with the
# special toolchain and embed it into every userspace cross-build.

echo "==> Building eBPF object with ${TOOLCHAIN}"
( cd "${PROJECT_ROOT}/crates/hop-tap-ebpf" && cargo "+${TOOLCHAIN}" build --release )
EBPF_OUT="${PROJECT_ROOT}/crates/hop-tap-ebpf/target/bpfel-unknown-none/release/hop-tap-ebpf"
if [[ ! -f "${EBPF_OUT}" ]]; then
  echo "Error: eBPF build produced no artifact at ${EBPF_OUT}"
  exit 1
fi
echo "    eBPF object: $(ls -lh "${EBPF_OUT}" | awk '{print $5, $9}')"

# --- Userspace cross-builds -------------------------------------------------

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

BUILD_LOG_DIR=$(mktemp -d)
BUILD_PIDS=()
start_build() {
  local label="$1"; shift
  local logfile="${BUILD_LOG_DIR}/${label}.log"
  echo "==> Starting: ${label}"
  ("$@") > "${logfile}" 2>&1 &
  BUILD_PIDS+=("$!:${label}:${logfile}")
}

# Linux aarch64: native arm64 Docker build (no QEMU emulation).
# Reuses the cross images hop already has if present (hop-cross-aarch64-musl);
# falls back to the public cross image otherwise.
ARM64_IMAGE="${HOP_TAP_ARM64_IMAGE:-ghcr.io/cross-rs/aarch64-unknown-linux-musl:main}"
start_build "hop-tap-linux-arm64" bash -c "
  docker run --rm \
    -e HOP_TAP_SKIP_EBPF_BUILD=1 \
    -v '${PROJECT_ROOT}:/build' \
    -v '${HOME}/.cargo/registry:/usr/local/cargo/registry' \
    -v '${HOME}/.cargo/git:/usr/local/cargo/git' \
    '${ARM64_IMAGE}' \
    cargo build --release --target aarch64-unknown-linux-musl \
      --manifest-path /build/Cargo.toml -p hop-tap-d --bins \
  && cp '${PROJECT_ROOT}/target/aarch64-unknown-linux-musl/release/hop-tap-d'     '${DIST_DIR}/hop-tap-d-linux-arm64' \
  && cp '${PROJECT_ROOT}/target/aarch64-unknown-linux-musl/release/hop-tap-probe' '${DIST_DIR}/hop-tap-probe-linux-arm64'
"

# Linux x86_64: cross under QEMU
start_build "hop-tap-linux-x86_64" bash -c "
  HOP_TAP_SKIP_EBPF_BUILD=1 cross build --release --target x86_64-unknown-linux-musl \
    --manifest-path '${PROJECT_ROOT}/Cargo.toml' -p hop-tap-d --bins \
  && cp '${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/release/hop-tap-d'     '${DIST_DIR}/hop-tap-d-linux-x86_64' \
  && cp '${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/release/hop-tap-probe' '${DIST_DIR}/hop-tap-probe-linux-x86_64'
"

# Wait for builds
echo "==> Waiting for builds to complete..."
FAILED=0
for entry in "${BUILD_PIDS[@]}"; do
  IFS=':' read -r pid label logfile <<< "${entry}"
  if wait "${pid}"; then
    echo "  ✓ ${label}"
  else
    echo "  ✗ ${label} FAILED (see ${logfile})"
    tail -30 "${logfile}"
    FAILED=1
  fi
done
[[ "${FAILED}" -eq 0 ]] || { echo "Error: build(s) failed"; exit 1; }
rm -rf "${BUILD_LOG_DIR}"

# Strip
echo "==> Stripping binaries"
for f in "${DIST_DIR}"/hop-tap-*; do
  # Note: strip on a foreign-arch binary needs llvm-strip or the
  # cross binutils. The release host typically has llvm-strip via
  # llvm-tools; if it's missing we just skip strip (binaries are
  # bigger but still functional).
  if command -v llvm-strip >/dev/null 2>&1; then
    llvm-strip "${f}" || true
  fi
done

# --- Checksums --------------------------------------------------------------

echo "==> Generating checksums"
cd "${DIST_DIR}"
for f in hop-tap-*; do
  shasum -a 256 "${f}" | awk '{print $1}' > "${f}.sha256"
done
cd "${PROJECT_ROOT}"

# --- Upload to S3 -----------------------------------------------------------

echo "==> Uploading binaries to s3://${BUCKET}/v${VERSION}/"
aws s3 cp "${DIST_DIR}/" "s3://${BUCKET}/v${VERSION}/" \
  --recursive --exclude '*' --include 'hop-tap-*'

echo "==> Uploading latest version marker"
echo -n "${VERSION}" > "${DIST_DIR}/latest"
aws s3 cp "${DIST_DIR}/latest" "s3://${BUCKET}/latest" \
  --content-type "text/plain"

echo "==> Uploading install.sh + service unit"
aws s3 cp "${PROJECT_ROOT}/install.sh" "s3://${BUCKET}/install.sh" \
  --content-type "text/plain"
aws s3 cp "${PROJECT_ROOT}/hop-tap.service" "s3://${BUCKET}/hop-tap.service" \
  --content-type "text/plain"

# --- Git tag ----------------------------------------------------------------

echo "==> Tagging v${VERSION}"
if git -C "${PROJECT_ROOT}" rev-parse "v${VERSION}" >/dev/null 2>&1; then
  echo "    Tag v${VERSION} already exists, skipping"
else
  git -C "${PROJECT_ROOT}" tag "v${VERSION}"
fi

echo "==> Pushing to origin (with tags)"
git -C "${PROJECT_ROOT}" push
git -C "${PROJECT_ROOT}" push --tags

# --- CloudFront invalidation -----------------------------------------------

if [[ -n "${CF_DISTRIBUTION_ID}" ]]; then
  echo "==> Invalidating CloudFront cache"
  aws cloudfront create-invalidation \
    --distribution-id "${CF_DISTRIBUTION_ID}" \
    --paths "/" "/latest" "/install.sh" "/hop-tap.service" "/v${VERSION}/*" \
    --output text --query 'Invalidation.Id'
else
  echo "==> Skipping CloudFront invalidation (HOP_TAP_CF_DISTRIBUTION_ID not set)"
fi

# --- Done -------------------------------------------------------------------

echo ""
echo "============================================"
echo "  Released hop-tap v${VERSION}"
echo "============================================"
echo ""
echo "Binaries:"
ls -lh "${DIST_DIR}"/hop-tap-* | grep -v sha256
echo ""
echo "Install: curl -fsSL https://hop-tap.keik.ai/install.sh | bash"
