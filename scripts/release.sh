#!/usr/bin/env bash
#
# Full release script for hop-tap.
#
# Usage:
#   ./scripts/release.sh              # Release current version from Cargo.toml
#   ./scripts/release.sh 0.2.0        # Bump to 0.2.0, commit, tag, and release
#   ./scripts/release.sh --site       # Upload site/ + install.sh only (no build)
#
# What it builds (Linux only — hop-tap is eBPF):
#   - hop-tap-d-linux-x86_64,  hop-tap-d-linux-arm64
#   - tap-linux-x86_64, tap-linux-arm64
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
SITE_ONLY=0

# --- Parse arguments --------------------------------------------------------

for arg in "$@"; do
  case "${arg}" in
    --help|-h)
      echo "Usage: $0 [VERSION] [--site]"
      echo ""
      echo "  VERSION   Bump to this version before releasing (e.g. 0.2.0)"
      echo "  --site    Upload site/ + install.sh only (skip build, tag, push)"
      echo ""
      echo "Environment:"
      echo "  HOP_TAP_RELEASE_BUCKET     S3 bucket (default: hop-tap-releases)"
      echo "  HOP_TAP_CF_DISTRIBUTION_ID CloudFront distribution to invalidate"
      echo "  HOP_TAP_BPF_TOOLCHAIN      Rustc toolchain for eBPF build"
      echo "                             (default: stage1-vlad)"
      exit 0
      ;;
    --site|--site-only)
      SITE_ONLY=1
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

# --- Site upload helper -----------------------------------------------------
#
# Uploads site/*.html, *.css, *.js, icons, and install.sh with appropriate
# Content-Type and Cache-Control. HTML/CSS/JS get a short cache (5 min) so
# updates roll out fast; icons get 30 days. Used by both --site mode and
# the normal full release.

upload_site() {
  local site_dir="${PROJECT_ROOT}/site"
  if [[ ! -d "${site_dir}" ]]; then
    echo "==> No site/ directory, skipping site upload"
    return 0
  fi

  echo "==> Uploading site files to s3://${BUCKET}/"

  local short_cache="public, max-age=300"
  local long_cache="public, max-age=2592000"

  for f in "${site_dir}"/*.html; do
    [[ -e "$f" ]] || continue
    aws s3 cp "$f" "s3://${BUCKET}/$(basename "$f")" \
      --content-type "text/html; charset=utf-8" \
      --cache-control "${short_cache}"
  done

  for f in "${site_dir}"/*.css; do
    [[ -e "$f" ]] || continue
    aws s3 cp "$f" "s3://${BUCKET}/$(basename "$f")" \
      --content-type "text/css; charset=utf-8" \
      --cache-control "${short_cache}"
  done

  for f in "${site_dir}"/*.js; do
    [[ -e "$f" ]] || continue
    aws s3 cp "$f" "s3://${BUCKET}/$(basename "$f")" \
      --content-type "application/javascript; charset=utf-8" \
      --cache-control "${short_cache}"
  done

  for f in "${site_dir}"/*.png; do
    [[ -e "$f" ]] || continue
    aws s3 cp "$f" "s3://${BUCKET}/$(basename "$f")" \
      --content-type "image/png" \
      --cache-control "${long_cache}"
  done

  for f in "${site_dir}"/*.ico; do
    [[ -e "$f" ]] || continue
    aws s3 cp "$f" "s3://${BUCKET}/$(basename "$f")" \
      --content-type "image/x-icon" \
      --cache-control "${long_cache}"
  done

  # asciinema cast recordings — JSON-lines format, Content-Type per
  # the asciicast v2 spec.
  for f in "${site_dir}"/*.cast; do
    [[ -e "$f" ]] || continue
    aws s3 cp "$f" "s3://${BUCKET}/$(basename "$f")" \
      --content-type "application/x-asciicast" \
      --cache-control "${short_cache}"
  done

  if [[ -f "${PROJECT_ROOT}/install.sh" ]]; then
    aws s3 cp "${PROJECT_ROOT}/install.sh" "s3://${BUCKET}/install.sh" \
      --content-type "text/x-shellscript; charset=utf-8" \
      --cache-control "${short_cache}"
  fi
}

invalidate_site_paths() {
  if [[ -z "${CF_DISTRIBUTION_ID}" ]]; then
    echo "==> Skipping CloudFront invalidation (HOP_TAP_CF_DISTRIBUTION_ID not set)"
    return 0
  fi
  echo "==> Invalidating CloudFront site paths"
  aws cloudfront create-invalidation \
    --distribution-id "${CF_DISTRIBUTION_ID}" \
    --paths "/" "/index.html" "/remote.html" "/shared.css" "/shared.js" "/install.sh" \
    --output text --query 'Invalidation.Id'
}

if [[ "${SITE_ONLY}" -eq 1 ]]; then
  echo "==> Site-only mode (skipping build/tag/push)"
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "Error: AWS credentials not configured."
    exit 1
  fi
  upload_site
  invalidate_site_paths
  echo ""
  echo "Site updated: https://tap.keik.ai/"
  exit 0
fi

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

# Both Linux targets use the `cross` wrapper. Direct `docker run`
# bypasses cross-rs's image entrypoint and loses cargo from PATH.
#
# CROSS_CONTAINER_OPTS injects HOP_TAP_SKIP_EBPF_BUILD=1 into the
# container's environment. Without it the eBPF build.rs runs *inside*
# the cross container and can't find vlad's stage1 toolchain — the
# cross image is a generic musl image, not a Rust nightly host.
# We've already produced the `.bpf.o` on the host above and embedded
# it via include_bytes_aligned!; we just need to tell the userspace
# build to skip re-doing it.
#
# On Apple Silicon hosts cross runs the aarch64 image natively; the
# x86_64 image is QEMU-emulated.
CROSS_ENV='-e HOP_TAP_SKIP_EBPF_BUILD=1'

start_build "hop-tap-linux-arm64" bash -c "
  CROSS_CONTAINER_OPTS='${CROSS_ENV}' \
  HOP_TAP_SKIP_EBPF_BUILD=1 cross build --release --target aarch64-unknown-linux-musl \
    --manifest-path '${PROJECT_ROOT}/Cargo.toml' -p hop-tap-d --bins \
  && cp '${PROJECT_ROOT}/target/aarch64-unknown-linux-musl/release/hop-tap-d' '${DIST_DIR}/hop-tap-d-linux-arm64' \
  && cp '${PROJECT_ROOT}/target/aarch64-unknown-linux-musl/release/tap' '${DIST_DIR}/tap-linux-arm64'
"

start_build "hop-tap-linux-x86_64" bash -c "
  CROSS_CONTAINER_OPTS='${CROSS_ENV}' \
  HOP_TAP_SKIP_EBPF_BUILD=1 cross build --release --target x86_64-unknown-linux-musl \
    --manifest-path '${PROJECT_ROOT}/Cargo.toml' -p hop-tap-d --bins \
  && cp '${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/release/hop-tap-d' '${DIST_DIR}/hop-tap-d-linux-x86_64' \
  && cp '${PROJECT_ROOT}/target/x86_64-unknown-linux-musl/release/tap' '${DIST_DIR}/tap-linux-x86_64'
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

# Both binary names get stripped, summed, and uploaded:
#   hop-tap-d-linux-{x86_64,arm64}   (the daemon)
#   tap-linux-{x86_64,arm64}         (the local CLI)
# An earlier version of this script only matched `hop-tap-*` and
# silently skipped the `tap-*` binaries, leaving install.sh with
# 403s in production.
shopt -s nullglob
RELEASE_BINS=("${DIST_DIR}"/hop-tap-d-linux-* "${DIST_DIR}"/tap-linux-*)
shopt -u nullglob

echo "==> Stripping binaries"
for f in "${RELEASE_BINS[@]}"; do
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
for f in "${RELEASE_BINS[@]}"; do
  shasum -a 256 "${f}" | awk '{print $1}' > "${f}.sha256"
done

# --- Upload to S3 -----------------------------------------------------------

echo "==> Uploading binaries to s3://${BUCKET}/v${VERSION}/"
for f in "${RELEASE_BINS[@]}"; do
  aws s3 cp "${f}"          "s3://${BUCKET}/v${VERSION}/$(basename "${f}")"
  aws s3 cp "${f}.sha256"   "s3://${BUCKET}/v${VERSION}/$(basename "${f}").sha256"
done

echo "==> Uploading latest version marker"
echo -n "${VERSION}" > "${DIST_DIR}/latest"
aws s3 cp "${DIST_DIR}/latest" "s3://${BUCKET}/latest" \
  --content-type "text/plain"

echo "==> Uploading service unit"
aws s3 cp "${PROJECT_ROOT}/hop-tap.service" "s3://${BUCKET}/hop-tap.service" \
  --content-type "text/plain"

# Site files + install.sh use the shared helper (correct content-types + caching).
upload_site

# --- Git tag ----------------------------------------------------------------

echo "==> Tagging v${VERSION}"
if git -C "${PROJECT_ROOT}" rev-parse "v${VERSION}" >/dev/null 2>&1; then
  echo "    Tag v${VERSION} already exists, skipping"
else
  git -C "${PROJECT_ROOT}" tag "v${VERSION}"
fi

# Skip the push if no `origin` remote is configured. Useful for
# release hosts that publish artifacts but keep source local; the
# tag still lives in the local repo and can be pushed later.
if git -C "${PROJECT_ROOT}" remote get-url origin >/dev/null 2>&1; then
  echo "==> Pushing to origin (with tags)"
  git -C "${PROJECT_ROOT}" push
  git -C "${PROJECT_ROOT}" push --tags
else
  echo "==> Skipping git push (no 'origin' remote configured)"
fi

# --- CloudFront invalidation -----------------------------------------------

if [[ -n "${CF_DISTRIBUTION_ID}" ]]; then
  echo "==> Invalidating CloudFront cache"
  aws cloudfront create-invalidation \
    --distribution-id "${CF_DISTRIBUTION_ID}" \
    --paths "/" "/index.html" "/remote.html" "/shared.css" "/shared.js" \
            "/latest" "/install.sh" "/hop-tap.service" "/v${VERSION}/*" \
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
echo "Install: curl -fsSL https://tap.keik.ai/install.sh | bash"
