#!/usr/bin/env bash
# Installer for hop-tap (the terminal-capture extension for hop).
#
# Usage:
#   curl -fsSL https://tap.keikai.ai/install.sh | bash
#   curl -fsSL https://tap.keikai.ai/install.sh | bash -s -- --version 0.1.0
#
# Behavior:
#   - Linux-only (eBPF). On macOS/other this exits with a clear error.
#   - If `hop` is not installed (or its daemon isn't running), this
#     script first delegates to `https://hop.keikai.ai/install-daemon.sh`
#     to bring up hop, then continues.
#   - Downloads the hop-tap-d daemon and tap binaries to
#     /usr/local/bin, drops a manifest at /etc/hop/extensions/tap-terminal.toml,
#     installs a systemd unit, and starts the service.
#   - Restarts hop afterwards so it picks up the new manifest.
#
# After install, the operator can:
#   hop <host> tap list             # active sessions, with owner attribution
#   hop <host> tap snapshot <pty>   # current screen
#   hop <host> tap watch <pty>      # live byte stream
#
# (or `tap` directly on the host for local development).

set -euo pipefail

BASE_URL="${HOP_TAP_CDN_URL:-https://tap.keikai.ai}"
# Release-signing public key. Empty => checksum-only (current). When signed
# releases begin, embed the WireHop release pubkey here and installs become
# fail-closed (a missing/bad .sig aborts). Override for testing with HOP_TAP_PUBKEY.
HOP_TAP_PUBKEY="${HOP_TAP_PUBKEY:-}"
HOP_BASE_URL="${HOP_CDN_URL:-https://hop.keikai.ai}"

# --- Colour helpers (disabled when piped) ------------------------------------

if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
  BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''
fi

info()  { printf "${GREEN}info${RESET}  %s\n" "$*"; }
warn()  { printf "${YELLOW}warn${RESET}  %s\n" "$*"; }
error() { printf "${RED}error${RESET} %s\n" "$*" >&2; }
die()   { error "$@"; exit 1; }

TMPDIR_HOPTAP=$(mktemp -d)
trap 'rm -rf "${TMPDIR_HOPTAP}"' EXIT

# --- Parse arguments ---------------------------------------------------------

VERSION=""
SKIP_RESTART=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)        VERSION="$2"; shift 2 ;;
    --skip-restart)   SKIP_RESTART=true; shift ;;
    *)                die "Unknown option: $1" ;;
  esac
done

# --- HTTP helpers ------------------------------------------------------------

fetch() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "${dest}" "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${dest}" "${url}"
  else
    die "Neither curl nor wget found. Please install one and retry."
  fi
}

fetch_text() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${url}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- "${url}"
  else
    die "Neither curl nor wget found."
  fi
}

# --- Platform check ----------------------------------------------------------

OS=$(uname -s)
ARCH=$(uname -m)

if [[ "${OS}" != "Linux" ]]; then
  die "hop-tap is Linux-only (it uses eBPF). Detected: ${OS}.
On macOS/Windows you can still use \`hop <linux-host> tap ...\` to view
sessions on a Linux host that has hop-tap installed."
fi

case "${ARCH}" in
  x86_64|amd64)  ARCH="x86_64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)             die "Unsupported architecture: ${ARCH}. hop-tap currently ships x86_64 and arm64 binaries." ;;
esac

info "Detected platform: linux-${ARCH}"

# --- Resolve version ---------------------------------------------------------

if [[ -z "${VERSION}" ]]; then
  info "Fetching latest hop-tap version..."
  VERSION=$(fetch_text "${BASE_URL}/latest")
fi
[[ -n "${VERSION}" ]] || die "Could not determine version"
info "Installing hop-tap v${VERSION}"

# --- Detect hop integration ---------------------------------------------------
#
# hop-tap can run two ways:
#
#   1. Standalone — hop-tap-d + tap locally on the host, no hop.
#      List / snapshot / watch sessions through `tap`. No remote
#      access, no peer auth — the only authorization is "you can read
#      /run/hop-tap/bootstrap" (root-owned, mode 0600).
#
#   2. hop-integrated — same daemon, plus a manifest registered with the
#      hop daemon so peers on the hop network can run `hop <host> tap ...`.
#      Adds remote QUIC-authenticated access on top of #1.
#
# We always install the daemon. We register the manifest only when hop is
# present and running. We never auto-install hop, never auto-start hop —
# that's the user's call (run hop's own installer if they want it).

HOP_INTEGRATION="standalone"   # set to "registered" if we drop the manifest
if command -v hop >/dev/null 2>&1; then
  if systemctl is-active --quiet hop 2>/dev/null; then
    HOP_INTEGRATION="registered"
    info "hop daemon detected — will register hop-tap as an extension"
  else
    warn "hop is installed but the daemon isn't running."
    warn "Installing hop-tap in standalone mode. Start hop and re-run this"
    warn "installer to register hop-tap with the hop network."
  fi
else
  info "hop is not installed — installing hop-tap in standalone mode."
  info "Use tap directly on this host. To enable remote access,"
  info "install hop (curl -fsSL ${HOP_BASE_URL}/install-daemon.sh | bash)"
  info "and re-run this installer."
fi

# --- Download daemon + probe binaries + checksums ---------------------------

DAEMON_NAME="hop-tap-d-linux-${ARCH}"
TAP_NAME="tap-linux-${ARCH}"
HONEYPOT_NAME="tap-honeypot-linux-${ARCH}"
DAEMON_URL="${BASE_URL}/v${VERSION}/${DAEMON_NAME}"
TAP_URL="${BASE_URL}/v${VERSION}/${TAP_NAME}"
HONEYPOT_URL="${BASE_URL}/v${VERSION}/${HONEYPOT_NAME}"

info "Downloading hop-tap-d..."
fetch "${DAEMON_URL}" "${TMPDIR_HOPTAP}/hop-tap-d"
fetch "${DAEMON_URL}.sha256" "${TMPDIR_HOPTAP}/hop-tap-d.sha256"

info "Downloading tap..."
fetch "${TAP_URL}" "${TMPDIR_HOPTAP}/tap"
fetch "${TAP_URL}.sha256" "${TMPDIR_HOPTAP}/tap.sha256"

info "Downloading tap-honeypot (Phase 2 sandbox tester)..."
fetch "${HONEYPOT_URL}" "${TMPDIR_HOPTAP}/tap-honeypot"
fetch "${HONEYPOT_URL}.sha256" "${TMPDIR_HOPTAP}/tap-honeypot.sha256"

# --- Verify checksums --------------------------------------------------------

verify_sha256() {
  local file="$1" sumfile="$2"
  local expected actual
  expected=$(cat "${sumfile}" | tr -d '[:space:]')
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${file}" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "${file}" | awk '{print $1}')
  else
    warn "No sha256sum or shasum found — skipping checksum verification"
    return 0
  fi
  [[ "${actual}" == "${expected}" ]] || die "Checksum mismatch for ${file}!
  expected: ${expected}
  got:      ${actual}"
}

info "Verifying checksums..."
verify_sha256 "${TMPDIR_HOPTAP}/hop-tap-d" "${TMPDIR_HOPTAP}/hop-tap-d.sha256"
verify_sha256 "${TMPDIR_HOPTAP}/tap" "${TMPDIR_HOPTAP}/tap.sha256"
verify_sha256 "${TMPDIR_HOPTAP}/tap-honeypot" "${TMPDIR_HOPTAP}/tap-honeypot.sha256"

# --- Verify signatures (when a pubkey is embedded) --------------------------
# Checksums prove integrity, not provenance: a compromised CDN could serve a
# matching binary+checksum. When HOP_TAP_PUBKEY is embedded, require a valid
# detached openssl signature over each binary and fail closed. Empty => skipped.
verify_sig() {
  local file="$1" url="$2" name="$3"
  [[ -n "${HOP_TAP_PUBKEY}" ]] || return 0
  command -v openssl >/dev/null 2>&1 || die "Signature verification needs openssl, which was not found."
  if ! fetch "${url}.sig" "${file}.sig" 2>/dev/null; then
    die "Signed releases expected, but no signature found for ${name}. Aborting."
  fi
  printf '%s\n' "${HOP_TAP_PUBKEY}" > "${TMPDIR_HOPTAP}/pub.pem"
  openssl dgst -sha256 -verify "${TMPDIR_HOPTAP}/pub.pem" \
      -signature "${file}.sig" "${file}" >/dev/null 2>&1 \
    || die "Signature verification FAILED for ${name}. Refusing to install."
}
if [[ -n "${HOP_TAP_PUBKEY}" ]]; then
  info "Verifying signatures..."
  verify_sig "${TMPDIR_HOPTAP}/hop-tap-d" "${DAEMON_URL}" "hop-tap-d"
  verify_sig "${TMPDIR_HOPTAP}/tap" "${TAP_URL}" "tap"
  verify_sig "${TMPDIR_HOPTAP}/tap-honeypot" "${HONEYPOT_URL}" "tap-honeypot"
  info "Signatures verified."
fi

# --- Install binaries --------------------------------------------------------
#
# `hop-tap-d` is the daemon (started by systemd, runs as root for
# eBPF). `tap` is the user-facing CLI; SO_PEERCRED on the daemon's
# local socket authenticates the caller.

chmod +x "${TMPDIR_HOPTAP}/hop-tap-d" "${TMPDIR_HOPTAP}/tap" "${TMPDIR_HOPTAP}/tap-honeypot"
info "Installing hop-tap-d, tap, and tap-honeypot to /usr/local/bin (sudo required)..."
sudo mv "${TMPDIR_HOPTAP}/hop-tap-d" /usr/local/bin/hop-tap-d
sudo mv "${TMPDIR_HOPTAP}/tap" /usr/local/bin/tap
sudo mv "${TMPDIR_HOPTAP}/tap-honeypot" /usr/local/bin/tap-honeypot

# --- Drop the extension manifest (only if hop is around) --------------------
#
# hop-tap-d runs as root (eBPF) so expected_uid=0 lines up with the
# User= in hop-tap.service. The hop daemon refuses to trust the bootstrap
# file unless its file owner matches this UID.
#
# In standalone mode we skip this — there's no hop to register against,
# and dropping a stale manifest in /etc/hop/extensions/ would mislead
# any future hop install.

if [[ "${HOP_INTEGRATION}" == "registered" ]]; then
  info "Installing extension manifest at /etc/hop/extensions/tap-terminal.toml..."
  sudo mkdir -p /etc/hop/extensions
  sudo tee /etc/hop/extensions/tap-terminal.toml >/dev/null <<'EOF'
# hop-tap extension manifest, installed by install.sh.
ext_id         = "tap.terminal"
description    = "Terminal session capture via eBPF"
bootstrap_path = "/run/hop-tap/bootstrap"
expected_uid   = 0
version        = "0.1.0"
required_role  = "creator"
EOF
  sudo chown root:hop /etc/hop/extensions/tap-terminal.toml 2>/dev/null || true
  sudo chmod 0640 /etc/hop/extensions/tap-terminal.toml
fi

# --- Install systemd unit ----------------------------------------------------

# /etc/hop is referenced by the unit's ReadWritePaths so namespace
# setup can succeed even when hop isn't installed. The unit uses a
# `-` prefix to tolerate it being absent, but older copies of the
# unit may already be installed on a re-run; create it
# unconditionally to keep both new and old units happy.
sudo mkdir -p /etc/hop

info "Installing systemd unit hop-tap.service..."
fetch "${BASE_URL}/hop-tap.service" "${TMPDIR_HOPTAP}/hop-tap.service"
sudo mv "${TMPDIR_HOPTAP}/hop-tap.service" /etc/systemd/system/hop-tap.service
sudo systemctl daemon-reload

# --- Start hop-tap-d ---------------------------------------------------------

info "Enabling and starting hop-tap-d..."
if systemctl is-active --quiet hop-tap 2>/dev/null; then
  sudo systemctl restart hop-tap
  info "hop-tap restarted."
else
  sudo systemctl enable --now hop-tap
fi

# Give the bootstrap file a moment to land before nudging hop.
for _ in $(seq 1 20); do
  [[ -f /run/hop-tap/bootstrap ]] && break
  sleep 0.1
done

if [[ ! -f /run/hop-tap/bootstrap ]]; then
  warn "/run/hop-tap/bootstrap didn't appear — check 'sudo journalctl -u hop-tap'"
fi

# --- Restart hop so it picks up the manifest (only in registered mode) ------

if [[ "${HOP_INTEGRATION}" == "registered" && "${SKIP_RESTART}" == "false" ]]; then
  info "Restarting hop daemon to pick up the new manifest..."
  if sudo systemctl restart hop 2>/dev/null; then
    info "hop restarted."
  else
    warn "Could not restart hop (try: sudo systemctl restart hop)"
  fi
fi

# --- Done --------------------------------------------------------------------

printf "\n${BOLD}hop-tap v${VERSION}${RESET} installed (mode: ${HOP_INTEGRATION}).\n\n"

if [[ "${HOP_INTEGRATION}" == "registered" ]]; then
  printf "Remote access (from any hop peer):\n"
  printf "  ${BOLD}hop <host> ext list${RESET}              # tap.terminal listed as available\n"
  printf "  ${BOLD}hop <host> tap list${RESET}              # active sessions\n"
  printf "  ${BOLD}hop <host> tap snapshot <pty>${RESET}    # current screen\n"
  printf "  ${BOLD}hop <host> tap watch <pty>${RESET}       # live byte stream\n\n"
fi

printf "Local access:\n"
printf "  ${BOLD}tap list${RESET}                          # sessions you can see\n"
printf "  ${BOLD}tap snapshot <pty>${RESET}                # current screen\n"
printf "  ${BOLD}tap watch <pty>${RESET}                   # live byte stream\n"
printf "  ${BOLD}tap repl${RESET}                          # interactive REPL\n\n"
printf "  Permission model: root sees every session; non-root users\n"
printf "  see only sessions opened by themselves. Authenticated by\n"
printf "  SO_PEERCRED on the daemon's local socket (no claims trusted).\n\n"

printf "Service control: ${BOLD}sudo systemctl status hop-tap${RESET}\n"
printf "Logs:            ${BOLD}sudo journalctl -u hop-tap -f${RESET}\n"

if [[ "${HOP_INTEGRATION}" == "standalone" ]]; then
  printf "\n${YELLOW}Standalone mode:${RESET} hop is not installed or not running on this host.\n"
  printf "To enable ${BOLD}hop <host> tap ...${RESET} from remote peers:\n"
  printf "  curl -fsSL ${HOP_BASE_URL}/install-daemon.sh | bash\n"
  printf "  curl -fsSL ${BASE_URL}/install.sh | bash    # re-run, will register\n"
fi
