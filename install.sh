#!/usr/bin/env bash
# Installer for hop-tap (the terminal-capture extension for hop).
#
# Usage:
#   curl -fsSL https://hop-tap.keik.ai/install.sh | bash
#   curl -fsSL https://hop-tap.keik.ai/install.sh | bash -s -- --version 0.1.0
#
# Behavior:
#   - Linux-only (eBPF). On macOS/other this exits with a clear error.
#   - If `hop` is not installed (or its daemon isn't running), this
#     script first delegates to `https://hop.keik.ai/install-daemon.sh`
#     to bring up hop, then continues.
#   - Downloads the hop-tap-d daemon and hop-tap-probe binaries to
#     /usr/local/bin, drops a manifest at /etc/hop/extensions/tap-terminal.toml,
#     installs a systemd unit, and starts the service.
#   - Restarts hop afterwards so it picks up the new manifest.
#
# After install, the operator can:
#   hop <host> tap list             # active sessions, with owner attribution
#   hop <host> tap snapshot <pty>   # current screen
#   hop <host> tap watch <pty>      # live byte stream
#
# (or `hop-tap-probe` directly on the host for local development).

set -euo pipefail

BASE_URL="${HOP_TAP_CDN_URL:-https://hop-tap.keik.ai}"
HOP_BASE_URL="${HOP_CDN_URL:-https://hop.keik.ai}"

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

# --- Make sure hop is installed and running ---------------------------------
#
# hop-tap is a hop extension. Without hop running there's nothing for the
# manifest to register against.
#
# Two cases we handle:
#   1. hop binary missing entirely — delegate to hop's official daemon
#      installer (the only hop-related logic this script touches; we
#      deliberately do NOT duplicate any of it).
#   2. hop binary present but daemon not running — bail with a clear
#      message. There are too many ways a user can run hop (systemd,
#      tmux, user-local --dir install, custom service name) for us to
#      reliably "fix" this without potentially clobbering their setup.
#      They know their config; just tell them what we need.

ensure_hop_running() {
  if ! command -v hop >/dev/null 2>&1; then
    info "hop binary not found — installing hop daemon first..."
    if command -v curl >/dev/null 2>&1; then
      bash <(curl -fsSL "${HOP_BASE_URL}/install-daemon.sh")
    else
      bash <(wget -qO- "${HOP_BASE_URL}/install-daemon.sh")
    fi
    return
  fi

  if ! systemctl is-active --quiet hop 2>/dev/null; then
    die "hop is installed but the daemon isn't running.
Start it however you normally do (e.g. \`sudo systemctl start hop\` or
\`hop host\`) and re-run this installer. We deliberately don't try to
start hop ourselves to avoid clobbering manual / user-local /
non-systemd setups."
  fi

  info "hop daemon already running — registering hop-tap as an extension"
}

ensure_hop_running

# --- Download daemon + probe binaries + checksums ---------------------------

DAEMON_NAME="hop-tap-d-linux-${ARCH}"
PROBE_NAME="hop-tap-probe-linux-${ARCH}"
DAEMON_URL="${BASE_URL}/v${VERSION}/${DAEMON_NAME}"
PROBE_URL="${BASE_URL}/v${VERSION}/${PROBE_NAME}"

info "Downloading hop-tap-d..."
fetch "${DAEMON_URL}" "${TMPDIR_HOPTAP}/hop-tap-d"
fetch "${DAEMON_URL}.sha256" "${TMPDIR_HOPTAP}/hop-tap-d.sha256"

info "Downloading hop-tap-probe..."
fetch "${PROBE_URL}" "${TMPDIR_HOPTAP}/hop-tap-probe"
fetch "${PROBE_URL}.sha256" "${TMPDIR_HOPTAP}/hop-tap-probe.sha256"

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
verify_sha256 "${TMPDIR_HOPTAP}/hop-tap-probe" "${TMPDIR_HOPTAP}/hop-tap-probe.sha256"

# --- Install binaries --------------------------------------------------------

chmod +x "${TMPDIR_HOPTAP}/hop-tap-d" "${TMPDIR_HOPTAP}/hop-tap-probe"
info "Installing hop-tap-d and hop-tap-probe to /usr/local/bin (sudo required)..."
sudo mv "${TMPDIR_HOPTAP}/hop-tap-d" /usr/local/bin/hop-tap-d
sudo mv "${TMPDIR_HOPTAP}/hop-tap-probe" /usr/local/bin/hop-tap-probe

# --- Drop the extension manifest --------------------------------------------
#
# hop-tap-d is going to run as root (eBPF) so expected_uid=0. The hop
# daemon refuses to trust the bootstrap file unless its file owner
# matches this UID, so the value here has to line up with the User= in
# hop-tap.service.

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

# --- Install systemd unit ----------------------------------------------------

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

# --- Restart hop so it picks up the manifest --------------------------------

if [[ "${SKIP_RESTART}" == "false" ]]; then
  info "Restarting hop daemon to pick up the new manifest..."
  if sudo systemctl restart hop 2>/dev/null; then
    info "hop restarted."
  else
    warn "Could not restart hop (try: sudo systemctl restart hop)"
  fi
fi

# --- Done --------------------------------------------------------------------

printf "\n${BOLD}hop-tap v${VERSION}${RESET} installed.\n\n"
printf "Try it from a peer:\n"
printf "  ${BOLD}hop <host> ext list${RESET}              # tap.terminal listed as available\n"
printf "  ${BOLD}hop <host> tap list${RESET}              # active sessions\n"
printf "  ${BOLD}hop <host> tap snapshot <pty>${RESET}    # current screen\n"
printf "  ${BOLD}hop <host> tap watch <pty>${RESET}       # live byte stream\n\n"
printf "Or locally on this host (no hop network needed):\n"
printf "  ${BOLD}hop-tap-probe --bootstrap /run/hop-tap/bootstrap repl${RESET}\n\n"
printf "Service control: ${BOLD}sudo systemctl status hop-tap${RESET}\n"
printf "Logs:            ${BOLD}sudo journalctl -u hop-tap -f${RESET}\n"
