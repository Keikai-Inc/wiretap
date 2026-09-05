#!/usr/bin/env bash
# quarantine-containment.sh — prove the tap honeypot's decoy sandbox actually
# contains a shell: no host filesystem, no host PID space, no host network, a
# read-only /usr, a synthesized identity, and a refusal to run as root.
#
# Cross-builds tap-honeypot for Linux, runs it inside a container, drives a
# probe script through the sandboxed shell, and scores the output. The harness
# decides pass/fail, not the shell under test.
#
#   ./tests/quarantine-containment.sh
#
# Needs Docker (Colima on macOS) and `cross`. The container runs --privileged
# only so it may create user namespaces; the isolation being tested is the
# sandbox's own, which holds regardless of the outer container.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET=aarch64-unknown-linux-gnu
BIN="$ROOT/target/$TARGET/release/tap-honeypot"
IMG=wiretap-quarantine
WORK="$(mktemp -d)"
trap 'docker rmi -f "$IMG" >/dev/null 2>&1; rm -rf "$WORK"' EXIT

command -v docker >/dev/null || { echo "need docker" >&2; exit 2; }
command -v cross  >/dev/null || { echo "need cross"  >&2; exit 2; }

echo "==> building tap-honeypot ($TARGET)"
HOP_TAP_SKIP_EBPF_BUILD=1 cross build --release --target "$TARGET" --bin tap-honeypot -p wiretap-d \
  || { echo "build failed" >&2; exit 1; }
cp "$BIN" "$WORK/tap-honeypot"

# Probe script, baked into the image, run INSIDE the sandbox (no awk: not
# guaranteed on PATH there).
cat > "$WORK/probe.sh" <<'PROBE'
echo "ID=$(id -un 2>&1):$(id -u 2>&1)"
echo "HOST_SECRET=$(cat /host-only-secret 2>&1)"
echo "PASSWD_HOST_USER=$(grep -cE '^ubuntu:' /etc/passwd 2>/dev/null);HAS_ALICE=$(grep -cE '^alice:' /etc/passwd 2>/dev/null)"
echo "NET_IFACES=$(ls /sys/class/net 2>/dev/null | tr '\n' ',')"
echo "USR_WRITE=$(touch /usr/EVIL 2>/dev/null && echo WROTE || echo denied)"
echo "PROC_PIDS=$(ls /proc 2>/dev/null | grep -cE '^[0-9]+$')"
PROBE

cat > "$WORK/Dockerfile" <<'EOF'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils iproute2 procps ca-certificates && rm -rf /var/lib/apt/lists/*
COPY tap-honeypot /usr/local/bin/tap-honeypot
COPY probe.sh /probe.sh
RUN chmod +x /usr/local/bin/tap-honeypot && echo "TOP-SECRET-HOST-DATA" > /host-only-secret
EOF
docker build -q -t "$IMG" "$WORK" >/dev/null || { echo "image build failed" >&2; exit 1; }

echo "==> running containment probes"
OUT="$(docker run --rm --privileged "$IMG" \
      bash -lc 'cat /probe.sh | tap-honeypot exec --user alice --uid 1000 2>&1')"
echo "$OUT" | sed 's/^/    /'

echo "==> uid=0 refusal"
REF="$(docker run --rm --privileged "$IMG" \
      bash -lc 'printf "id\n" | tap-honeypot exec --user root --uid 0 2>&1; echo "rc=$?"')"
echo "$REF" | sed 's/^/    /'

echo "==> scoring"
fail=0
check() { if [ "$2" = 0 ]; then echo "    PASS  $1"; else echo "    FAIL  $1"; fail=1; fi; }
grep -q 'ID=alice:1000'              <<<"$OUT"; check "runs as the synthesized unprivileged user" $?
grep -q 'HOST_SECRET=.*No such file' <<<"$OUT"; check "host filesystem is not reachable"          $?
grep -q 'PASSWD_HOST_USER=0;HAS_ALICE=1' <<<"$OUT"; check "/etc/passwd is synthesized (alice present, host user absent)" $?
grep -qE 'NET_IFACES=(lo,)?$'        <<<"$OUT"; check "network namespace is isolated (lo only)"    $?
grep -q 'USR_WRITE=denied'           <<<"$OUT"; check "/usr is read-only"                          $?
pids=$(sed -n 's/.*PROC_PIDS=//p' <<<"$OUT")
{ [ -n "$pids" ] && [ "$pids" -le 20 ]; }; check "PID namespace is isolated (few processes: ${pids:-?})" $?
grep -q 'refusing to spawn the quarantine sandbox with uid/gid 0' <<<"$REF"; check "refuses to run the decoy as root" $?

echo
if [ $fail = 0 ]; then echo "QUARANTINE CONTAINMENT: PASS"; else echo "QUARANTINE CONTAINMENT: FAIL"; fi
exit $fail
