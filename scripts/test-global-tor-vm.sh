#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/test-global-tor-vm.sh --snapshot-confirmed --console-confirmed

Runs the privileged whole-host Tor acceptance checks. Use only inside a
disposable Fedora VM restored from a clean snapshot, from its hypervisor
console. Network access is intentionally changed while the test runs.
EOF
}

snapshot_confirmed=0
console_confirmed=0
for arg in "$@"; do
  case "$arg" in
    --snapshot-confirmed) snapshot_confirmed=1 ;;
    --console-confirmed) console_confirmed=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if (( ! snapshot_confirmed || ! console_confirmed )); then
  echo "Refusing: confirm the clean VM snapshot and hypervisor console." >&2
  usage >&2
  exit 2
fi
if (( EUID == 0 )); then
  echo "Run as the regular VM user; the script invokes sudo for inspection." >&2
  exit 2
fi
if [[ ! -t 0 || ! -t 1 ]]; then
  echo "Run from an interactive hypervisor console, not SSH or a pipe." >&2
  exit 2
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
python="$repo_root/.venv/bin/python"
if [[ ! -x "$python" ]]; then
  echo "Missing project venv at $python; install the checkout first." >&2
  exit 2
fi
if ! command -v sudo >/dev/null || ! command -v nft >/dev/null \
    || ! command -v curl >/dev/null || ! command -v ping >/dev/null \
    || ! command -v dig >/dev/null; then
  echo "Required tools: sudo, nft, curl, ping and dig." >&2
  exit 2
fi

chxsec() {
  PYTHONPATH="$repo_root/src${PYTHONPATH:+:$PYTHONPATH}" \
    "$python" -m chxchx_security "$@"
}

echo "Checking sudo access and global mode baseline..."
sudo -v
if chxsec global status --json | "$python" -c \
    'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("active") else 1)'; then
  echo "Refusing: global Tor mode is already active; stop it or restore snapshot." >&2
  exit 2
fi

echo "Reviewing the plan..."
chxsec global plan
echo "Applying whole-host Tor mode..."
chxsec global start --yes
applied=1

cleanup() {
  rc=$?
  trap - EXIT INT TERM
  if (( ${applied:-0} )); then
    echo "Stopping whole-host mode during cleanup..." >&2
    chxsec global stop || {
      echo "Cleanup failed; use the hypervisor console or restore the snapshot." >&2
      rc=1
    }
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Checking state and transparent Tor egress..."
chxsec global status
curl --fail --silent --show-error --max-time 30 \
  https://check.torproject.org/api/ip \
  | "$python" -c 'import json,sys; data=json.load(sys.stdin); print("IsTor:", data.get("IsTor")); raise SystemExit(0 if data.get("IsTor") is True else 1)'

echo "Checking that direct ICMP and external DNS fail closed..."
if ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
  echo "FAIL: direct ICMP unexpectedly succeeded." >&2
  exit 1
fi
if dig +time=3 +tries=1 @1.1.1.1 example.com A \
    | grep -q 'status: NOERROR'; then
  echo "FAIL: direct DNS unexpectedly returned an answer." >&2
  exit 1
fi

echo "Stopping global mode and checking cleanup..."
chxsec global stop
applied=0
if chxsec global status --json | "$python" -c \
    'import json,sys; raise SystemExit(0 if not json.load(sys.stdin).get("active") else 1)'; then
  :
else
  echo "FAIL: global mode still reports active after stop." >&2
  exit 1
fi
if sudo test -e /etc/tor/torrc.d/chxsec-global.conf; then
  echo "FAIL: ChxChx Tor drop-in remains after stop." >&2
  exit 1
fi
if sudo nft list table ip chxsec_global_nat >/dev/null 2>&1 \
    || sudo nft list table inet chxsec_global_filter >/dev/null 2>&1; then
  echo "FAIL: a ChxChx nftables table remains after stop." >&2
  exit 1
fi

echo "PASS: global mode routed HTTPS through Tor, blocked direct ICMP/DNS, and cleaned up."
echo "Still verify manually: reboot returns to inactive mode; inspect SELinux labels; test a failed apply/rollback."
