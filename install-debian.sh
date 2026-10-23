#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
INSTALL_SYSTEM_PACKAGES=1
INSTALL_DEV_DEPENDENCIES=0
START_TOR=0
ENABLE_TOR=0
ASSUME_YES=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: ./install-debian.sh [options]

Install ChxChx Security on Ubuntu or Kali Linux.

Options:
  --yes                 Do not ask before installing system packages.
  --dry-run             Show planned actions without changing the system.
  --no-system-packages  Skip APT; use when dependencies are already installed.
  --with-dev            Also install pytest and build tools in the project virtual environment.
  --start-tor           Start tor.service after installation.
  --enable-tor          Enable tor.service at boot and start it now.
  -h, --help            Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --no-system-packages) INSTALL_SYSTEM_PACKAGES=0 ;;
    --with-dev) INSTALL_DEV_DEPENDENCIES=1 ;;
    --start-tor) START_TOR=1 ;;
    --enable-tor) ENABLE_TOR=1; START_TOR=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      printf 'Unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [[ "$(uname -s)" != "Linux" ]] || ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer requires Linux with APT (Ubuntu or Kali)." >&2
  exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release
if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "kali" ]]; then
  echo "This installer targets Ubuntu or Kali Linux. Detected: ${NAME:-unknown}." >&2
  exit 1
fi

if command -v python3 >/dev/null 2>&1 && ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required. Use Ubuntu 24.04+ or upgrade Python before installation." >&2
  exit 1
fi

if [[ ! -f "$SCRIPT_DIR/pyproject.toml" ]]; then
  echo "Run this installer from a ChxChx Security source tree." >&2
  exit 1
fi

packages=(python3 python3-venv python3-pip tor torsocks curl network-manager iproute2 nftables)
if (( INSTALL_SYSTEM_PACKAGES )); then
  printf 'ChxChx Security will install/verify these APT packages on %s:\n' "${NAME:-Linux}"
  printf '  - %s\n' "${packages[@]}"
  echo
  if (( ! ASSUME_YES && ! DRY_RUN )); then
    if [[ ! -t 0 ]]; then
      echo "Non-interactive execution requires --yes." >&2
      exit 2
    fi
    read -r -p 'Continue? [Y/n] ' answer
    if [[ "${answer:-}" =~ ^[Nn]$ ]]; then
      echo "Installation cancelled."
      exit 0
    fi
  fi
fi

if (( DRY_RUN )); then
  printf '\nPlanned project directory: %s\n' "$SCRIPT_DIR"
  printf 'Planned virtual environment: %s\n' "$VENV_DIR"
  if (( INSTALL_SYSTEM_PACKAGES )); then
    echo 'Planned system commands: apt-get update; apt-get install'
  fi
  if (( ENABLE_TOR )); then
    echo 'Tor service action: enable and start'
  elif (( START_TOR )); then
    echo 'Tor service action: start'
  else
    echo 'Tor service action: leave unchanged'
  fi
  exit 0
fi

run_privileged() {
  if [[ "$EUID" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

if (( INSTALL_SYSTEM_PACKAGES )); then
  echo 'Updating APT package indexes...'
  run_privileged apt-get update
  echo 'Installing ChxChx Security system dependencies...'
  run_privileged apt-get install --yes "${packages[@]}"
fi

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "Python 3.11 or newer is required. Upgrade Python and rerun this installer." >&2
  exit 1
fi

if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/python" -m pip install --disable-pip-version-check -e "$SCRIPT_DIR"
if (( INSTALL_DEV_DEPENDENCIES )); then
  "$VENV_DIR/bin/python" -m pip install --disable-pip-version-check pytest build
fi

if (( ENABLE_TOR )); then
  run_privileged systemctl enable --now tor.service
elif (( START_TOR )); then
  run_privileged systemctl start tor.service
fi

echo
echo "ChxChx Security installation complete."
echo "Activate the environment with:"
printf '  source %q/bin/activate\n' "$VENV_DIR"
echo "Then run:"
echo "  chxsec doctor"
echo "  chxsec tor verify"
if (( ! START_TOR )); then
  echo "Tor was not started by this installer. Use: chxsec tor start"
fi
