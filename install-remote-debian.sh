#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ARCHIVE_URL="${CHXSEC_SOURCE_ARCHIVE_URL:-https://github.com/chxchx-dev/chxchx-security/archive/refs/heads/dev.tar.gz}"
DATA_HOME="${XDG_DATA_HOME:-${HOME:?HOME must be set}/.local/share}"
INSTALL_DIR="${CHXSEC_INSTALL_DIR:-$DATA_HOME/chxchx-security}"

for tool in curl tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$tool" >&2
    exit 1
  fi
done

temporary_dir="$(mktemp -d)"
trap 'rm -rf -- "$temporary_dir"' EXIT

printf 'Downloading ChxChx Security source archive...\n'
curl --fail --location --show-error --retry 3 --connect-timeout 20 --max-time 300 --progress-bar \
  "$REPOSITORY_ARCHIVE_URL" \
  --output "$temporary_dir/chxchx-security.tar.gz"

if ! tar -tzf "$temporary_dir/chxchx-security.tar.gz" >/dev/null; then
  echo "The downloaded source archive is invalid." >&2
  exit 1
fi

mkdir -p -- "$INSTALL_DIR"
tar -xzf "$temporary_dir/chxchx-security.tar.gz" \
  --strip-components=1 \
  --directory "$INSTALL_DIR"

"$INSTALL_DIR/install-debian.sh" "$@"
