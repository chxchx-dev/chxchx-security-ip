#!/usr/bin/env bash
set -euo pipefail

SOURCE_REF="${CHXSEC_SOURCE_REF:-}"
EXPECTED_SHA256="${CHXSEC_SOURCE_ARCHIVE_SHA256:-}"
CUSTOM_ARCHIVE_URL="${CHXSEC_SOURCE_ARCHIVE_URL:-}"

if [[ -n "$SOURCE_REF" ]]; then
  if [[ -n "$CUSTOM_ARCHIVE_URL" ]]; then
    echo "Set either CHXSEC_SOURCE_REF or CHXSEC_SOURCE_ARCHIVE_URL, not both." >&2
    exit 1
  fi
  if [[ "$SOURCE_REF" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
    REPOSITORY_ARCHIVE_URL="https://github.com/chxchx-dev/chxchx-security/archive/refs/tags/$SOURCE_REF.tar.gz"
  elif [[ "$SOURCE_REF" =~ ^[[:xdigit:]]{40}$ ]]; then
    REPOSITORY_ARCHIVE_URL="https://github.com/chxchx-dev/chxchx-security/archive/$SOURCE_REF.tar.gz"
  else
    echo "CHXSEC_SOURCE_REF must be a release tag (for example v0.2.0) or a 40-character commit SHA." >&2
    exit 1
  fi
  if [[ ! "$EXPECTED_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
    echo "CHXSEC_SOURCE_REF requires a 64-character CHXSEC_SOURCE_ARCHIVE_SHA256." >&2
    exit 1
  fi
elif [[ -n "$CUSTOM_ARCHIVE_URL" ]]; then
  REPOSITORY_ARCHIVE_URL="$CUSTOM_ARCHIVE_URL"
else
  REPOSITORY_ARCHIVE_URL="https://github.com/chxchx-dev/chxchx-security/archive/refs/heads/dev.tar.gz"
fi

if [[ -n "$EXPECTED_SHA256" && ! "$EXPECTED_SHA256" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "CHXSEC_SOURCE_ARCHIVE_SHA256 must contain exactly 64 hexadecimal characters." >&2
  exit 1
fi
EXPECTED_SHA256="${EXPECTED_SHA256,,}"
DATA_HOME="${XDG_DATA_HOME:-${HOME:?HOME must be set}/.local/share}"
INSTALL_DIR="${CHXSEC_INSTALL_DIR:-$DATA_HOME/chxchx-security}"
for tool in curl tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf "Required command not found: %s\n" "$tool" >&2
    exit 1
  fi
done

if [[ -n "$EXPECTED_SHA256" ]] && ! command -v sha256sum >/dev/null 2>&1; then
  echo "Required command not found: sha256sum" >&2
  exit 1
fi

temporary_dir="$(mktemp -d)"
trap 'rm -rf -- "$temporary_dir"' EXIT

printf 'Downloading ChxChx Security source...\n'
curl --fail --location --show-error --retry 3 --connect-timeout 20 --max-time 300 --progress-bar \
  "$REPOSITORY_ARCHIVE_URL" \
  --output "$temporary_dir/chxchx-security.tar.gz"

if [[ -n "$EXPECTED_SHA256" ]]; then
  if ! printf "%s  %s\n" "$EXPECTED_SHA256" "$temporary_dir/chxchx-security.tar.gz" | sha256sum --check --status -; then
    echo "The downloaded source archive does not match CHXSEC_SOURCE_ARCHIVE_SHA256." >&2
    exit 1
  fi
fi

if ! tar -tzf "$temporary_dir/chxchx-security.tar.gz" >/dev/null; then
  echo "The downloaded source archive is invalid." >&2
  exit 1
fi

mkdir -p -- "$INSTALL_DIR"
tar -xzf "$temporary_dir/chxchx-security.tar.gz" \
  --strip-components=1 \
  --directory "$INSTALL_DIR"

"$INSTALL_DIR/install-fedora.sh" "$@"
