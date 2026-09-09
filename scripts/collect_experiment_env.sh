#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <output-file>" >&2
  exit 2
fi

output_file="$1"
mkdir -p "$(dirname "$output_file")"

{
  echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "=== system ==="
  uname -a || true
  echo
  echo "=== cpu ==="
  lscpu || true
  echo
  echo "=== memory ==="
  free -h || true
  echo
  echo "=== toolchain ==="
  go version || true
  forge --version || true
  geth version || true
  docker --version || true
  docker compose version || true
} > "$output_file"
