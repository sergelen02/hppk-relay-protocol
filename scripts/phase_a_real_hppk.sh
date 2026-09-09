#!/usr/bin/env bash
set -euo pipefail

RELAY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HPPK_ROOT="${HPPK_ROOT:?set HPPK_ROOT to the absolute HPPK_2 repository path}"
HPPK_PUBLIC_KEY_PATH="${HPPK_PUBLIC_KEY_PATH:?set HPPK_PUBLIC_KEY_PATH to a fresh public-key JSON file}"
HPPK_SECRET_KEY_PATH="${HPPK_SECRET_KEY_PATH:?set HPPK_SECRET_KEY_PATH to a fresh secret-key JSON file}"
HPPK_PARAMS="${HPPK_PARAMS:-$HPPK_ROOT/configs/params/ds/level5.json}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-phase-a}"
RESULT_DIR="$RELAY_ROOT/results/phase-a/$RUN_ID"

for required_path in "$HPPK_ROOT/go.mod" "$HPPK_PUBLIC_KEY_PATH" "$HPPK_SECRET_KEY_PATH" "$HPPK_PARAMS"; do
  [[ -f "$required_path" ]] || { echo "required file not found: $required_path" >&2; exit 2; }
done

mkdir -p "$RESULT_DIR"
"$RELAY_ROOT/scripts/collect_experiment_env.sh" "$RESULT_DIR/environment.txt"

(
  cd "$RELAY_ROOT"
  if [[ ! -f go.work ]]; then
    go work init "$RELAY_ROOT" "$HPPK_ROOT"
  fi
  go work edit -replace github.com/sergelen02/HPPK_2="$HPPK_ROOT"
)

{
  echo "run_id=$RUN_ID"
  echo "captured_at_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "relay_root=$RELAY_ROOT"
  echo "hppk_root=$HPPK_ROOT"
  echo "hppk_params=$HPPK_PARAMS"
  echo "hppk_public_key_sha256=$(sha256sum "$HPPK_PUBLIC_KEY_PATH" | awk '{print $1}')"
  echo "relay_commit=$(git -C "$RELAY_ROOT" rev-parse HEAD)"
  echo "hppk_commit=$(git -C "$HPPK_ROOT" rev-parse HEAD)"
} > "$RESULT_DIR/manifest.txt"

(
  cd "$HPPK_ROOT"
  go test ./... -count=1 -v
) 2>&1 | tee "$RESULT_DIR/hppk-unit-tests.txt"

(
  cd "$RELAY_ROOT"
  HPPK_PUBLIC_KEY_PATH="$HPPK_PUBLIC_KEY_PATH" \
  HPPK_SECRET_KEY_PATH="$HPPK_SECRET_KEY_PATH" \
  go test ./agent/internal/protocol \
    -run '^(TestRealHPPK|TestProcessRelayRealHPPK)' \
    -count=1 -v
) 2>&1 | tee "$RESULT_DIR/relay-real-hppk-tests.txt"

(
  cd "$HPPK_ROOT"
  BENCH_PARAMS="$HPPK_PARAMS" \
  go test ./internal/ds -run '^$' \
    -bench 'BenchmarkDS_(KeyGen|Sign|Verify)' \
    -benchmem -benchtime=3s -count=10
) 2>&1 | tee "$RESULT_DIR/hppk-benchmark-10runs.txt"

(
  cd "$RELAY_ROOT"
  HPPK_PUBLIC_KEY_PATH="$HPPK_PUBLIC_KEY_PATH" \
  HPPK_SECRET_KEY_PATH="$HPPK_SECRET_KEY_PATH" \
  go test ./agent/internal/protocol -run '^$' \
    -bench 'Benchmark(ProcessRelayRealHPPK|RejectRealHPPK)' \
    -benchmem -benchtime=3s -count=10
) 2>&1 | tee "$RESULT_DIR/relay-benchmark-10runs.txt"

(
  cd "$RESULT_DIR"
  sha256sum environment.txt manifest.txt *.txt > checksums.sha256
)

echo "Phase A completed: $RESULT_DIR"
