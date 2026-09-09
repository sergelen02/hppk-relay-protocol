# Phase A: HPPK relay experiment readiness

This document prepares the reproducible off-chain baseline for the paper *A Post-Quantum-Resistant Relay Protocol Using HPPK Signatures for Blockchain Systems*.

## Scope and pass conditions

Phase A evaluates RQ1 and RQ2 before Docker, Geth, or on-chain anchoring is introduced.

| Check | Evidence | Pass condition |
|---|---|---|
| HPPK unit tests | `go test ./...` in HPPK_2 | exit code 0 |
| Direct HPPK test | `TestRealHPPKSignVerifyDirect` | sign and verify pass |
| Tamper test | `TestRealHPPKTamperedMessageDirectReject` | altered message is rejected |
| Relay tests | `TestProcessRelayRealHPPK...` | valid packet accepted; invalid cases rejected |
| HPPK benchmark | `BenchmarkDS_...` | ten raw runs preserved |
| Relay benchmark | `BenchmarkProcessRelayRealHPPK...` | ten raw runs preserved |

## One-time local setup

The relay module currently contains a machine-specific `replace` directive for HPPK_2. The supplied runner creates a local, ignored `go.work` workspace and overrides that directive without editing `go.mod`.

```bash
git clone https://github.com/sergelen02/HPPK_2.git
git clone https://github.com/sergelen02/hppk-relay-protocol.git

cd hppk-relay-protocol
export HPPK_ROOT="$(cd ../HPPK_2 && pwd)"
export HPPK_PUBLIC_KEY_PATH="/absolute/path/outside/repositories/agent-a-pk.json"
export HPPK_SECRET_KEY_PATH="/absolute/path/outside/repositories/agent-a-sk.json"
bash scripts/phase_a_real_hppk.sh
```

Generate fresh experimental keys outside either Git repository:

```bash
KEY_ROOT="$PWD/../hppk-experiment-keys/agent-a"
mkdir -p "$KEY_ROOT"

cd "$HPPK_ROOT"
go run ./cmd/ds/keygen \
  -params ./configs/params/ds/level5.json \
  -out "$KEY_ROOT/sk.json" \
  -pub "$KEY_ROOT/pk.json"

chmod 600 "$KEY_ROOT/sk.json"
export HPPK_PUBLIC_KEY_PATH="$KEY_ROOT/pk.json"
export HPPK_SECRET_KEY_PATH="$KEY_ROOT/sk.json"
```

## Outputs

The runner writes one immutable run directory:

```text
results/phase-a/<UTC-run-id>/
  environment.txt
  manifest.txt
  hppk-unit-tests.txt
  relay-real-hppk-tests.txt
  hppk-benchmark-10runs.txt
  relay-benchmark-10runs.txt
  checksums.sha256
```

Do not merge or compare results from different run directories until CPU, Go version, parameter file, and git commits have been checked in `manifest.txt`.

## Security prerequisite

The default branches presently contain tracked development configuration and HPPK secret-key-like JSON files. Treat every tracked private value as exposed; do **not** use them for new experiments. Generate fresh keys as above. Before a public release, rotate the affected keys, remove tracked secrets from the working tree and Git history, and retain only `.env.example` and public test vectors.
