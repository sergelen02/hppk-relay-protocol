# Experiment Plan

## Experiment order

| Phase | Goal | Prerequisite | Output |
|---|---|---|---|
| 0 | scope, RQs, threat model, acceptance criteria | none | four documents in `docs/` |
| A | HPPK and off-chain relay correctness | Phase 0 | raw unit-test and attack logs |
| B | durable store, restart, and concurrency | Phase A | state-consistency evidence |
| C | Dockerized multi-agent relay | Phase B | compose deployment and metrics |
| D | Ethereum anchoring and audit verification | Phase C | contract tests, receipts, root checks |
| E | ECDSA/HPPK/ML-DSA performance comparison | Phase A; same harness | CSV and statistical summary |
| F | AKS/PoS scale evaluation | C, D, E | deployment manifests and scale results |
| G | paper writing and reproducibility review | all relevant results | figures, tables, appendix package |

## Fixed experimental controls

Record these fields in every run manifest:

- UTC start/end time and experiment identifier;
- repository commit SHA for HPPK_2 and hppk-relay-protocol;
- parameter JSON SHA-256 and parameter name;
- public-key SHA-256 only; never record secret-key contents or secret-key hashes in public results;
- OS, kernel, CPU model/count, RAM, Go version, Foundry version, geth version;
- message size, client count, iteration count, and anchor batch size;
- chain ID, contract address, and confirmation policy for on-chain tests.

## Phase-A procedure

1. Create fresh HPPK experimental keys outside Git repositories.
2. Run all HPPK_2 unit tests.
3. Run direct real-HPPK sign/verify and tamper tests.
4. Run real-HPPK relay acceptance/rejection tests.
5. Benchmark HPPK KeyGen, Sign, and Verify ten times.
6. Benchmark relay processing and rejection paths ten times.
7. Preserve raw output, manifest, and SHA-256 checksums.

Use:

```bash
export HPPK_ROOT=/absolute/path/to/HPPK_2
export HPPK_PUBLIC_KEY_PATH=/absolute/path/to/agent-a-pk.json
export HPPK_SECRET_KEY_PATH=/absolute/path/to/agent-a-sk.json

bash scripts/phase_a_real_hppk.sh
```

## Result schemas

### Security-result CSV

```text
experiment_id,case_id,attack_type,expected,observed,http_status,error_code,state_changed,status
```

### Performance-result CSV

```text
experiment_id,algorithm,operation,message_bytes,run_index,ns_per_op,bytes_per_op,allocs_per_op,status
```

### Anchor-result CSV

```text
experiment_id,session_id,start_step,end_step,root_hash,tx_hash,block_number,gas_used,status
```

## Statistical analysis

For each operation and configuration, calculate:

- number of valid runs;
- mean and median;
- standard deviation;
- minimum and maximum;
- 95% confidence interval;
- excluded-run reason, if any.

Raw benchmark files are the source of truth; summary CSVs and graphs must be generated from them by versioned scripts.

## Completion gates

| Gate | Required condition |
|---|---|
| A complete | all real-HPPK correctness tests pass; raw ten-run benchmarks exist |
| B complete | restart and concurrency tests show no duplicate acceptance |
| C complete | at least two independently keyed clients relay through Observer |
| D complete | auditor recomputes anchored root and detects modified/deleted anchored history |
| E complete | ECDSA, HPPK, and chosen ML-DSA use the same message sizes and reporting method |
| G complete | another environment can reproduce the stated result set from README |
