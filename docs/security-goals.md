# Security Goals and Test Traceability

## Canonical relay commitment

Before signing, the implementation must construct one canonical byte representation containing at least:

```text
protocolVersion || domain || chainId || contractAddress ||
sessionId || senderId || publicKeyHash || step || nonce ||
timestamp || expiry || payloadHash || previousChainHash
```

The exact binary or ABI encoding, field widths, ordering, and hash functions must be fixed in `docs/encoding-spec.md` before cross-language or on-chain experiments begin.

## Goals

| Goal ID | Goal | Failure condition |
|---|---|---|
| G1 | Message integrity | altered signed field is accepted |
| G2 | Origin authentication | signature verifies under an unregistered/substituted key |
| G3 | Replay resistance | identical packet or reused nonce is accepted twice |
| G4 | Ordering integrity | wrong, skipped, or reordered step advances state |
| G5 | Chain continuity | incorrect previous hash or recomputed chain hash is accepted |
| G6 | Restart safety | replay succeeds after Observer restart |
| G7 | Anchored auditability | changed/deleted anchored event interval still matches anchor |
| G8 | Measurement reproducibility | result lacks version, parameter, environment, or checksum evidence |

## Test mapping

| Goal | Test case | Expected result | Required evidence |
|---|---|---|---|
| G1 | payload, payloadHash, timestamp, metadata, chainHash tamper | reject | test log and CSV row |
| G2 | malformed key; independent Agent-B key | reject unless registered | public-key fingerprints and test log |
| G3 | identical packet; reused nonce | reject after first acceptance | state snapshot before/after |
| G4 | previous step; future step; gap | reject | response/error and state snapshot |
| G5 | incorrect previous hash; inserted event | reject | recomputed hash record |
| G6 | restart Observer, replay same event | reject | durable-state file/DB evidence |
| G7 | modify/remove anchored event | audit mismatch | on-chain tx hash and recomputed root |
| G8 | rerun fixed experiment | reproducible output | manifest, raw log, checksum |

## PASS/FAIL rule

A test case passes only when:

1. its observed result equals the predefined expected result;
2. rejected packets do not advance sequence, nonce, or chain state;
3. raw output, input identifiers, source commit, and result checksum are preserved;
4. the test runner exits with status 0.

## Security claim boundaries

- HPPK verifies the signature only; replay resistance also requires durable state.
- Hash chaining exposes broken linkage but an unanchored final event can still be deleted without a prior external commitment.
- Ethereum anchoring makes only the committed interval independently auditable.
- A smart contract that merely stores a supplied hash is an anchor registry, not an on-chain HPPK verifier. The paper must distinguish these designs.
