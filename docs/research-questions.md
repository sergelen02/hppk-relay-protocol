# Research Questions and Hypotheses

## Working title

**A Post-Quantum-Resistant Relay Protocol Using HPPK Signatures for Blockchain Systems**

## Research objective

This work designs and evaluates an HPPK-signed relay protocol that protects off-chain relay events and periodically anchors their audit evidence to Ethereum. The work evaluates the system under the claimed security assumptions of the HPPK digital-signature scheme; it does not claim that HPPK is a NIST-standardized signature scheme.

## Main research question

> Can a relay protocol that combines HPPK signatures, stateful replay and ordering checks, hash chaining, and Ethereum anchoring provide verifiable integrity and auditability with practical performance costs?

## Sub-questions

### RQ1 — Message integrity and origin authentication

> Does the HPPK-signed relay protocol detect modification of a relay event and its security-relevant metadata?

**Tested fields:** payload, payload hash, previous chain hash, current chain hash, sender public key, signature, timestamp, nonce, and step.

**Acceptance criterion:** every altered event is rejected before it changes relay state.

### RQ2 — Replay and ordering resistance

> Do nonce, step/sequence validation, and previous-hash linkage detect replayed and out-of-order relay events?

**Tested attacks:** identical packet replay, duplicate nonce, incorrect step, skipped step, stale timestamp, and incorrect previous chain hash.

**Acceptance criterion:** a valid event is accepted once; duplicate or incorrectly ordered events are rejected and do not advance session state.

**Important scope note:** a hash chain alone cannot prove that the final, unanchored tail event was not deleted. Detection of deletion for an already committed interval belongs to RQ3.

### RQ3 — Auditability through anchoring

> Can periodic anchoring of a relay-log commitment to Ethereum make modification or deletion of events in the anchored interval detectable to an auditor?

**Tested attacks:** altered stored event, removed intermediate event, substituted root, and mismatched on-chain commitment.

**Acceptance criterion:** recomputation from retained events produces a commitment that matches the on-chain anchor only when the anchored event interval is intact.

### RQ4 — Cost and performance trade-offs

> How do HPPK, ECDSA secp256k1, and ML-DSA differ in cryptographic cost, artifact size, relay latency, throughput, and anchoring-related cost?

**Measured variables:** key generation, signing, verification, public-key size, signature size, packet size, end-to-end latency, throughput, CPU and memory use, and gas used per anchor/event.

**Acceptance criterion:** report median, mean, standard deviation, minimum, maximum, and 95% confidence interval from repeated runs. No algorithm is assumed to be universally superior.

## Hypotheses

| ID | Hypothesis | Evidence required |
|---|---|---|
| H1 | A signature over the canonical relay commitment rejects altered messages and signed metadata. | Valid/tampered test matrix and raw logs |
| H2 | Replay and ordering checks reject duplicate or invalidly ordered packets without mutating durable state. | Replay, step, nonce, restart, and concurrency tests |
| H3 | An on-chain anchor exposes inconsistency in altered or deleted events from its anchored interval. | Root recomputation and contract-event verification |
| H4 | HPPK, ECDSA, and ML-DSA exhibit measurable performance and size trade-offs. | Controlled repeated benchmark dataset |

## Comparison policy

| Role | Algorithm |
|---|---|
| Existing Ethereum baseline | ECDSA secp256k1 |
| Proposed signature | HPPK DS |
| Standardized PQC baseline | ML-DSA-44 or ML-DSA-65 |

Use one fixed ML-DSA parameter set for the primary comparison. ML-DSA-65 is recommended when the objective is a stronger general-purpose baseline; ML-DSA-44 is appropriate where constrained-resource cost is the primary comparison. If both are measured, label one primary and the other supplementary.

## Sources

- NIST, [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final).
- Kuang et al., [Homomorphic Polynomial Public Key Cryptography for Quantum-secure Digital Signature](https://arxiv.org/abs/2311.08967).
- Wood, [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).
