# Threat Model

## System boundary

The evaluated system contains a Client/Agent, an Observer relay service, durable off-chain state, and an Ethereum smart contract that records an anchor commitment. A relay event is accepted only after protocol validation and HPPK signature verification.

## Assets to protect

| Asset | Security property |
|---|---|
| Relay payload and metadata | Integrity |
| Sender identity / public-key binding | Origin authentication |
| Nonce and sequence state | Replay and ordering resistance |
| Hash-linked event history | Tamper evidence |
| Anchored root and transaction receipt | Third-party audit evidence |
| HPPK private key | Confidentiality and signing authority |

## Adversary capabilities

The adversary may:

1. observe, capture, delay, reorder, drop, duplicate, and replay relay packets;
2. modify packet fields, including payload, hashes, nonce, timestamp, public key, and signature;
3. submit malformed packets directly to the Observer API;
4. alter or remove events in an off-chain store after they were written;
5. submit an incorrect anchor or claim a false relationship between an event set and an anchor;
6. restart the Observer and attempt a replay after recovery;
7. issue concurrent duplicate requests.

## Trusted components and assumptions

The analysis assumes:

- HPPK key generation, signing, and verification operate correctly under the selected HPPK parameters;
- the sender private key is not compromised;
- Keccak-256/SHA-256 collision and preimage resistance hold for the evaluated lifetime;
- the Observer binary and its runtime host are not malicious while processing a request;
- Ethereum finality assumptions hold after the chosen confirmation policy;
- the configured Ethereum account is authorized to submit anchors;
- clocks remain within the configured maximum skew.

## Explicitly out of scope

| Out-of-scope event | Reason |
|---|---|
| Private-key theft or endpoint malware | Requires key management, HSM, OS hardening, and incident response beyond relay protocol logic |
| Cryptanalytic break of HPPK | The protocol evaluation depends on HPPK's claimed security assumptions; it does not establish a new proof |
| Hash collision/preimage break | Assumed cryptographically infeasible |
| Ethereum consensus failure or chain reorganization beyond the finality policy | Outside application-layer control |
| Denial of service from unlimited traffic | Availability controls require separate rate limiting and infrastructure capacity evaluation |
| Deletion of unanchored tail events | No external commitment yet exists; periodic anchoring bounds this exposure window |

## Security goals

The protocol seeks message integrity, origin authentication, replay resistance, ordering integrity, durable state consistency, and auditability of anchored event intervals. It does not claim confidentiality because payload encryption is not part of this protocol.

## Attack-to-control mapping

| Attack | Primary control | Verification evidence |
|---|---|---|
| Payload modification | HPPK signature + payload-hash validation | tampered-payload test |
| Signature modification | HPPK verification | tampered-signature test |
| Public-key substitution | registered key/public-key-hash binding | wrong-key test |
| Replay | durable nonce/packet identity record | replay and restart tests |
| Out-of-order event | expected step/sequence check | wrong-step and gap tests |
| History insertion/reordering | previous chain hash and recomputed chain hash | previous-hash test |
| Alteration/deletion in anchored interval | recomputed commitment compared with on-chain anchor | audit test |
| Concurrent duplicate submission | atomic durable update | concurrency test |

## Scope statement for the paper

The paper must say that the protocol *detects* tampering under these assumptions. It must not state that it prevents an attacker from transmitting a malicious packet; rather, it rejects that packet before acceptance.
