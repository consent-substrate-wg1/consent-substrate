# Security Policy

## Reporting a vulnerability

Open a **private** GitHub security advisory (Security tab → Report a
vulnerability) rather than a public issue. You will get an acknowledgment
within 7 days and a status update every 14 days until resolution.

## Scope

- The cryptographic design (Ed25519 signature scheme usage, chain-head
  pegging, digest-only publication).
- The enforcement invariants of `roe_gate.py` (deny-by-default, fail-closed,
  tier reachability, kill switch) and `canary_skill.py` (trip scoring,
  witness-chain append-only semantics).
- Bypasses: any sequence of actions that causes a protected agent to perform
  an unauthorized capability without a gate receipt, or that mutates a
  committed chain link without detection.

## Out of scope

- Attacks that require the signing key or an authorized operator's explicit
  consent (that is the threat model working as designed).
- Reports about the companion lab agent framework beyond its integration
  surface with this stack.

## Safe harbor

We consider good-faith research following this policy to be authorized
security research. We will not pursue action against researchers who respect
this scope, use their own deployments or test fixtures, and avoid exfiltrating
or retaining third-party data.
