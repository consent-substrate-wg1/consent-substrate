# consent-substrate
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23797526.svg)](https://doi.org/10.5281/zenodo.23797526)

**Signed authorization and witness boundaries for LLM agents.**

> Sell consent, never capability. Every dollar of trust this project earns is
> traceable to a signature, a hash chain, or a disclosure.

The most dangerous intrusions into LLM-agent deployments are not the ones that
look dangerous. A *quiet-class* attacker makes every individual action read as
legitimate work — read a file, summarize a document, check an endpoint — so any
defense that asks **"does this action look bad?"** fails by construction.
This project replaces that detection primitive with two questions that can
actually be answered, both backed by one Ed25519 trust root:

1. **Is this action authorized?** — the rules-of-engagement gate
   (`roe_gate.py` + `manifest_tool.py`). Deny-by-default against signed scope
   manifests; fail-closed; every allow *and* every denial lands in a
   tamper-evident, hash-chained audit log.
2. **Did this actor touch a witness?** — the canary substrate
   (`canary_skill.py`). Seeded tokens, decoy paths, and decoy endpoints that
   are indistinguishable from real loot; contact is logged to a digest-only
   signed chain whose first link is pegged to the gate's chain head.

The result is one evidence forest with a property no refusal-rate scanner
offers: an attack against a protected agent is either **detected** or
**proven** — there is no third option.

## Components

| File | Role | Self-check |
|---|---|---|
| `manifest_tool.py` | Ed25519-signed scope manifests (keygen, sign, verify) | roundtrip below |
| `roe_gate.py` | runtime gate: deny-by-default, fail-closed, audit chain, kill switch | `python roe_gate.py --self-test` (21) |
| `agent_roe.py` | reference integration wiring the gate into an agent loop | imported by tests |
| `gate_bootstrap.py` | one-time consent setup for a lab machine | `python -m py_compile` |
| `patch_agent.py` | idempotent, reversible patcher adding gate enforcement points to an agent | `python -m py_compile` |
| `canary_skill.py` | injection canary: 38-case corpus, quiet-class tripwires, signed witness chain | `python canary_skill.py --selftest` (38/38) |
| `schema/scope_manifest.schema.json` | JSON Schema for signed manifests | `manifest_tool.py export-schema` |

Zero third-party dependencies. Python 3.9+. `networkx`-free, `cryptography`-free:
all Ed25519 signing is pure-stdlib.

## Quickstart (test-proven)

```bash
# 1. signing key
python manifest_tool.py keygen --outdir keys/          # -> roe_signing.pem/.pub

# 2. a manifest (example template), sign it
python manifest_tool.py example --out m.json
python manifest_tool.py sign m.json --key keys/roe_signing.pem --out signed.json

# 3. verify, then check a capability at runtime
python manifest_tool.py verify signed.json --pub keys/roe_signing.pub
python roe_gate.py --self-test                          # 21/21
python canary_skill.py --selftest                       # 38/38
```

Wiring the gate into an existing agent is one wrapper around any action —
see `agent_roe.py` for the three enforcement points (startup, every tool
call, in-band denial observations the model can see and adapt to), and
`patch_agent.py` for an idempotent patcher that installs them.

## The paper

**Detected or Proven: Signed Witness Boundaries Against Quiet-Class
Compromise of LLM Agents** — [`paper/detected-or-proven-preprint.pdf`](paper/detected-or-proven-preprint.pdf)
(LaTeX source in `paper/`). DOI: [10.5281/zenodo.23797526](https://doi.org/10.5281/zenodo.23797526).

The paper contains the full threat model (the quiet class, four unavoidable
contact points, four asymmetries), the design rationale, the 38-case replay
methodology, and **Appendix A: a third-party reproduction protocol**.

## Reproducibility

The evaluation's headline exhibit is a **digest pair**: a chain dry-run and a
production run over the same corpus produce *identical* chain digests
(`f9181d99…95656` for the v1.0.0 corpus), because the chain is a pure
function of the rule set. The same protocol re-run on any machine must
reproduce the digest exactly; divergence is a finding, not a nuisance.
The 38-case corpus ships inside `canary_skill.py --selftest`, so the entire
replay is one command with no network access.

## Scope

This is defensive infrastructure. The gate refuses to execute without a
signed manifest; the audit chain records refusals with the same care as
allows, so an operator can prove both what their agents *did* and what they
*refused to do*. Capability tiers are compiled in, not documented in:
staged-data demonstrations are unreachable outside explicit lab mode.
Disclosure workflows built on this stack are report-only by construction.

> If a module needs a camouflage layer to pass review, it isn't a product —
> it's evidence.

## Citation

See [`CITATION.cff`](CITATION.cff). The DOI is minted:
[10.5281/zenodo.23797526](https://doi.org/10.5281/zenodo.23797526).

## License

Apache-2.0 — see [`LICENSE`](LICENSE). The patent grant is deliberate: this
project intends to participate in standardization (ISO/IEC 42001 evidence
surface, OWASP ASI mapping, ATLAS-style taxonomies), not to weaponize
exclusivity.
