# v1.1.1 — zero-dependency signing

Ed25519 is now implemented **in-module, pure standard library** (RFC 8032).
`manifest_tool.py` previously hard-required the third-party `cryptography`
package at import time — which also failed the gate on bare interpreters.
The published zero-dependency claim now matches the code: no pip, no
network, anywhere in the stack.

- `python manifest_tool.py ed25519-vectors` (new, CI-enforced): RFC 8032
  test vectors, tamper rejection, and PKCS8 interop with keys written by
  the `cryptography` package.
- Existing keys (`roe_signing.pem` / `roe_signing.pub`) load unchanged.
- Signatures are byte-identical to RFC-conformant implementations
  (differential-tested: 100 random keys × 5 assertions, all green).
- The 38-case corpus replay is byte-identical to v1.1.0 — the only delta in
  replay output is the version string. Digest semantics untouched.
- Docs scrub in the same pass: stale `pip install cryptography` docstring
  guidance removed from `roe_gate.py` and `agent_roe.py` (neither module
  imports it — that was the false claim's residue); `roe_gate.py`'s
  tested-Python note now matches the CI matrix (3.9+); README cites the
  minted Zenodo DOI. No code paths touched.

The v1.1.0 table below remains the verified numbers; CI re-proves all of it
on every push, now including the vectors.

---

# v1.1.0 — first public release

**consent-substrate** — signed authorization and witness boundaries for LLM
agents. Companion software for the preprint *Detected or Proven: Signed
Witness Boundaries Against Quiet-Class Compromise of LLM Agents*
(`paper/detected-or-proven-preprint.pdf`).

## What ships

- **`manifest_tool.py`** — Ed25519-signed scope manifests (keygen, example,
  sign, verify, export-schema). Deny-by-default starts here: no manifest,
  no run.
- **`roe_gate.py`** — the runtime gate. Fail-closed on bad signature, parse
  error, or expiry; per-target capability lists; kill switch; hash-chained
  audit log that records refusals with the same care as allows.
- **`agent_roe.py`** — reference integration: three enforcement points
  (startup, every tool call, in-band denial observations).
- **`gate_bootstrap.py`** — one-time, idempotent consent setup for a lab
  machine.
- **`patch_agent.py`** — idempotent, reversible enforcement-point installer
  for an existing agent.
- **`canary_skill.py` v1.1.0** — injection canary: 38-case corpus, three shim
  boundaries (user / observation / args), quiet-class tripwires, optional
  on-disk bait materialization (`--materialize`), digest-only signed witness
  chain pegged to the gate's chain head.
- **`schema/scope_manifest.schema.json`** — JSON Schema, byte-identical to
  `manifest_tool.py export-schema` output (CI-enforced).

## Verified numbers (CI runs all of this on every push)

| Check | Result |
|---|---|
| Gate self-test | 21/21 |
| Canary corpus + chain self-test | 38/38 (66/66 boundary scans, 0 mismatches) |
| Benign false positives | 0 |
| Loud / quiet / trip detection | 10/10, 14/14, 3/3 |
| Rules exercised | 21/21 |
| ASI01–ASI10 attack coverage | all 10 categories present |
| Manifest roundtrip (keygen→sign→verify) | green |
| Schema export vs shipped schema | byte-identical |

New in v1.1.0 over v1.0.0: q13 browser-credential-store probe, q14
boot-persistence probe (corpus 36→38, scans 64→66), `--materialize`
physical decoys for C2, and the materialize event appended to the witness
chain.

## Reproduce

```bash
python roe_gate.py --self-test        # 21/21
python canary_skill.py --selftest     # 38/38
```

Zero third-party dependencies, zero network calls. Python 3.9–3.13 (CI
matrix). The witness chain is a pure function of the rule set: a re-run
must reproduce the exact chain digest — the v1.0.0 corpus pair
(`f9181d99…95656`) is the worked example in the paper; the v1.1.0 pair is
sealed on lab hardware and published with this release.

## Paper

*Detected or Proven: Signed Witness Boundaries Against Quiet-Class
Compromise of LLM Agents* — full threat model (the quiet class, four
unavoidable contact points, four asymmetries), design, 38-case replay
methodology, results, and **Appendix A: third-party reproduction
protocol**.

## License

Apache-2.0.

## Seal — independent reproduction

Sealed on bare-metal lab hardware (Android/Termux, stdlib-only Python, no
pip): the deterministic 38-case / 66-scan boundary replay produced an
identical results digest from two independent chain states — a fresh
unsigned dry chain (52 entries) and the signed production chain (51 prior
entries; slice seq 51–101; 102/102 signed; verify-log clean):
`8a9bad9c3eee3c4ca6daf33e766d9a6d429b0b8922811ae3878760a1458c5c3d`.
Independently reproduced on a second, unrelated device (laptop, --dry):
identical. Differs from the v1.0.0 exhibit `f9181d99…95656` exactly as the
corpus growth (36→38 cases, 64→66 scans, materialize class) predicts.
Ed25519 (RFC 8032, in-module): vectors 14/14, PKCS8 interop with keys
written by the `cryptography` package. Divergence remains a finding.
