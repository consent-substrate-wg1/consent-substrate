#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manifest_tool.py -- Consent substrate, part 1 of 2: signed scope manifests.

Track 2 of the four-track plan ("Consent substrate" -- the gate is the product).

What this is
------------
A Scope Manifest is a machine-readable Rules of Engagement (RoE) document:
who authorizes which agent, to touch which targets, with which actions,
at what rate, inside what time window, and what is forbidden.

It is signed with Ed25519. The runtime gate (roe_gate.py) verifies
signatures but cannot create them: the signing key lives with the party
that owns the targets (or their bug-bounty program), NOT on the agent host.

Design invariants (non-negotiable)
----------------------------------
1.  FAIL CLOSED: unverifiable == unauthorized. Every ambiguity, missing
    timestamp, or unreadable key resolves to DENY.
2.  NO WILDCARDS: "*", "0.0.0.0/0", "::/0" are refused at signing time.
    A manifest must NAME its targets. (Private/RFC1918 ranges are allowed
    on purpose: your lab harness is the first customer.)
3.  SHORT LIVED: maximum validity 90 days. Authorization decays.
4.  CORE PROHIBITIONS ARE STRUCTURAL: denial_of_service, credential_stuffing,
    brute_force, social_engineering, data_exfiltration, destructive_ops,
    persistence, lateral_movement can never appear in allowed_actions.
    The signer refuses, and the gate refuses even against hand-forged files.

CLI
---
  python manifest_tool.py keygen --outdir keys/
  python manifest_tool.py example --out manifest.json
  python manifest_tool.py sign manifest.json --key keys/roe_signing.pem --out signed.json
  python manifest_tool.py verify signed.json --pub keys/roe_signing.pub
  python manifest_tool.py export-schema --out scope_manifest.schema.json

Requires: cryptography      (pip install cryptography)
Tested on Termux/Android, Python 3.10+.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:
    sys.stderr.write(
        "manifest_tool.py requires 'cryptography'. Install with:\n"
        "    pip install cryptography\n"
        "Fail closed: refusing to run without it.\n"
    )
    sys.exit(1)

MANIFEST_VERSION = "1.0"
MAX_VALIDITY_DAYS = 90
SIGNATURE_ALG = "ed25519"

# The allowlist of actions a manifest can authorize. Anything not listed
# here cannot appear in allowed_actions (structural refusal at signing,
# DENY at runtime). The enum itself is the wall.
KNOWN_ACTIONS = (
    "read_public",         # fetch what an anonymous visitor can reach
    "probe",               # active existence checks (HEAD/OPTIONS, known paths)
    "fingerprint",         # identify tech, versions, headers
    "api_discovery",       # enumerate documented surface (OpenAPI, robots, docs)
    "authenticated_scan",  # scan with credentials the OWNER provided (by handle)
    "injection_test",      # benign canary payloads; detect reflection/handling
    "exploit_poc",         # minimal PoC; needs poc_consent + bug_bounty block
)

# Structural prohibitions: NEVER authorizable by any manifest. They are
# absent from KNOWN_ACTIONS on purpose.
CORE_FORBIDDEN = frozenset({
    "denial_of_service",
    "credential_stuffing",
    "brute_force",
    "social_engineering",
    "data_exfiltration",
    "destructive_ops",
    "persistence",          # no implants, no backdoors, no dead-man switches
    "lateral_movement",
})

# Pragmatic hostname check: 2+ labels, no wildcards, no spaces.
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_URLISH_RE = re.compile(r"^https?://[a-z0-9.\-]+(:\d+)?(/.*)?$")


# --------------------------------------------------------------------------
# Canonicalization & time helpers
# --------------------------------------------------------------------------

def canonical_json(obj) -> bytes:
    """The byte form that gets signed. Same function everywhere, forever."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(s) -> datetime:
    if not isinstance(s, str):
        raise ValueError("timestamp must be a string")
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------
# Structural validation (runs at signing AND at verification: fail closed)
# --------------------------------------------------------------------------

def _check_target(i: int, t, manifest: dict) -> list:
    p = f"targets[{i}]"
    if not isinstance(t, dict):
        return [f"{p}: must be an object"]
    errs = []
    ttype = t.get("type")
    if ttype not in ("domain", "url_prefix", "ip_cidr", "app_package"):
        return [f"{p}: unknown target type {ttype!r}"]
    val = t.get("value")
    if not isinstance(val, str) or not val.strip():
        return [f"{p}: value required"]
    val = val.strip()

    if ttype == "domain":
        d = val.lower().rstrip(".")
        if "*" in d:
            errs.append(f"{p}: wildcard domains refused ({val!r}); name your targets")
        elif not _DOMAIN_RE.match(d):
            errs.append(f"{p}: not a plausible hostname: {val!r}")
    elif ttype == "url_prefix":
        if "*" in val:
            errs.append(f"{p}: wildcards refused in url_prefix")
        elif not _URLISH_RE.match(val.lower()):
            errs.append(f"{p}: url_prefix must look like https://host[/prefix]")
    elif ttype == "ip_cidr":
        try:
            net = ipaddress.ip_network(val, strict=False)
            if net.prefixlen == 0:
                errs.append(f"{p}: global wildcard CIDR refused ({val})")
        except ValueError as e:
            errs.append(f"{p}: invalid CIDR {val!r}: {e}")

    actions = t.get("allowed_actions")
    if not isinstance(actions, list) or not actions:
        errs.append(f"{p}: allowed_actions must be a non-empty list")
    else:
        unknown = [a for a in actions if a not in KNOWN_ACTIONS]
        if unknown:
            errs.append(f"{p}: unknown action(s) {unknown} -- allowlist is: "
                        + ", ".join(KNOWN_ACTIONS))
        banned = CORE_FORBIDDEN.intersection(actions)
        if banned:
            errs.append(f"{p}: action(s) {sorted(banned)} can never be authorized (structural)")
        if "exploit_poc" in actions:
            if not t.get("poc_consent"):
                errs.append(f"{p}: exploit_poc requires poc_consent: true on this target")
            if not isinstance(manifest.get("bug_bounty"), dict):
                errs.append(f"{p}: exploit_poc requires a bug_bounty block on the manifest")

    rl = t.get("rate_limit")
    if rl is not None:
        if not isinstance(rl, dict) or not rl:
            errs.append(f"{p}: rate_limit must be a non-empty object")
        else:
            rpm = rl.get("requests_per_minute")
            if rpm is not None and (not isinstance(rpm, int) or rpm < 1):
                errs.append(f"{p}: requests_per_minute must be a positive integer")
            mc = rl.get("max_concurrent")
            if mc is not None and (not isinstance(mc, int) or mc < 1):
                errs.append(f"{p}: max_concurrent must be a positive integer")
    return errs


def structural_check(m) -> list:
    """Returns a list of error strings; empty list == structurally valid."""
    if not isinstance(m, dict):
        return ["manifest must be a JSON object"]
    errs = []
    if m.get("manifest_version") != MANIFEST_VERSION:
        errs.append(f"manifest_version must be '{MANIFEST_VERSION}'")
    mid = m.get("manifest_id")
    if not isinstance(mid, str) or len(mid) < 8:
        errs.append("manifest_id must be a string of >= 8 chars (uuid recommended)")

    issuer = m.get("issuer")
    if not isinstance(issuer, dict) or not issuer.get("org") or not issuer.get("contact"):
        errs.append("issuer.{org,contact} required -- authorization must name a human")
    subject = m.get("subject")
    if not isinstance(subject, dict) or not subject.get("agent_id"):
        errs.append("subject.agent_id required -- the gate binds to a named agent")

    v = m.get("validity")
    if not isinstance(v, dict):
        errs.append("validity{not_before,not_after} required")
    else:
        try:
            nb = parse_iso(v.get("not_before"))
            na = parse_iso(v.get("not_after"))
            if na <= nb:
                errs.append("validity: not_after must be after not_before")
            elif (na - nb) > timedelta(days=MAX_VALIDITY_DAYS):
                errs.append(f"validity exceeds MAX_VALIDITY_DAYS={MAX_VALIDITY_DAYS}")
        except (ValueError, TypeError) as e:
            errs.append(f"validity timestamps invalid: {e}")

    targets = m.get("targets")
    if not isinstance(targets, list) or not targets:
        errs.append("targets must be a non-empty list")
    else:
        for i, t in enumerate(targets):
            errs.extend(_check_target(i, t, m))

    roe = m.get("rules_of_engagement")
    if not isinstance(roe, dict):
        errs.append("rules_of_engagement required")
    else:
        fa = roe.get("forbidden_actions")
        if not isinstance(fa, list):
            errs.append("rules_of_engagement.forbidden_actions must be a list")
        else:
            missing = CORE_FORBIDDEN - set(fa)
            if missing:
                errs.append("forbidden_actions must explicitly include the core set: "
                            + ", ".join(sorted(missing)))
        dh = roe.get("data_handling", "evidence_hashed")
        if dh not in ("metadata_only", "evidence_hashed", "full_capture"):
            errs.append("data_handling must be metadata_only|evidence_hashed|full_capture")
    return errs


# --------------------------------------------------------------------------
# Keys
# --------------------------------------------------------------------------

def key_id_from_pub(raw_pub: bytes) -> str:
    return hashlib.sha256(raw_pub).hexdigest()[:16]


def generate_keypair(outdir: str):
    """Writes roe_signing.pem (chmod 600) + roe_signing.pub. Refuses overwrite."""
    os.makedirs(outdir, exist_ok=True)
    priv_path = os.path.join(outdir, "roe_signing.pem")
    pub_path = os.path.join(outdir, "roe_signing.pub")
    if os.path.exists(priv_path):
        raise SystemExit(f"refusing to overwrite existing key: {priv_path}")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    with open(priv_path, "wb") as f:
        f.write(pem)
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass
    with open(pub_path, "wb") as f:
        f.write(pub_raw)
    return priv_path, pub_path, key_id_from_pub(pub_raw)


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path_or_bytes):
    if isinstance(path_or_bytes, (bytes, bytearray)):
        return Ed25519PublicKey.from_public_bytes(bytes(path_or_bytes))
    with open(path_or_bytes, "rb") as f:
        blob = f.read()
    try:
        return serialization.load_pem_public_key(blob)
    except ValueError:
        return Ed25519PublicKey.from_public_bytes(blob)


# --------------------------------------------------------------------------
# Sign / verify
# --------------------------------------------------------------------------

def sign_manifest(manifest: dict, key_path: str) -> dict:
    if "signature" in manifest:
        raise SystemExit("manifest already carries a signature; refuse to re-sign")
    errs = structural_check(manifest)
    if errs:
        raise SystemExit("refusing to sign an invalid manifest:\n  - "
                         + "\n  - ".join(errs))
    priv = load_private_key(key_path)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = priv.sign(canonical_json(manifest))
    out = dict(manifest)
    out["signature"] = {
        "alg": SIGNATURE_ALG,
        "key_id": key_id_from_pub(pub_raw),
        "sig": base64.b64encode(sig).decode("ascii"),
    }
    return out


def verify_manifest(signed, pubkey) -> tuple:
    """Returns (ok, reason). ok=True means: structurally valid AND the
    signature covers exactly this structural content."""
    if not isinstance(signed, dict):
        return False, "manifest must be a JSON object"
    sigblk = signed.get("signature")
    if not isinstance(sigblk, dict):
        return False, "missing signature block"
    body = {k: v for k, v in signed.items() if k != "signature"}
    errs = structural_check(body)
    if errs:
        return False, "structural: " + "; ".join(errs)
    if sigblk.get("alg") != SIGNATURE_ALG:
        return False, f"unsupported alg {sigblk.get('alg')!r}"
    try:
        raw = base64.b64decode(sigblk.get("sig", ""), validate=True)
    except Exception:
        return False, "signature is not valid base64"
    try:
        pub = pubkey if isinstance(pubkey, Ed25519PublicKey) else load_public_key(pubkey)
    except Exception as e:
        return False, f"cannot load public key: {e}"
    try:
        pub.verify(raw, canonical_json(body))
    except InvalidSignature:
        return False, "Ed25519 signature INVALID -- content does not match key"
    except Exception as e:
        return False, f"verification error: {e}"
    return True, "ok"


# --------------------------------------------------------------------------
# Example manifest (the lab scenario -- your own agents are target #1)
# --------------------------------------------------------------------------

def build_example_manifest(quiet_hours: bool = True) -> dict:
    now = datetime.now(timezone.utc)
    roe = {
        "forbidden_actions": sorted(CORE_FORBIDDEN),
        "max_concurrent": 4,
        "data_handling": "evidence_hashed",
        "retention_days": 30,
        "escalation_contact": "oncall@example-labs.test",
    }
    if quiet_hours:
        roe["quiet_hours"] = {"start": "23:00", "end": "06:00", "tz": "UTC"}
    return {
        "manifest_version": MANIFEST_VERSION,
        "manifest_id": str(uuid.uuid4()),
        "issuer": {"org": "Example Labs, LLC",
                   "contact": "security@example-labs.test"},
        "subject": {"agent_id": "tree-search-agent@lab",
                    "operator": "researcher@localhost"},
        "validity": {"not_before": iso(now),
                     "not_after": iso(now + timedelta(days=30))},
        "targets": [
            {"type": "domain", "value": "lab.internal", "include_subdomains": True,
             "allowed_actions": ["read_public", "probe", "fingerprint",
                                 "api_discovery", "authenticated_scan"],
             "rate_limit": {"requests_per_minute": 60, "max_concurrent": 2}},
            {"type": "url_prefix", "value": "https://api.lab.internal/v1",
             "allowed_actions": ["read_public", "probe", "injection_test"],
             "rate_limit": {"requests_per_minute": 30, "max_concurrent": 1}},
            {"type": "ip_cidr", "value": "10.0.5.0/24",
             "allowed_actions": ["probe", "fingerprint"],
             "rate_limit": {"requests_per_minute": 120, "max_concurrent": 4}},
        ],
        "rules_of_engagement": roe,
        "bug_bounty": None,
    }


# --------------------------------------------------------------------------
# Published JSON Schema (draft 2020-12) -- the standardization artifact
# --------------------------------------------------------------------------

def build_json_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://your-org.example/schemas/scope-manifest-1.0.json",
        "title": "Agent Scope Manifest v1.0",
        "description": ("Signed rules of engagement for autonomous agents. "
                        "Fail-closed: anything not described here is denied."),
        "type": "object",
        "required": ["manifest_version", "manifest_id", "issuer", "subject",
                     "validity", "targets", "rules_of_engagement", "signature"],
        "additionalProperties": False,
        "properties": {
            "manifest_version": {"const": "1.0"},
            "manifest_id": {"type": "string", "minLength": 8},
            "issuer": {
                "type": "object", "required": ["org", "contact"],
                "additionalProperties": False,
                "properties": {"org": {"type": "string"},
                               "contact": {"type": "string"}}},
            "subject": {
                "type": "object", "required": ["agent_id"],
                "additionalProperties": False,
                "properties": {"agent_id": {"type": "string"},
                               "operator": {"type": "string"}}},
            "validity": {
                "type": "object", "required": ["not_before", "not_after"],
                "additionalProperties": False,
                "properties": {
                    "not_before": {"type": "string", "format": "date-time"},
                    "not_after": {"type": "string", "format": "date-time"}}},
            "targets": {"type": "array", "minItems": 1,
                        "items": {"$ref": "#/$defs/target"}},
            "rules_of_engagement": {"$ref": "#/$defs/roe"},
            "bug_bounty": {
                "type": ["object", "null"],
                "additionalProperties": False,
                "properties": {
                    "program_id": {"type": "string"},
                    "platform": {"type": "string"},
                    "policy_url": {"type": "string", "format": "uri"}}},
            "signature": {"$ref": "#/$defs/signature"},
        },
        "$defs": {
            "target": {
                "type": "object",
                "required": ["type", "value", "allowed_actions"],
                "additionalProperties": False,
                "properties": {
                    "type": {"enum": ["domain", "url_prefix", "ip_cidr",
                                       "app_package"]},
                    "value": {"type": "string", "minLength": 1},
                    "allowed_actions": {"type": "array", "minItems": 1,
                                        "items": {"enum": list(KNOWN_ACTIONS)}},
                    "include_subdomains": {"type": "boolean"},
                    "poc_consent": {"type": "boolean"},
                    "rate_limit": {
                        "type": "object", "additionalProperties": False,
                        "properties": {
                            "requests_per_minute": {"type": "integer",
                                                     "minimum": 1},
                            "max_concurrent": {"type": "integer",
                                                "minimum": 1}}}}},
            "roe": {
                "type": "object", "required": ["forbidden_actions"],
                "additionalProperties": False,
                "properties": {
                    "forbidden_actions": {"type": "array",
                                           "items": {"type": "string"}},
                    "max_concurrent": {"type": "integer", "minimum": 1},
                    "quiet_hours": {
                        "type": "object", "required": ["start", "end"],
                        "additionalProperties": False,
                        "properties": {"start": {"type": "string"},
                                        "end": {"type": "string"},
                                        "tz": {"type": "string",
                                                "default": "UTC"}}},
                    "data_handling": {"enum": ["metadata_only",
                                                "evidence_hashed",
                                                "full_capture"]},
                    "retention_days": {"type": "integer", "minimum": 0},
                    "escalation_contact": {"type": "string"}}},
            "signature": {
                "type": "object", "required": ["alg", "key_id", "sig"],
                "additionalProperties": False,
                "properties": {"alg": {"const": "ed25519"},
                                "key_id": {"type": "string"},
                                "sig": {"type": "string"}}},
        },
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Signed scope manifests (consent substrate, part 1)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="generate an Ed25519 signing keypair")
    p.add_argument("--outdir", default="keys")

    p = sub.add_parser("example", help="write an example (unsigned) manifest")
    p.add_argument("--out", default="manifest.json")

    p = sub.add_parser("sign", help="validate + sign a manifest")
    p.add_argument("manifest")
    p.add_argument("--key", required=True)
    p.add_argument("--out", default="signed.json")

    p = sub.add_parser("verify", help="verify a signed manifest")
    p.add_argument("signed")
    p.add_argument("--pub", required=True)

    p = sub.add_parser("export-schema", help="write the JSON Schema file")
    p.add_argument("--out", default="scope_manifest.schema.json")

    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        priv, pub, kid = generate_keypair(args.outdir)
        print(f"private key : {priv}  (keep OFF the agent host)")
        print(f"public key  : {pub}")
        print(f"key_id      : {kid}")
        return 0

    if args.cmd == "example":
        m = build_example_manifest()
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(m, f, indent=2, ensure_ascii=False)
        print(f"wrote {args.out}  (next: sign it with `sign {args.out} --key ...`)")
        return 0

    if args.cmd == "sign":
        with open(args.manifest, "r", encoding="utf-8") as f:
            m = json.load(f)
        signed = sign_manifest(m, args.key)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(signed, f, indent=2, ensure_ascii=False)
        print(f"signed -> {args.out} (key_id {signed['signature']['key_id']})")
        return 0

    if args.cmd == "verify":
        with open(args.signed, "r", encoding="utf-8") as f:
            signed = json.load(f)
        ok, why = verify_manifest(signed, args.pub)
        if ok:
            print(f"VERIFIED: manifest {signed.get('manifest_id')} "
                  f"({len(signed.get('targets', []))} targets in scope)")
            return 0
        print(f"REJECTED: {why}")
        return 1

    if args.cmd == "export-schema":
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(build_json_schema(), f, indent=2, ensure_ascii=False)
        print(f"wrote {args.out}")
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
