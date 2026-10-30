#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gate_bootstrap.py -- one-time consent setup for the phone lab.

Creates (idempotently), under ~/roe/ (override with ROE_DIR env var):
    keys/roe_signing.pem       KEEP PRIVATE -- signing happens here, never
                               on the agent's behalf at runtime
    keys/roe_signing.pub
    signed_manifest.json       30-day lab RoE covering exactly what this
                               agent legitimately needs:
                                 - DuckDuckGo HTML search endpoint
                                 - your configured model API (AGENT_API_URL)
                                 - loopback 127.0.0.0/8 (your lab targets)
    roe_audit.jsonl            written by the gate at first run (hash chain)

Usage:
    python gate_bootstrap.py            # set up, or print status if done
    python gate_bootstrap.py --renew    # rotate: fresh 30-day window, same key

If you change AGENT_API_URL, run --renew so the manifest covers the new
endpoint. The gate will otherwise deny the model call -- by design.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from manifest_tool import (CORE_FORBIDDEN, generate_keypair, iso,
                           parse_iso, sign_manifest, verify_manifest)

DEFAULT_API_URL = "https://api.groq.com/openai/v1/chat/completions"
VALIDITY_DAYS = 30


def roe_dir() -> str:
    return os.environ.get("ROE_DIR",
                          os.path.join(os.path.expanduser("~"), "roe"))


def paths() -> dict:
    d = roe_dir()
    return {
        "dir": d,
        "keys": os.path.join(d, "keys"),
        "priv": os.path.join(d, "keys", "roe_signing.pem"),
        "pub": os.path.join(d, "keys", "roe_signing.pub"),
        "manifest": os.path.join(d, "signed_manifest.json"),
        "audit": os.path.join(d, "roe_audit.jsonl"),
    }


def model_api_base() -> str:
    url = os.environ.get("AGENT_API_URL", DEFAULT_API_URL)
    return url.rsplit("/chat/completions", 1)[0]


def build_lab_manifest() -> dict:
    """The lab RoE: search + model API + loopback. Nothing else. No
    wildcards -- a manifest that names everything authorizes nothing."""
    now = datetime.now(timezone.utc)
    return {
        "manifest_version": "1.0",
        "manifest_id": str(uuid.uuid4()),
        "issuer": {"org": "Local Phone Lab", "contact": "operator@localhost"},
        "subject": {"agent_id": "tree-search-agent@phone",
                    "operator": "owner"},
        "validity": {"not_before": iso(now),
                     "not_after": iso(now + timedelta(days=VALIDITY_DAYS))},
        "targets": [
            {"type": "url_prefix",
             "value": "https://html.duckduckgo.com/html/",
             "allowed_actions": ["read_public"],
             "rate_limit": {"requests_per_minute": 10,
                            "max_concurrent": 1}},
            {"type": "url_prefix", "value": model_api_base(),
             "allowed_actions": ["read_public"],
             "rate_limit": {"requests_per_minute": 30,
                            "max_concurrent": 2}},
            {"type": "ip_cidr", "value": "127.0.0.0/8",
             "allowed_actions": ["read_public", "probe", "fingerprint"],
             "rate_limit": {"requests_per_minute": 120,
                            "max_concurrent": 4}},
        ],
        "rules_of_engagement": {
            "forbidden_actions": sorted(CORE_FORBIDDEN),
            "max_concurrent": 4,
            "data_handling": "evidence_hashed",
            "retention_days": 30,
            "escalation_contact": "operator@localhost",
        },
        "bug_bounty": None,
    }


def print_status() -> int:
    p = paths()
    if not os.path.exists(p["manifest"]):
        print("No signed manifest at %s" % p["manifest"])
        print("Run: python gate_bootstrap.py")
        return 1
    with open(p["manifest"], "r", encoding="utf-8") as f:
        signed = json.load(f)
    ok, why = verify_manifest(signed, p["pub"])
    if not ok:
        print("MANIFEST INVALID (%s) -- run: python gate_bootstrap.py --renew" % why)
        return 1
    na = parse_iso(signed["validity"]["not_after"])
    days_left = (na - datetime.now(timezone.utc)).total_seconds() / 86400.0
    print("consent dir   : %s" % p["dir"])
    print("manifest      : %s (%d target(s) in scope)"
          % (signed["manifest_id"][:8], len(signed["targets"])))
    for t in signed["targets"]:
        print("  - %-10s %s  [%s]" % (t["type"], t["value"],
                                       ", ".join(t["allowed_actions"])))
    print("expires in    : %.1f day(s)" % days_left)
    if days_left < 7:
        print("  !! renew soon: python gate_bootstrap.py --renew")
    if os.path.exists(p["audit"]):
        from roe_gate import verify_audit_log
        ok2, n, why2 = verify_audit_log(p["audit"])
        print("audit chain   : %s"
              % ("intact" if ok2 else "TAMPERED at record %s (%s)" % (n, why2)))
    else:
        print("audit chain   : no audit log yet (created on first agent run)")
    return 0


def setup(renew: bool) -> int:
    p = paths()
    os.makedirs(p["keys"], exist_ok=True)
    if not os.path.exists(p["priv"]):
        priv, pub, kid = generate_keypair(p["keys"])
        print("generated signing keypair (key_id %s)" % kid)
        print("  private: %s  <-- keep it; NEVER ship it with the agent" % priv)
    if os.path.exists(p["manifest"]) and not renew:
        return print_status()
    m = build_lab_manifest()
    signed = sign_manifest(m, p["priv"])
    ok, why = verify_manifest(signed, p["pub"])   # belt and braces
    if not ok:
        print("SELF-CHECK FAILED after signing: %s" % why)
        return 1
    if renew and os.path.exists(p["manifest"]):
        bak = p["manifest"] + ".bak"
        with open(p["manifest"], "r", encoding="utf-8") as f_in, \
                open(bak, "w", encoding="utf-8") as f_out:
            f_out.write(f_in.read())
        print("previous manifest -> %s" % bak)
    with open(p["manifest"], "w", encoding="utf-8") as f:
        json.dump(signed, f, indent=2, ensure_ascii=False)
    print("signed manifest -> %s (valid %d day(s))"
          % (p["manifest"], VALIDITY_DAYS))
    print()
    print("next steps:")
    print("  python patch_agent.py        # wire the gate into tree_search_agent")
    print("  python tree_search_agent.py  # refuses to start without the manifest")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="consent bootstrap for the phone lab")
    ap.add_argument("--renew", action="store_true",
                    help="rotate: build + sign a fresh %d-day manifest" % VALIDITY_DAYS)
    args = ap.parse_args()
    return setup(args.renew)


if __name__ == "__main__":
    sys.exit(main())
