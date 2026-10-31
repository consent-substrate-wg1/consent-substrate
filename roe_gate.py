#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
roe_gate.py -- Consent substrate, part 2 of 2: the runtime gate.

THE RULE: an agent must be able to prove, at call time, that each action it
is about to take is covered by a signed, unexpired scope manifest.
If it cannot prove it, the action does not happen. No manifest, no run.

Integration with tree_search_agent.py (or any agent loop):

    from roe_gate import Gate, NoManifestError, GateViolation

    gate = Gate.load("signed_manifest.json", pubkey="keys/roe_signing.pub")
    #   ^ raises NoManifestError if missing/unreadable/tampered:
    #     an agent that cannot prove its authorization refuses to start.

    # Before EVERY side-effecting tool call:
    try:
        gate.authorize("read_public", url)
        do_the_thing(url)
    except GateViolation as e:
        obs = f"[GATE DENY] {e.decision.rule}: {e.decision.reason}"

    # For scans that hold a connection open, use a session so concurrency
    # limits are enforced:
    with gate.session("probe", "10.0.5.17"):
        probe_host("10.0.5.17")

    # Or the non-raising form:
    decision = gate.check("fingerprint", "https://api.lab.internal/v1")
    if not decision.allowed: ...

What the gate enforces (in evaluation order)
--------------------------------------------
* gate seal                     (any internal failure seals all future calls)
* core prohibitions             (structurally forbidden actions, runtime too)
* action allowlist              (unknown action == DENY; never wildcard)
* target membership             (most-specific match wins; unknown == DENY)
* manifest validity window      (not_before / not_after, UTC)
* quiet hours                   (timezone-aware; unevaluatable tz == DENY)
* rate limits per target        (requests_per_minute, conservative default)
* concurrency per target        (via `with gate.session(...)`)
* tamper-evident audit log      (hash-chained JSONL; verify with --verify-log)

Failure posture: every error path resolves to DENY. If the audit log becomes
unwritable, the gate seals itself -- silent agents are how abuse hides.

CLI
---
  python roe_gate.py --self-test        # 21-test battery, exits non-zero on FAIL
  python roe_gate.py --verify-log roe_audit.jsonl

Termux setup:
    pkg install tzdata   # only needed for quiet hours outside UTC
    (no pip installs: Ed25519 is pure stdlib since v1.1.1)

Tested on Termux/Android, Python 3.9+.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import uuid
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, time as dtime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from manifest_tool import (CORE_FORBIDDEN, KNOWN_ACTIONS, canonical_json,
                           generate_keypair, iso, parse_iso, sign_manifest,
                           build_example_manifest, verify_manifest)

try:
    from zoneinfo import ZoneInfo
except ImportError:            # pragma: no cover
    ZoneInfo = None


DEFAULT_RPM = 60               # applied when a target omits rate_limit
DEFAULT_MAX_CONCURRENT = 1     # applied when a target omits max_concurrent
GENESIS = "0" * 64


# --------------------------------------------------------------------------
# Decisions & exceptions
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    rule: str            # seal|core|action|target_match|action_scope|
                         # time_window|quiet_hours|rate_limit|concurrency
    action: str = ""
    target: str = ""
    manifest_id: str = ""
    scope_key: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class GateViolation(PermissionError):
    def __init__(self, decision: Decision):
        super().__init__(f"[{decision.rule}] {decision.reason}")
        self.decision = decision


class NoManifestError(RuntimeError):
    """Raised by Gate.load when there is no usable manifest. An agent that
    cannot prove its authorization must refuse to start."""


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------

class Gate:
    _URL_RE = re.compile(r"^https?://([^/:?#]+)(?::\d+)?([^?#]*)?$")
    _SPECIFICITY = {"url_prefix": 3, "domain": 2, "ip_cidr": 1,
                    "app_package": 1}

    # -- construction ------------------------------------------------------

    def __init__(self, signed_manifest: dict, pubkey, audit_log=None):
        self._init_runtime(audit_log)
        ok, reason = verify_manifest(signed_manifest, pubkey)
        if not ok:
            self._seal(f"manifest rejected: {reason}")
            return
        self._manifest = signed_manifest
        self._manifest_id = signed_manifest.get("manifest_id", "none")
        self._targets = signed_manifest.get("targets", [])
        self._roe = signed_manifest.get("rules_of_engagement", {})

    @classmethod
    def load(cls, path: str, pubkey, audit_log=None) -> "Gate":
        if not os.path.exists(path):
            raise NoManifestError(
                f"no scope manifest at {path!r}: an agent without RoE "
                "must refuse to run")
        try:
            with open(path, "r", encoding="utf-8") as f:
                signed = json.load(f)
        except Exception as e:
            raise NoManifestError(f"unreadable manifest: {e}")
        g = cls(signed, pubkey, audit_log=audit_log)
        if g.is_sealed:
            # Tampered/invalid: refuse to start rather than hand back a
            # zombie gate. Fail closed, loudly.
            raise NoManifestError(g._sealed_reason)
        return g

    @classmethod
    def sealed(cls, reason: str) -> "Gate":
        g = cls.__new__(cls)
        g._init_runtime(None)
        g._seal(f"sealed: {reason}")
        return g

    def _init_runtime(self, audit_log):
        self._manifest = None
        self._manifest_id = "none"
        self._targets = []
        self._roe = {}
        self._buckets = {}
        self._active = {}
        self._seq = 0
        self._prev_hash = GENESIS
        self._memlog = deque(maxlen=4096)
        self._audit_path = audit_log
        self._sealed_reason = None

    def _seal(self, reason: str):
        self._sealed_reason = reason

    @property
    def is_sealed(self) -> bool:
        return self._sealed_reason is not None

    @property
    def manifest_id(self) -> str:
        return self._manifest_id

    # -- public API --------------------------------------------------------

    def check(self, action: str, target: str, *,
              now: datetime = None) -> Decision:
        d = self._evaluate(action, target, now)
        self._audit(d)
        return d

    def authorize(self, action: str, target: str, *,
                  now: datetime = None) -> Decision:
        d = self.check(action, target, now=now)
        if not d.allowed:
            raise GateViolation(d)
        return d

    @contextmanager
    def session(self, action: str, target: str):
        """authorize + hold one concurrency slot for the scope."""
        d = self.authorize(action, target)
        entry, _ = self._match(target)
        limit = ((entry or {}).get("rate_limit") or {}).get(
            "max_concurrent") or DEFAULT_MAX_CONCURRENT
        key = d.scope_key
        cur = self._active.get(key, 0)
        if cur >= limit:
            v = Decision(False, "concurrency limit exceeded for this scope",
                         "concurrency", action, target, self._manifest_id)
            self._audit(v)
            raise GateViolation(v)
        self._active[key] = cur + 1
        try:
            yield d
        finally:
            self._active[key] = max(0, self._active.get(key, 1) - 1)

    def note_denial(self, action: str, target: str, reason: str, rule: str) -> Decision:
        """Record an out-of-band denial (e.g. from the EXECUTE_PYTHON shim)
        in the hash-chained audit log WITHOUT evaluating it. Audit fidelity:
        the recorder must show WHY, not just THAT."""
        d = Decision(False, reason, rule, action, target, self._manifest_id)
        self._audit(d)
        return d

    def report(self) -> dict:
        allows = sum(1 for r in self._memlog if r["decision"] == "ALLOW")
        return {"manifest_id": self._manifest_id,
                "sealed": self.is_sealed,
                "sealed_reason": self._sealed_reason,
                "targets_in_scope": len(self._targets),
                "decisions_seen": len(self._memlog),
                "allowed": allows,
                "denied": len(self._memlog) - allows}

    # -- decision engine ---------------------------------------------------

    def _deny(self, action, target, reason, rule, now=None) -> Decision:
        return Decision(False, reason, rule, action, target,
                        self._manifest_id)

    def _evaluate(self, action, target, now) -> Decision:
        now = now or datetime.now(timezone.utc)
        if self._sealed_reason:
            return self._deny(action, target, self._sealed_reason, "seal")
        if not isinstance(action, str) or not action:
            return self._deny(action, target, "malformed action", "action")
        if action in CORE_FORBIDDEN:
            return self._deny(
                action, target,
                f"{action} is structurally forbidden (core prohibitions)",
                "core")
        if action not in KNOWN_ACTIONS:
            return self._deny(
                action, target,
                f"unknown action {action!r}: the gate is allowlist-only",
                "action")
        entry, how = self._match(target)
        if entry is None:
            return self._deny(action, target,
                              "target not in scope of any manifest entry",
                              "target_match")
        if action not in entry.get("allowed_actions", []):
            return self._deny(
                action, target,
                f"action {action!r} not authorized for the most specific "
                f"matching scope ({how})",
                "action_scope")
        v = self._manifest.get("validity", {})
        try:
            if not (parse_iso(v["not_before"]) <= now <= parse_iso(v["not_after"])):
                return self._deny(action, target,
                                  "outside manifest validity window",
                                  "time_window")
        except Exception as e:
            return self._deny(action, target, f"validity unreadable: {e}",
                              "time_window")
        qh = self._roe.get("quiet_hours")
        if qh and self._in_quiet_hours(qh, now):
            return self._deny(action, target, "quiet hours in effect",
                              "quiet_hours")
        if not self._admit_rate(entry, now):
            return self._deny(action, target,
                              "rate limit exceeded for this scope",
                              "rate_limit")
        return Decision(
            True, f"authorized via {how}", how.split(":")[0],
            action, target, self._manifest_id,
            scope_key=f"{entry.get('type')}:{entry.get('value')}")

    # -- target matching (most specific wins) -------------------------------

    def _match(self, target: str):
        """Return (entry, how) for the MOST SPECIFIC matching scope, or
        (None, 'no-match'). Specificity: url_prefix > domain > ip_cidr >
        app_package; ties broken by longer value (longest-prefix semantics)."""
        t = str(target).strip().lower().rstrip(".")
        m = self._URL_RE.match(t)
        host, path = (m.group(1), (m.group(2) or "/")) if m else (None, None)
        best, best_how, best_rank = None, "no-match", (-1, -1)
        for e in self._targets:
            et = e.get("type")
            val = str(e.get("value", "")).strip().lower()
            how = None
            if et == "url_prefix" and host is not None:
                um = self._URL_RE.match(val)
                if um and host == um.group(1):
                    epath = um.group(2) or "/"
                    if path == epath or epath == "/" or \
                            path.startswith(epath.rstrip("/") + "/"):
                        how = "url_prefix"
            elif et == "domain":
                dv = val.rstrip(".")
                if host is not None:
                    if host == dv or (e.get("include_subdomains")
                                      and host.endswith("." + dv)):
                        how = "domain"
                elif t == dv or (e.get("include_subdomains")
                                 and t.endswith("." + dv)):
                    how = "domain"
            elif et == "ip_cidr":
                try:
                    ip = ipaddress.ip_address(host or t)
                    if ip in ipaddress.ip_network(e.get("value"),
                                                  strict=False):
                        how = "ip_cidr"
                except ValueError:
                    pass
            elif et == "app_package" and t == val:
                how = "app_package"
            if how:
                rank = (self._SPECIFICITY.get(how, 0), len(val))
                if rank > best_rank:
                    best, best_how, best_rank = e, f"{how}:{val}", rank
        return best, best_how

    # -- rate limiting (token-ish bucket per scope) --------------------------

    def _admit_rate(self, entry, now: datetime) -> bool:
        rl = entry.get("rate_limit") or {}
        rpm = rl.get("requests_per_minute") or DEFAULT_RPM
        key = ("rate", entry.get("type"), str(entry.get("value")))
        dq = self._buckets.setdefault(key, deque())
        cutoff = now - timedelta(minutes=1)
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if len(dq) >= rpm:
            return False
        dq.append(now)
        return True

    # -- quiet hours (fail closed on any evaluation problem) -----------------

    @staticmethod
    def _in_quiet_hours(qh, now: datetime) -> bool:
        if ZoneInfo is None:
            return True                     # cannot evaluate -> treat as quiet
        try:
            tz = ZoneInfo(qh.get("tz", "UTC"))
            start = dtime.fromisoformat(str(qh["start"]))
            end = dtime.fromisoformat(str(qh["end"]))
        except Exception:
            return True                     # malformed window -> fail closed
        local = now.astimezone(tz).time()
        if start <= end:
            return start <= local <= end
        return local >= start or local <= end   # overnight window

    # -- tamper-evident audit log (hash chain) -------------------------------

    def _audit(self, d: Decision):
        self._seq += 1
        rec = {
            "seq": self._seq,
            "ts": iso(datetime.now(timezone.utc)),
            "decision": "ALLOW" if d.allowed else "DENY",
            "rule": d.rule,
            "reason": d.reason,
            "action": d.action,
            "target": d.target,
            "manifest_id": d.manifest_id,
            "prev": self._prev_hash,
        }
        rec["hash"] = hashlib.sha256(canonical_json(rec)).hexdigest()
        self._prev_hash = rec["hash"]
        self._memlog.append(rec)
        if self._audit_path:
            try:
                with open(self._audit_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False,
                                       separators=(",", ":")) + "\n")
            except OSError:
                # Fail closed: if the flight recorder cannot run, the gate
                # seals itself. Silent agents are how abuse hides.
                self._seal("audit log unwritable")


def verify_audit_log(path: str):
    """Walk a hash-chained JSONL audit log. Returns (ok, bad_seq, reason)."""
    prev = GENESIS
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception as e:
                return False, n, f"unparsable line: {e}"
            if rec.get("prev") != prev:
                return False, n, "chain break (prev mismatch)"
            body = {k: v for k, v in rec.items() if k != "hash"}
            if hashlib.sha256(canonical_json(body)).hexdigest() != rec.get("hash"):
                return False, n, "hash mismatch -- record was altered"
            prev = rec["hash"]
    return True, None, "ok"


# --------------------------------------------------------------------------
# Self-test battery (21 checks; exits non-zero on any failure)
# --------------------------------------------------------------------------

def _selftest() -> int:
    base = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        ".roe_selftest")
    os.makedirs(base, exist_ok=True)
    tmp = tempfile.mkdtemp(prefix="run_", dir=base)
    results = []

    def t(name, cond, detail=""):
        results.append((name, bool(cond)))
        print(f"[{'PASS' if cond else 'FAIL'}] {name}"
              + ("" if cond else f"  -- {detail}"))

    # 1-2: crypto roundtrip + tamper detection
    priv, pub, kid = generate_keypair(tmp)
    m = build_example_manifest(quiet_hours=False)
    signed = sign_manifest(m, priv)
    ok, why = verify_manifest(signed, pub)
    t("sign+verify roundtrip", ok, why)

    bad = json.loads(json.dumps(signed))
    bad["targets"][0]["value"] = "evil.example.com"   # structurally still valid
    ok2, why2 = verify_manifest(bad, pub)
    t("tamper detection (signature)", not ok2, why2)

    # 3-11: decision engine on the example manifest
    audit_path = os.path.join(tmp, "audit.jsonl")
    gate = Gate(signed, pub, audit_log=audit_path)
    d = gate.check("read_public", "https://target.lab.internal/status")
    t("allow: read_public on in-scope subdomain", d.allowed, d.reason)
    d = gate.check("read_public", "https://evil.example.com/")
    t("deny: out-of-scope host", (not d.allowed) and d.rule == "target_match",
      d.reason)
    d = gate.check("injection_test", "https://api.lab.internal/v1/users")
    t("allow: url_prefix scope grants injection_test", d.allowed, d.reason)
    d = gate.check("injection_test", "https://api.lab.internal/v2/users")
    t("deny: outside url_prefix (most-specific wins)",
      (not d.allowed) and d.rule == "action_scope", d.reason)
    d = gate.check("social_engineering", "https://target.lab.internal/")
    t("deny: structurally forbidden action",
      (not d.allowed) and d.rule == "core", d.reason)
    d = gate.check("exploit_poc", "https://api.lab.internal/v1/users")
    t("deny: exploit_poc not in scope", not d.allowed, d.reason)
    d = gate.check("read_public", "8.8.8.8")
    t("deny: ip outside cidr", not d.allowed, d.reason)
    d = gate.check("probe", "10.0.5.17")
    t("allow: probe inside cidr", d.allowed, d.reason)
    d = gate.check("nmap_scan", "https://target.lab.internal/")
    t("deny: unknown action (allowlist-only gate)",
      (not d.allowed) and d.rule == "action", d.reason)

    # 12: rate limiting
    def fresh(body):
        now = datetime.now(timezone.utc)
        body["manifest_id"] = str(uuid.uuid4())
        body["validity"] = {"not_before": iso(now - timedelta(minutes=1)),
                            "not_after": iso(now + timedelta(days=7))}
        return sign_manifest(body, priv)

    m2 = build_example_manifest(quiet_hours=False)
    m2["targets"] = [{"type": "domain", "value": "ratelimit.lab.internal",
                      "allowed_actions": ["read_public"],
                      "rate_limit": {"requests_per_minute": 3,
                                     "max_concurrent": 4}}]
    g2 = Gate(fresh(m2), pub)
    denials = [g2.check("read_public", "https://ratelimit.lab.internal/a")
               for _ in range(5)]
    t("rate limit trips after burst",
      any((not x.allowed) and x.rule == "rate_limit" for x in denials))

    # 13: quiet hours (window built to cover 'now' whatever the clock says)
    now = datetime.now(timezone.utc)
    m3 = build_example_manifest(quiet_hours=False)
    m3["rules_of_engagement"]["quiet_hours"] = {
        "start": (now - timedelta(hours=1)).strftime("%H:%M"),
        "end": (now + timedelta(hours=1)).strftime("%H:%M"),
        "tz": "UTC"}
    g3 = Gate(fresh(m3), pub)
    d = g3.check("read_public", "https://target.lab.internal/x")
    t("deny: quiet hours in effect", (not d.allowed) and d.rule == "quiet_hours",
      d.reason)

    # 14: expired manifest (signed but stale -> every call denies)
    m4 = build_example_manifest(quiet_hours=False)
    m4["validity"] = {"not_before": iso(now - timedelta(days=2)),
                      "not_after": iso(now - timedelta(days=1))}
    m4["manifest_id"] = str(uuid.uuid4())
    g4 = Gate(sign_manifest(m4, priv), pub)
    d = g4.check("read_public", "https://target.lab.internal/x")
    t("deny: outside validity window",
      (not d.allowed) and d.rule == "time_window", d.reason)

    # 15-16: load-time refusals
    try:
        Gate.load(os.path.join(tmp, "does_not_exist.json"), pub)
        t("missing manifest -> NoManifestError", False)
    except NoManifestError:
        t("missing manifest -> NoManifestError", True)
    badpath = os.path.join(tmp, "tampered.json")
    with open(badpath, "w", encoding="utf-8") as f:
        json.dump(bad, f)
    try:
        Gate.load(badpath, pub)
        t("tampered manifest refused at load", False)
    except NoManifestError:
        t("tampered manifest refused at load", True)

    # 17: sealed gate denies everything
    sg = Gate.sealed("unit test")
    d = sg.check("read_public", "https://target.lab.internal/")
    t("sealed gate denies everything", (not d.allowed) and d.rule == "seal",
      d.reason)

    # 18-19: sessions & concurrency
    m5 = build_example_manifest(quiet_hours=False)
    m5["targets"] = [{"type": "domain", "value": "conc.lab.internal",
                      "allowed_actions": ["read_public"],
                      "rate_limit": {"requests_per_minute": 60,
                                     "max_concurrent": 1}}]
    g5 = Gate(fresh(m5), pub)
    with g5.session("read_public", "https://conc.lab.internal/a") as sd:
        t("session allowed", sd.allowed, sd.reason)
    try:
        with g5.session("read_public", "https://conc.lab.internal/a"):
            with g5.session("read_public", "https://conc.lab.internal/a"):
                pass
        t("second concurrent session denied (max_concurrent=1)", False)
    except GateViolation:
        t("second concurrent session denied (max_concurrent=1)", True)

    # 20-21: audit chain integrity
    ok3, _, why3 = verify_audit_log(audit_path)
    t("audit chain verifies", ok3, why3)
    with open(audit_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    rec = json.loads(lines[1])
    rec["target"] = "evil.example.com"
    lines[1] = json.dumps(rec) + "\n"
    tampered = os.path.join(tmp, "audit_tampered.jsonl")
    with open(tampered, "w", encoding="utf-8") as f:
        f.writelines(lines)
    ok4, _, why4 = verify_audit_log(tampered)
    t("audit tamper detected", not ok4, why4)

    shutil.rmtree(tmp, ignore_errors=True)
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    if failed:
        print("FAILED: " + ", ".join(failed))
        return 1
    print("roe_gate self-test: ALL GREEN")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Runtime RoE gate (consent substrate, part 2)")
    ap.add_argument("--self-test", action="store_true",
                    help="run the 21-test battery and exit")
    ap.add_argument("--verify-log", metavar="PATH",
                    help="verify a hash-chained audit log")
    args = ap.parse_args(argv)

    if args.self_test:
        return _selftest()
    if args.verify_log:
        ok, n, why = verify_audit_log(args.verify_log)
        print(("OK: audit chain intact" if ok
               else f"TAMPERED at record {n}: {why}"))
        return 0 if ok else 1
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
