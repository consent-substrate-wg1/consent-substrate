#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
agent_roe.py -- wires the RoE gate into tree_search_agent.py (reference integration).

Track 2 deliverable: turns the gate from a library into an enforced runtime
policy for a real agent loop. Three enforcement points:

  1. startup         -- no signed manifest -> the agent refuses to start.
  2. every tool call -- WEB_SEARCH / EXECUTE_PYTHON pass the gate first;
                        denials return "[GATE DENY] ..." observations the
                        model can see and adapt to (denial is in-band).
  3. every byte out  -- even the model API call is authorized: all network
                        egress is in scope or it does not happen.

EXECUTE_PYTHON policy (v1, defense-in-depth, NOT a sandbox):
  * process spawn / raw sockets / native loaders / deletion are denied at
    the pattern level -- core prohibitions (lateral_movement,
    destructive_ops) apply to model-generated code even though your own
    first-party tools (like PHONE_FILE_SEARCH using `find`) may use them.
    The gate distinguishes audited first-party tool code from untrusted
    generated code. That distinction is the whole point.
  * network egress requires literal URLs, each authorized against the
    manifest; egress through values the gate cannot inspect is denied.
  * every denial lands in the SAME hash-chained audit log as gate
    decisions: one flight recorder, no gaps.

Install on the phone:
    pip install cryptography        (if not already)
    python gate_bootstrap.py        (one-time: keys + signed lab manifest)
    python patch_agent.py           (patches tree_search_agent.py; makes .bak)
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from roe_gate import Gate, GateViolation, NoManifestError  # noqa: F401 (re-exported)

WEB_SEARCH_ENDPOINT = "https://html.duckduckgo.com/html/"


def roe_dir() -> str:
    """Where consent artifacts live (shared with gate_bootstrap.py)."""
    return os.environ.get("ROE_DIR",
                          os.path.join(os.path.expanduser("~"), "roe"))


def _seed_chain_from_disk(gate):
    """Continue the hash chain across agent restarts: seed the gate's
    prev/seq from the last record already on disk. Without this, every
    restart would start a new chain at GENESIS and the verifier would
    report a false chain break. Fail-safe: if the tail is unreadable we
    start at GENESIS -- the verifier then reports a break, which is the
    correct fail-closed signal to go investigate."""
    path = gate._audit_path     # same product; shipped as one versioned unit
    if not path or not os.path.exists(path):
        return
    last = None
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    last = line
    except OSError:
        return
    if not last:
        return
    try:
        import json as _json
        rec = _json.loads(last)
        if rec.get("hash"):
            gate._prev_hash = rec["hash"]
            gate._seq = int(rec.get("seq", 0))
    except Exception:
        pass  # corrupt tail -> chain break on verify = investigate


def load_production_gate() -> Gate:
    d = roe_dir()
    gate = Gate.load(
        os.path.join(d, "signed_manifest.json"),
        pubkey=os.path.join(d, "keys", "roe_signing.pub"),
        audit_log=os.path.join(d, "roe_audit.jsonl"),
    )
    _seed_chain_from_disk(gate)
    return gate


# ---------------------------------------------------------------------------
# EXECUTE_PYTHON static policy
# ---------------------------------------------------------------------------

# (pattern, human reason). These map onto CORE_FORBIDDEN classes: no manifest
# can ever authorize them for GENERATED code, so the gate denies by structure,
# not by policy choice.
PY_DENY_PATTERNS = (
    (r"\bsubprocess\b", "process spawn (lateral_movement)"),
    (r"\bos\.system\b", "shell execution (lateral_movement)"),
    (r"\bos\.popen\b", "shell execution (lateral_movement)"),
    (r"\bsocket\b", "raw sockets (lateral_movement)"),
    (r"\bctypes\b", "native code loading (lateral_movement)"),
    (r"\bshutil\.rmtree\b", "recursive deletion (destructive_ops)"),
    (r"\bos\.remove\b|\bos\.unlink\b", "file deletion (destructive_ops)"),
)
NET_LIB_RE = re.compile(r"\b(requests|urllib|httpx|aiohttp|urlopen)\b")
URL_RE = re.compile(r"https?://[^\s'\"<>)]+")


def _log_and_raise(gate, action, target, reason, rule):
    """Record the denial in the hash chain with its REAL reason, then raise
    the violation the tool layer will render in-band."""
    if hasattr(gate, "note_denial"):
        gate.note_denial(action, target, reason, rule)
    else:                       # older gate build: still land a DENY record
        gate.check(action, target)
    from roe_gate import Decision
    raise GateViolation(Decision(False, reason, rule, action, target,
                                 gate.manifest_id))


def guard_python(gate: Gate, code: str):
    """Authorize model-generated code BEFORE it runs. Raises GateViolation."""
    for pat, why in PY_DENY_PATTERNS:
        if re.search(pat, code):
            _log_and_raise(
                gate, "execute_python", "<generated-code>",
                "generated code requests " + why
                + " -- no manifest can authorize it",
                "core")
    urls = URL_RE.findall(code)
    if NET_LIB_RE.search(code) and not urls:
        _log_and_raise(
            gate, "execute_python", "<generated-code>",
            "code performs network egress through values the gate cannot "
            "inspect; rewrite with a literal in-scope URL",
            "action_scope")
    for u in urls:
        gate.authorize("read_public", u)   # raises + logs if out of scope


# ---------------------------------------------------------------------------
# Helpers the patched agent calls
# ---------------------------------------------------------------------------

def pre_tool_guard(gate: Gate, action, argument):
    """Gate every tool call. Returns None if allowed, else a '[GATE DENY]'
    observation string the agent loop shows to the model (in-band denial)."""
    action = (action or "").strip().upper()
    try:
        if action == "WEB_SEARCH":
            gate.authorize("read_public", WEB_SEARCH_ENDPOINT)
        elif action == "EXECUTE_PYTHON":
            guard_python(gate, argument or "")
        elif action == "PHONE_FILE_SEARCH":
            # Local read-only `find` run by first-party tool code; scoped by
            # the OS sandbox, zero network egress. No gate action needed.
            pass
        else:
            return ("[GATE DENY] action: unknown action %r "
                    "(the gate is allowlist-only)" % action)
        return None
    except GateViolation as e:
        d = e.decision
        return "[GATE DENY] %s: %s" % (d.rule, d.reason)


def authorize_or_reason(gate: Gate, action: str, target: str):
    """Non-raising authorize: None if allowed, else 'rule: reason'."""
    try:
        gate.authorize(action, target)
        return None
    except GateViolation as e:
        d = e.decision
        return "%s: %s" % (d.rule, d.reason)
