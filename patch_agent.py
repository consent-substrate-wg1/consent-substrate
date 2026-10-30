#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_agent.py -- apply the RoE-gate integration.

Patches two files (both atomic, idempotent, with .bak restore-on-failure):
  * tree_search_agent.py -- 5 enforcement points (see PATCHES_AGENT)
  * roe_gate.py          -- adds Gate.note_denial() so out-of-band denials
                            (EXECUTE_PYTHON shim) land in the hash chain
                            with their REAL reason, not a generic one
"""

from __future__ import annotations

import os
import py_compile
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "tree_search_agent.py")
BAK = AGENT + ".bak"

# (anchor, replacement) -- anchors are exact lines from tree_search_agent.py
# (cloud edition, as shipped). If any anchor is missing the file has changed:
# the patcher refuses instead of guessing.
PATCHES_AGENT = (
    # 1. import the shim
    (
        "from flask import Flask, request, jsonify, render_template_string\n",
        "from flask import Flask, request, jsonify, render_template_string\n"
        "\n"
        "sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n"
        "from agent_roe import (load_production_gate, pre_tool_guard,\n"
        "                       authorize_or_reason, NoManifestError)\n",
    ),
    # 2+3. GATE global + guard every tool dispatch
    (
        "def execute_tool(action, argument):\n"
        "    action = (action or \"\").strip().upper()\n",
        "GATE = None  # set in __main__; tools refuse to run without it\n"
        "\n"
        "\n"
        "def execute_tool(action, argument):\n"
        "    if GATE is None:\n"
        "        return \"[GATE DENY] agent not gated: run gate_bootstrap.py first\"\n"
        "    block = pre_tool_guard(GATE, action, argument)\n"
        "    if block:\n"
        "        return block\n"
        "    action = (action or \"\").strip().upper()\n",
    ),
    # 4. model API egress is gated too
    (
        "    headers = {\"Authorization\": \"Bearer \" + API_KEY}\n",
        "    headers = {\"Authorization\": \"Bearer \" + API_KEY}\n"
        "    if GATE is not None:  # even the model call is in-scope: all egress gated\n"
        "        block = authorize_or_reason(GATE, \"read_public\", API_URL)\n"
        "        if block:\n"
        "            return \"Model API blocked by RoE gate: \" + block\n",
    ),
    # 5a. tell the model about the gate in-band
    (
        "        \"AVAILABLE TOOLS:\\n\"\n",
        "        \"AVAILABLE TOOLS:\\n\"\n"
        "        \"Tool use is subject to a signed Rules-of-Engagement gate: a [GATE DENY] \"\n"
        "        \"observation means that action+target is NOT authorized; choose another path.\\n\"\n",
    ),
    # 5b. startup: load consent or refuse to run
    (
        "        sys.exit(1)\n"
        "    if shutil.which(\"termux-wake-lock\"):\n",
        "        sys.exit(1)\n"
        "    try:\n"
        "        GATE = load_production_gate()\n"
        "        rep = GATE.report()\n"
        "        print(\"RoE gate active: manifest %s | %d target(s) in scope\"\n"
        "              \" | audit: ~/roe/roe_audit.jsonl\"\n"
        "              % (rep[\"manifest_id\"][:8], rep[\"targets_in_scope\"]))\n"
        "    except NoManifestError as e:\n"
        "        print(\"CONSENT GATE REFUSED TO START:\", e)\n"
        "        print(\"Fix: python gate_bootstrap.py   (creates + signs your lab manifest)\")\n"
        "        sys.exit(1)\n"
        "    if shutil.which(\"termux-wake-lock\"):\n",
    ),
)

# Adds Gate.note_denial() to roe_gate.py (audit fidelity for shim denials).
PATCHES_ROE_GATE = (
    (
        "    def report(self) -> dict:\n",
        "    def note_denial(self, action, target, reason, rule) -> Decision:\n"
        "        \"\"\"Record an out-of-band denial (e.g. from the EXECUTE_PYTHON\n"
        "        shim) in the hash-chained audit log WITHOUT evaluating it.\n"
        "        Audit fidelity: the recorder must show WHY, not just THAT.\"\"\"\n"
        "        d = Decision(False, reason, rule, action, target, self._manifest_id)\n"
        "        self._audit(d)\n"
        "        return d\n"
        "\n"
        "    def report(self) -> dict:\n",
    ),
)

PATCH_TARGETS = (
    ("tree_search_agent.py", PATCHES_AGENT, "from agent_roe import"),
    ("roe_gate.py", PATCHES_ROE_GATE, "def note_denial"),
)

def patch_file(path, patches, done_marker):
    with open(path, "r", encoding="utf-8") as f:
        src = f.read()
    if done_marker in src:
        print("  %-24s already patched -- skipped" % os.path.basename(path))
        return True
    missing = [i for i, (a, _) in enumerate(patches) if a not in src]
    if missing:
        print("  %-24s ANCHOR(S) NOT FOUND: %s" % (os.path.basename(path), missing))
        print("    The file differs from the version these patches target.")
        print("    Refusing to guess -- restore the canonical file or patch by hand.")
        return False
    shutil.copy2(path, path + ".bak")
    try:
        for a, b in patches:
            src = src.replace(a, b, 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write(src)
        py_compile.compile(path, doraise=True)
    except Exception as e:
        shutil.copy2(path + ".bak", path)
        print("  %-24s PATCH FAILED, backup restored: %s" % (os.path.basename(path), e))
        return False
    print("  %-24s patched OK (backup: %s.bak)" % (os.path.basename(path), os.path.basename(path)))
    return True


def main() -> int:
    print("patching:")
    ok = True
    for name, patches, marker in PATCH_TARGETS:
        path = os.path.join(HERE, name)
        if not os.path.exists(path):
            print("  %-24s NOT FOUND next to patch_agent.py" % name)
            ok = False
            continue
        ok = patch_file(path, patches, marker) and ok
    if not ok:
        return 1
    print("enforcement: startup + tool dispatch + model egress + audit fidelity")
    print("next: python gate_bootstrap.py && python tree_search_agent.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
