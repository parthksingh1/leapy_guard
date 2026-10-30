"""Test double for the LLM: scripted answers for the PyJWT demo, so the pipeline mechanics can be tested offline.

Deliberately imperfect, to exercise the machinery: the first service_auth edit forgets the algorithms
allow-list (forcing one fix iteration), diffs carry wrong line numbers, and the plan asks to edit a test file
(which the guardrails must reject).
"""
from __future__ import annotations

import json
from pathlib import Path

from leaply_guard.llm import LLM
from leaply_guard.patching import make_diff

FIX = Path(__file__).parent / "fixtures" / "pyjwt_fix"
PROOF = Path(__file__).resolve().parent.parent / "leaply_guard" / "proofs" / "pyjwt_cve_2022_29217.py"


def _wrong_line_numbers(diff: str) -> str:
    return "\n".join("@@ -999,7 +999,7 @@" if l.startswith("@@") else l for l in diff.splitlines())


class ScriptedLLM(LLM):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.simulated = True
        self.fixed_service_auth = False

    def resolve_models(self):
        return {r: s.model_id for r, s in self.cfg.models.items()}

    def chat(self, role, purpose, messages, *, step="", max_tokens=4096, temperature=0.2):
        prompt = messages[-1]["content"]
        text = self._answer(purpose, prompt)
        rec = self.ledger.add(self.cfg.models[role], purpose, len(prompt) // 4, len(text) // 4, 0.01, step)
        if self.bus:
            self.bus.cost_usd = self.ledger.total_cost
            self.bus.emit("model_call", actor=role, **rec)
        return text

    def _current(self, prompt: str) -> str:
        return prompt.split("```python\n", 1)[1].rsplit("\n```", 1)[0].rstrip("\n") + "\n"

    def _answer(self, purpose: str, prompt: str) -> str:
        if purpose.startswith("reachability"):
            return json.dumps({"verdict": "REACHABLE", "evidence": [{"file": "app/service_auth.py", "line": 21, "why": "decode without algorithms using a public key"}],
                               "reasoning": "verify_service_token decodes with the SSH public key and no allow-list.", "vulnerable_advisory": "GHSA-ffqj-6fqr-9h24"})
        if purpose == "security regression test":
            return "```python\nimport pytest\n\ndef test_broken():\n    from app.nope import x\n```"  # invalid on purpose -> vetted fallback
        if purpose == "migration plan":
            return "```json\n" + json.dumps({
                "summary": "Migrate to PyJWT 2.x: encode returns str, decode needs algorithms, verify=False becomes options.",
                "breaking_changes": ["encode returns str", "decode requires algorithms", "verify kwarg removed"],
                "files": [
                    {"path": "app/tokens.py", "changes": ["drop .decode('utf-8')", "pass algorithms=[cfg.algorithm]"], "why": "2.x API", "risk": "low"},
                    {"path": "app/service_auth.py", "changes": ["drop .decode('utf-8')", "pass algorithms=['ES256']"], "why": "closes CVE", "risk": "medium"},
                    {"path": "app/introspect.py", "changes": ["options={'verify_signature': False}"], "why": "2.x API", "risk": "low"},
                    {"path": "tests/test_tokens.py", "changes": ["update"], "why": "-", "risk": "low"},
                ],
                "security_notes": "explicit allow-list", "risks": ["service tokens now only accept ES256"], "overall_risk": "low"}) + "\n```"
        if purpose.startswith("edit ") or purpose.startswith("fix "):
            path = purpose.split(" ", 1)[1]
            before = self._current(prompt)
            after = (FIX / path).read_text(encoding="utf-8")
            if path == "app/service_auth.py" and purpose.startswith("edit "):
                after = after.replace('algorithms=["ES256"], ', "")  # first attempt misses the allow-list
            return _wrong_line_numbers(make_diff(path, before, after))
        if purpose.startswith("rewrite "):
            return "```python\n" + (FIX / purpose.split(" ", 1)[1]).read_text(encoding="utf-8") + "```"
        if purpose == "failure triage":
            return json.dumps({"category": "api_change", "root_cause": "jwt.decode called without algorithms in service_auth",
                               "files": ["app/service_auth.py"], "signature": "DecodeError algorithms required"})
        if purpose == "explain changes":
            return json.dumps({"files": {"app/tokens.py": "PyJWT 2 returns str and needs an explicit HS256 allow-list."},
                               "reviewer_summary": {"what_changed": "Upgraded PyJWT.", "risk": "low", "double_check": ["ES256 only"]}})
        raise AssertionError(f"unscripted purpose: {purpose}")
