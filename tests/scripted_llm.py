"""Test double for the LLM: scripted answers built from a reference fix, so the pipeline mechanics can be tested offline.

Deliberately imperfect, to exercise the machinery: one file's first edit is wrong (forcing a fix iteration),
diffs carry wrong line numbers, the security test is broken (forcing the vetted fallback), and the plan asks
to edit a test file (which the guardrails must reject).
"""
from __future__ import annotations

import json
from pathlib import Path

from leaply_guard.llm import LLM
from leaply_guard.patching import make_diff

FIXTURES = Path(__file__).parent / "fixtures"

SCENARIOS = {
    "pyjwt": {
        "fix": FIXTURES / "pyjwt_fix",
        "broken": ("app/service_auth.py", 'algorithms=["ES256"], ', ""),
        "evidence": {"file": "app/service_auth.py", "line": 21, "why": "decode without algorithms using a public key"},
        "test_file": "tests/test_tokens.py",
        "breaking": ["encode returns str", "decode requires algorithms", "verify kwarg removed"],
    },
    "pyyaml": {
        "fix": FIXTURES / "pyyaml_fix",
        "broken": ("app/defaults.py", "yaml.safe_load(fh) or {}", "yaml.load(fh) or dict()"),
        "evidence": {"file": "app/config_loader.py", "line": 14, "why": "yaml.load on request body with default FullLoader"},
        "test_file": "tests/test_config.py",
        "breaking": ["yaml.load requires Loader", "yaml.load_all requires Loader"],
    },
}


def _wrong_line_numbers(diff: str) -> str:
    return "\n".join("@@ -999,7 +999,7 @@" if l.startswith("@@") else l for l in diff.splitlines())


class ScriptedLLM(LLM):
    def __init__(self, *a, scenario: str = "pyjwt", **kw):
        super().__init__(*a, **kw)
        self.simulated = True
        self.sc = SCENARIOS[scenario]

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

    def _fixed(self, path: str) -> str:
        return (self.sc["fix"] / path).read_text(encoding="utf-8")

    def _answer(self, purpose: str, prompt: str) -> str:
        sc = self.sc
        fix_files = sorted(p.relative_to(sc["fix"]).as_posix() for p in sc["fix"].rglob("*.py"))
        if purpose.startswith("reachability"):
            return json.dumps({"verdict": "REACHABLE", "evidence": [sc["evidence"]], "reasoning": sc["evidence"]["why"]})
        if purpose == "security regression test":
            return "```python\nimport pytest\n\ndef test_broken():\n    from app.nope import x\n```"  # invalid on purpose
        if purpose == "migration plan":
            files = [{"path": f, "changes": ["migrate"], "why": "new API", "risk": "low"} for f in fix_files]
            files.append({"path": sc["test_file"], "changes": ["update"], "why": "-", "risk": "low"})
            return "```json\n" + json.dumps({"summary": "Migrate to the new major version.", "breaking_changes": sc["breaking"],
                                             "files": files, "security_notes": "safe defaults", "risks": ["check callers"],
                                             "overall_risk": "low"}) + "\n```"
        if purpose.startswith("edit ") or purpose.startswith("fix "):
            path = purpose.split(" ", 1)[1]
            after = self._fixed(path)
            bpath, good, bad = sc["broken"]
            if path == bpath and purpose.startswith("edit "):
                after = after.replace(good, bad)  # first attempt is wrong
            return _wrong_line_numbers(make_diff(path, self._current(prompt), after))
        if purpose.startswith("rewrite "):
            return "```python\n" + self._fixed(purpose.split(" ", 1)[1]) + "```"
        if purpose == "failure triage":
            return json.dumps({"category": "api_change", "root_cause": f"old API still used in {sc['broken'][0]}",
                               "files": [sc["broken"][0]], "signature": "old api call"})
        if purpose == "security review of final diff":
            return json.dumps({"verdict": "approve", "findings": [{"file": "x", "severity": "low", "issue": "fine"}], "summary": "ok"})
        if purpose == "explain changes":
            return json.dumps({"files": {f: "Moved to the new, safe API." for f in fix_files},
                               "reviewer_summary": {"what_changed": "Upgraded.", "risk": "low", "double_check": ["callers"]}})
        raise AssertionError(f"unscripted purpose: {purpose}")
