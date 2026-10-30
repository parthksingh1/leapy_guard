"""Reachability triage: is the vulnerable package actually used, and how? (Nemotron 3 Nano)"""
from __future__ import annotations

import re
from pathlib import Path

from .llm import LLM, LLMError
from .scan import SEVERITY_RANK, Finding

# PyPI distribution name -> import name, where they differ
IMPORT_NAMES = {
    "pyjwt": "jwt", "pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "python-jose": "jose",
    "scikit-learn": "sklearn", "opencv-python": "cv2", "python-dateutil": "dateutil", "pycryptodome": "Crypto",
    "protobuf": "google.protobuf", "msgpack-python": "msgpack",
}
REACH_WEIGHT = {"REACHABLE": 1.0, "POSSIBLY REACHABLE": 0.6, "NOT USED": 0.1}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build", ".leaply"}
CODE_EXT = {".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}


def iter_code_files(repo: Path):
    for p in sorted(repo.rglob("*")):
        if p.is_file() and p.suffix in CODE_EXT and not (SKIP_DIRS & set(p.relative_to(repo).parts)):
            yield p


def find_usages(repo: Path, finding: Finding, limit: int = 60) -> list[dict]:
    name = finding.package.name
    mod = IMPORT_NAMES.get(name.lower(), name.replace("-", "_"))
    imp = re.compile(rf"^\s*(?:import\s+{re.escape(mod)}\b|from\s+{re.escape(mod)}[\s.]|.*require\(['\"]{re.escape(name)}['\"]\)|.*from\s+['\"]{re.escape(name)}['\"])")
    call = re.compile(rf"\b{re.escape(mod.split('.')[-1])}\.\w+\s*\(")
    hits = []
    for path in iter_code_files(repo):
        rel = path.relative_to(repo).as_posix()
        for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            kind = "import" if imp.match(line) else "call" if call.search(line) else None
            if kind:
                hits.append({"file": rel, "line": i, "kind": kind, "code": line.strip()[:200],
                             "test": "test" in rel.lower()})
                if len(hits) >= limit:
                    return hits
    return hits


def triage(repo: Path, finding: Finding, llm: LLM | None, step: str = "triage") -> dict:
    usages = find_usages(repo, finding)
    prod = [u for u in usages if not u["test"]]
    if not usages:
        result = {"verdict": "NOT USED", "evidence": [], "reasoning": f"No import of {finding.package.name} found in source files.", "by": "static"}
    elif llm is None:
        result = {
            "verdict": "POSSIBLY REACHABLE" if prod else "NOT USED",
            "evidence": [{"file": u["file"], "line": u["line"], "why": u["code"]} for u in prod[:6]],
            "reasoning": "Static match only (no model configured): the package is imported in application code.",
            "by": "static",
        }
    else:
        advisories = "\n".join(f"- {a.id} ({a.cve or 'no CVE'}, {a.severity}): {a.summary}" for a in finding.advisories[:8])
        sites = "\n".join(f"{u['file']}:{u['line']}: {u['code']}" for u in usages)
        prompt = f"""You triage dependency vulnerabilities for reachability.

Package: {finding.package.name} {finding.package.version} ({finding.package.ecosystem})
Advisories:
{advisories}

Every place the package is used in the repository:
{sites}

Decide whether the vulnerable behaviour can be reached from this application's code.
- REACHABLE: application code calls the vulnerable API in the vulnerable way (e.g. token verification without an algorithm allow-list, with an asymmetric public key).
- POSSIBLY REACHABLE: the package is used, but it is unclear whether the vulnerable path is hit.
- NOT USED: only tests/dead code use it, or the vulnerable API is never called.

Reply with JSON only:
{{"verdict": "REACHABLE|POSSIBLY REACHABLE|NOT USED", "evidence": [{{"file": "...", "line": 0, "why": "one short sentence"}}], "reasoning": "two sentences max", "vulnerable_advisory": "the advisory id that is most clearly reachable"}}"""
        try:
            result = llm.chat_json("nano", f"reachability {finding.package.name}", [{"role": "user", "content": prompt}],
                                   step=step, max_tokens=2048, temperature=0.0)
            result["by"] = "nano"
            if result.get("verdict") not in REACH_WEIGHT:
                result["verdict"] = "POSSIBLY REACHABLE"
            valid = {(u["file"], u["line"]) for u in usages}
            result["evidence"] = [e for e in result.get("evidence", []) if (e.get("file"), e.get("line")) in valid][:8] or [
                {"file": u["file"], "line": u["line"], "why": u["code"]} for u in prod[:4]]
        except LLMError as exc:
            result = {"verdict": "POSSIBLY REACHABLE", "evidence": [{"file": u["file"], "line": u["line"], "why": u["code"]} for u in prod[:6]],
                      "reasoning": f"Model triage failed ({exc}); static match only.", "by": "static"}
    result["usage_count"] = len(usages)
    finding.reachability = result
    finding.score = round(SEVERITY_RANK.get(finding.severity, 0) * REACH_WEIGHT[result["verdict"]], 2)
    return result
