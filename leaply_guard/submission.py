"""Submission helpers: secret scan of the repo and git history, the Devpost checklist, and filling result slots."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .guardrails import SECRET_PATTERNS

DOCS_WITH_SLOTS = ["README.md", "SUBMISSION.md", "FEEDBACK.md", "docs/DEVPOST_FORM.md", "docs/VIDEO_RUNBOOK.md"]
SLOT = re.compile(r"\{\{([A-Z_]+)\}\}")
SKIP_SCAN = {".git", ".venv", "venv", "node_modules", "runs", "__pycache__"}
# synthetic strings used by the secret-scanner unit test
ALLOWED = {"AKIAABCDEFGHIJKLMNOP"}


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, encoding="utf-8",
                          errors="replace").stdout


def env_values(root: Path) -> list[str]:
    env = root / ".env"
    if not env.exists():
        return []
    vals = []
    for line in env.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            v = line.split("=", 1)[1].strip().strip('"').strip("'")
            if len(v) >= 12 and not v.lower().startswith(("your", "xxx", "changeme")):
                vals.append(v)
    return vals


def secret_scan(root: Path) -> list[str]:
    """Problems found (never the secret itself): .env values or key patterns in tracked files or history."""
    problems: list[str] = []
    values = env_values(root)
    pats = {n: re.compile(p) for n, p in SECRET_PATTERNS.items() if n != "Generic credential"}
    tracked = [l for l in _git(root, "ls-files").splitlines() if l]
    for rel in tracked:
        p = root / rel
        if not p.is_file() or SKIP_SCAN & set(Path(rel).parts) or p.stat().st_size > 2_000_000:
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        if any(v in text for v in values):
            problems.append(f"{rel}: contains a value from .env")
        for name, pat in pats.items():
            if rel.startswith("leaply_guard/guardrails.py"):
                continue
            for m in pat.finditer(text):
                if m.group(0) not in ALLOWED:
                    problems.append(f"{rel}: looks like a {name}")
                    break
    if ".env" in tracked:
        problems.append(".env is tracked by git")
    history = _git(root, "log", "--all", "-p")
    if any(v in history for v in values):
        problems.append("git history contains a value from .env (rewrite history before pushing)")
    for name, pat in pats.items():
        if name == "Private key block":  # only a header followed by key material counts
            pat = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----\s*\n\+?[A-Za-z0-9+/=]{40}")
        if {m.group(0) for m in pat.finditer(history)} - ALLOWED:
            problems.append(f"git history: possible {name}")
    return problems


def replay_status(root: Path) -> tuple[bool, str]:
    path = root / "replays" / "pyjwt-demo.json"
    if not path.exists():
        return False, "replays/pyjwt-demo.json missing (run: leaply-guard finish)"
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("simulated") or data.get("status") != "success":
        return False, "replay is not a successful live run"
    calls = [e for e in data.get("events", []) if e.get("kind") == "model_call"]
    if not calls or not any(e.get("tokens_in", 0) > 0 for e in calls):
        return False, "replay has no real model calls"
    return True, f"live run {data.get('run_id')} with {len(calls)} model calls"


def checklist(root: Path) -> list[tuple[str, bool, str]]:
    readme = (root / "README.md").read_text(encoding="utf-8") if (root / "README.md").exists() else ""
    items: list[tuple[str, bool, str]] = []
    lic = root / "LICENSE"
    items.append(("MIT LICENSE at repo root", lic.exists() and "MIT License" in lic.read_text(encoding="utf-8"), "LICENSE"))
    items.append(("README has setup and run steps", "## Quick start" in readme and "pip install" in readme, "README.md"))
    items.append(("README names Nebius Token Factory", "Nebius Token Factory" in readme, ""))
    items.append(("README names NVIDIA Nemotron", "NVIDIA Nemotron" in readme, ""))
    items.append(("README has architecture diagram", "```mermaid" in readme, ""))
    items.append(("README has known limitations", "Known limitations" in readme, ""))
    items.append(("README explains what is new vs. Leaply", "What was built during the hackathon" in readme, ""))
    for f in ("FEEDBACK.md", "SUBMISSION.md", "docs/DEVPOST_FORM.md", "docs/VIDEO_RUNBOOK.md", "docs/DEPLOY.md", "Dockerfile"):
        items.append((f"{f} present", (root / f).exists(), ""))
    problems = secret_scan(root)
    items.append(("No keys in repo or git history", not problems, "; ".join(problems[:3])))
    ok, msg = replay_status(root)
    items.append(("Replay comes from a successful live run", ok, msg))
    open_slots = sorted({m for f in DOCS_WITH_SLOTS if (root / f).exists() for m in SLOT.findall((root / f).read_text(encoding="utf-8"))})
    items.append(("All result slots filled from the live run", not open_slots, ", ".join(open_slots[:6])))
    items.append(("docs/RESULTS.md generated", (root / "docs/RESULTS.md").exists(), ""))
    return items


# --- results from a run file -------------------------------------------------------------------
def _dur(seconds: float) -> str:
    m, s = divmod(int(round(seconds)), 60)
    return f"{m}m {s:02d}s" if m else f"{s}s"


def slot_values(run: dict) -> dict[str, str]:
    d = run["result"]
    cost = d.get("cost", {})
    rows = {r["role"]: r for r in cost.get("rows", [])}
    t = lambda x: f"{x.get('passed', 0)}/{x.get('total', 0)}"  # noqa: E731
    proof = d.get("proof", {})
    end = max((e.get("t", 0) for e in run.get("events", [])), default=0)
    v = {
        "RUN_ID": run.get("run_id", ""),
        "TESTS_BEFORE": t(d.get("tests_before", {})),
        "TESTS_AFTER_BUMP": t(d.get("tests_after_bump", {})),
        "TESTS_AFTER": t(d.get("tests_after", {})),
        "BROKEN_COUNT": str(d.get("tests_after_bump", {}).get("failed", 0) + d.get("tests_after_bump", {}).get("errors", 0)),
        "PROOF_RESULT": ("attack accepted on 1.x, rejected after the fix" if proof.get("before") == "failed" and proof.get("after") == "passed"
                         else f"before: {proof.get('before')}, after: {proof.get('after')}"),
        "PROOF_SOURCE": {"ultra": "written by Nemotron 3 Ultra and validated", "vetted": "vetted template"}.get(proof.get("source"), "none"),
        "ITERATIONS": str(d.get("iterations", "")),
        "RUN_TIME": _dur(end),
        "TOTAL_TOKENS": f"{cost.get('total_tokens', 0):,}",
        "TOTAL_COST": f"${cost.get('total_cost_usd', 0):.4f}",
        "ALL_ULTRA_COST": f"${cost.get('all_ultra_cost_usd', 0):.4f}",
        "SAVINGS_PCT": f"{cost.get('routing_savings_pct', 0):.0f}",
        "CONFIDENCE": str(d.get("confidence", {}).get("score", "")),
        "TARGET_VERSION": str(d.get("target", "")),
        "SOURCE_COUNT": str(len(d.get("sources", []))),
        "ADVISORY_COUNT": str(len(d.get("finding", {}).get("advisories", []))),
    }
    for role in ("ultra", "super", "nano"):
        r = rows.get(role, {})
        v[f"{role.upper()}_TOKENS"] = f"{r.get('tokens_in', 0) + r.get('tokens_out', 0):,}"
        v[f"{role.upper()}_CALLS"] = str(r.get("calls", 0))
        v[f"{role.upper()}_COST"] = f"${r.get('cost_usd', 0):.4f}"
        v[f"MODEL_{role.upper()}"] = r.get("model", "")
    return v


def fill_slots(root: Path, values: dict[str, str]) -> dict[str, list[str]]:
    """Replace {{SLOT}}s in the docs. Returns unknown slots per file."""
    unknown: dict[str, list[str]] = {}
    templates = root / ".leaply" / "templates"
    for f in DOCS_WITH_SLOTS:
        p = root / f
        if not p.exists():
            continue
        tpl = templates / f
        if not tpl.exists() and SLOT.search(p.read_text(encoding="utf-8")):
            tpl.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(p, tpl)  # keep the slotted version so a later run can refill
        text = (tpl if tpl.exists() else p).read_text(encoding="utf-8")
        missing = sorted({m for m in SLOT.findall(text) if m not in values})
        text = SLOT.sub(lambda m: values.get(m.group(1), m.group(0)), text)
        p.write_text(text, encoding="utf-8", newline="\n")
        if missing:
            unknown[f] = missing
    return unknown


def results_markdown(run: dict) -> str:
    d = run["result"]
    v = slot_values(run)
    cost = d.get("cost", {})
    L = [f"# Results: live run `{v['RUN_ID']}`", "",
         "Generated by `leaply-guard finish` from `runs/{}.json` (also served as `replays/pyjwt-demo.json`).".format(v["RUN_ID"]), "",
         f"**Target:** PyJWT {d['finding']['package']['version']} → {v['TARGET_VERSION']} · **Status:** {d.get('status')} · "
         f"**Confidence:** {v['CONFIDENCE']}/100 · **Wall-clock:** {v['RUN_TIME']}", "",
         "## Tests", "| Stage | Passing |", "|---|---|",
         f"| Before (PyJWT {d['finding']['package']['version']}) | {v['TESTS_BEFORE']} |",
         f"| After bump, code unchanged | {v['TESTS_AFTER_BUMP']} |",
         f"| After Leaply Guard | {v['TESTS_AFTER']} |", "",
         f"Fix iterations: **{v['ITERATIONS']}**", "",
         "## Security proof", f"- {v['PROOF_RESULT']} ({v['PROOF_SOURCE']})",
         f"- Advisory: {d.get('proof', {}).get('cve') or d.get('proof', {}).get('advisory')}", "",
         "## Re-scan", f"- {len(d.get('rescan', {}).get('remaining', []))} known vulnerabilities for {d.get('rescan', {}).get('package')} {d.get('rescan', {}).get('version')}",
         f"- Closed: {', '.join(d.get('rescan', {}).get('closed', []))}", "",
         "## Models, tokens and cost", "| Role | Model | Calls | Tokens in | Tokens out | Cost |", "|---|---|---|---|---|---|"]
    for r in cost.get("rows", []):
        L.append(f"| {r['role'].title()} | `{r['model']}` | {r['calls']} | {r['tokens_in']:,} | {r['tokens_out']:,} | ${r['cost_usd']:.4f} |")
    L += [f"| **Total** | | | | | **{v['TOTAL_COST']}** |", "",
          f"All calls on Ultra would have cost {v['ALL_ULTRA_COST']}: **{v['SAVINGS_PCT']}% saved by model routing.**", "",
          "## Model calls (audit log)", "| Step | Role | Purpose | Tokens in | Tokens out | Latency | Cost |", "|---|---|---|---|---|---|---|"]
    for c in d.get("audit", {}).get("model_calls", []):
        L.append(f"| {c['step']} | {c['role']} | {c['purpose']} | {c['tokens_in']:,} | {c['tokens_out']:,} | {c['latency_s']}s | ${c['cost_usd']:.4f} |")
    L += ["", "## Security review (Nemotron 3 Ultra)", f"- {d.get('security_review', {}).get('verdict')}: {d.get('security_review', {}).get('summary', '')}", "",
          "## Sources (Tavily + OSV)"]
    for s in d.get("sources", []):
        L.append(f"- [{s['title'][:100]}]({s['url']}) ({s.get('via')})")
    return "\n".join(L) + "\n"


def fill_in_items(root: Path) -> list[str]:
    out = []
    for f in ("README.md", "SUBMISSION.md", "FEEDBACK.md", "docs/DEVPOST_FORM.md"):
        p = root / f
        if p.exists():
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if "[fill in]" in line:
                    out.append(f"{f}:{i}: {line.strip()[:110]}")
    return out
