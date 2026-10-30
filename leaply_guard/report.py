"""Markdown report / PR body, delivery (git branch, GitHub PR, or report.md), and SARIF export."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import httpx

from .config import settings
from .patching import diff_stats


def _tests(t: dict | None) -> str:
    if not t:
        return "n/a"
    return f"{t.get('passed', 0)}/{t.get('total', 0)} passing" + (f", {t['failed'] + t['errors']} failing" if t.get("failed") or t.get("errors") else "")


def result_card(data: dict) -> str:
    f = data.get("finding", {})
    adv = f.get("advisories", [{}])[0] if f else {}
    proof = data.get("proof", {})
    cost = data.get("cost", {})
    after = data.get("tests_after", {})
    cve = data.get("proof", {}).get("cve") or adv.get("cve") or adv.get("id", "")
    closed = "closed" if not data.get("rescan", {}).get("remaining") else "partially closed"
    return (f"{cve} {closed} · {after.get('passed', 0)}/{after.get('total', 0)} tests passing · "
            f"security proof {'passing' if proof.get('after') == 'passed' else proof.get('after') or 'n/a'} · "
            f"{data.get('iterations', 0)} iteration(s) · ${cost.get('total_cost_usd', 0):.4f} · "
            f"{cost.get('routing_savings_pct', 0):.0f}% saved by routing")


def build_report(data: dict, run_id: str) -> str:
    f = data.get("finding", {})
    pkg = f.get("package", {})
    target = data.get("target")
    rs = data.get("reviewer_summary", {})
    proof = data.get("proof", {})
    reach = f.get("reachability", {})
    conf = data.get("confidence", {})
    rescan = data.get("rescan", {})
    cost = data.get("cost", {})
    g = data.get("guardrails", {})
    status = data.get("status", "")
    L = []
    L.append(f"# Leaply Guard: upgrade {pkg.get('name')} {pkg.get('version')} → {target}")
    L.append("")
    L.append(f"> {result_card(data)}")
    L.append("")
    if status == "needs_review" or conf.get("needs_human_review"):
        h = data.get("handover", {})
        L.append("**⚠ Needs human review.** " + (h.get("reason", "") or "Confidence below threshold."))
        for t in h.get("tried", []):
            L.append(f"- tried: {t}")
        L.append("")
    L.append("## Reviewer summary")
    L.append(f"- **What changed:** {rs.get('what_changed', data.get('plan', {}).get('summary', ''))}")
    L.append(f"- **Risk:** {rs.get('risk', data.get('plan', {}).get('overall_risk', 'n/a'))}")
    L.append(f"- **Confidence:** {conf.get('score', 0)}/100 ({conf.get('level', 'n/a')}) — " + "; ".join(conf.get("reasons", [])))
    checks = rs.get("double_check") or data.get("plan", {}).get("risks") or []
    if checks:
        L.append("- **Please double-check:**")
        L += [f"  - {c}" for c in checks]
    L.append("")
    L.append("## Advisories")
    L.append("| ID | CVE | Severity | EPSS | CISA KEV | Fixed in | Summary |")
    L.append("|---|---|---|---|---|---|---|")
    for a in f.get("advisories", []):
        epss = f"{a['epss'] * 100:.1f}%" if a.get("epss") is not None else "-"
        L.append(f"| [{a['id']}]({a['url']}) | {a.get('cve') or '-'} | {a['severity']} | {epss} | {'**yes**' if a.get('kev') else 'no'} | {a.get('fixed') or '-'} | {a['summary']} |")
    L.append("")
    L.append(f"**Reachability ({reach.get('by', 'static')}):** {reach.get('verdict', 'n/a')} — {reach.get('reasoning', '')}")
    for e in reach.get("evidence", [])[:6]:
        L.append(f"- `{e.get('file')}:{e.get('line')}` {e.get('why', '')}")
    L.append("")
    L.append("## Proof")
    L.append("| Check | Before | After bump (no code change) | After Leaply Guard |")
    L.append("|---|---|---|---|")
    L.append(f"| Test suite | {_tests(data.get('tests_before'))} | {_tests(data.get('tests_after_bump'))} | {_tests(data.get('tests_after'))} |")
    L.append(f"| Security proof ({proof.get('cve') or proof.get('advisory')}) | "
             f"{'attack accepted ❌' if proof.get('before') == 'failed' else proof.get('before')} | — | "
             f"{'attack rejected ✅' if proof.get('after') == 'passed' else proof.get('after')} |")
    remaining = rescan.get("remaining", [])
    L.append(f"| OSV re-scan of {rescan.get('package')} {rescan.get('version')} | {len(f.get('advisories', []))} advisories | — | "
             f"{len(remaining)} known vulnerabilities{' (' + ', '.join(remaining) + ')' if remaining else ''} |")
    pa = rescan.get("pip_audit", {})
    if pa.get("ran"):
        L.append(f"| pip-audit | — | — | {pa.get('vulnerabilities')} vulnerabilities |")
    L.append("")
    L.append(f"Fix iterations: **{data.get('iterations', 0)}**. Security test source: "
             f"{'written by Nemotron 3 Ultra and validated (fails on vulnerable code)' if proof.get('source') == 'ultra' else 'vetted template (model-written test failed validation)' if proof.get('source') == 'vetted' else 'none'}.")
    L.append("")
    L.append("## Changes")
    expl = data.get("explanations", {})
    total_add = total_rem = 0
    for path, d in data.get("diff", {}).items():
        a, r = diff_stats(d)
        total_add, total_rem = total_add + a, total_rem + r
        L.append(f"- `{path}` (+{a} −{r}): {expl.get(path, '')}")
    L.append(f"\n**{len(data.get('diff', {}))} files, +{total_add} −{total_rem}.**")
    L.append("")
    L.append("<details><summary>Full diff</summary>\n\n```diff\n" + "".join(data.get("diff", {}).values()) + "```\n</details>")
    L.append("")
    L.append("## Guardrails")
    L.append(f"- Status: **{g.get('status', 'n/a')}** ({g.get('checks', 0)} checks; max diff {g.get('max_diff_lines')} lines)")
    L.append(f"- Rejected edits: {len(g.get('rejected_edits', []))}" + "".join(f"\n  - {v}" for v in g.get("rejected_edits", [])))
    L.append(f"- Secret scan on final diff: {'clean' if not g.get('secrets_found') else str(len(g['secrets_found'])) + ' findings — PR blocked'}")
    L.append("")
    L.append("## Models, tokens and cost")
    L.append("| Step owner | Model | Calls | Tokens in | Tokens out | Cost (USD) |")
    L.append("|---|---|---|---|---|---|")
    for r in cost.get("rows", []):
        L.append(f"| Nemotron 3 {r['role'].title()} | `{r['model']}` | {r['calls']} | {r['tokens_in']:,} | {r['tokens_out']:,} | ${r['cost_usd']:.4f} |")
    L.append(f"| **Total** | | | | | **${cost.get('total_cost_usd', 0):.4f}** |")
    L.append(f"\nSame run with every call on Ultra: ${cost.get('all_ultra_cost_usd', 0):.4f} → **{cost.get('routing_savings_pct', 0):.0f}% saved by model routing.**")
    L.append("")
    L.append("## Sources")
    for s in data.get("sources", [])[:12]:
        L.append(f"- [{s['title'][:110]}]({s['url']}) ({s.get('via')})")
    L.append("")
    L.append(f"---\nGenerated by Leaply Guard (run `{run_id}`) with NVIDIA Nemotron 3 on Nebius Token Factory. Tests ran in an isolated virtualenv. No auto-merge.")
    return "\n".join(L)


# -- delivery ---------------------------------------------------------------------------------
def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=120)


def _scrub(text: str) -> str:
    return text.replace(settings.github_token, "***") if settings.github_token else text


def deliver(pipe, data: dict, src: Path, gh_repo: str | None) -> dict:
    run_dir = pipe.cfg.runs_dir / pipe.run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text(data["report_md"], encoding="utf-8")
    patch = "".join(data.get("diff", {}).values())
    (run_dir / "changes.patch").write_text(patch, encoding="utf-8")
    (run_dir / "findings.sarif").write_text(json.dumps(sarif(data), indent=1), encoding="utf-8")
    out = {"report_path": str(run_dir / "report.md"), "patch_path": str(run_dir / "changes.patch"), "pr_url": None, "branch": None}
    if data.get("guardrails", {}).get("secrets_found"):
        out["note"] = "secret scan found possible credentials in the diff; no branch or PR created"
        return out
    pkg = data["finding"]["package"]["name"].lower()
    branch = f"leaply-guard/{pkg}-{data['target']}"
    want_pr = pipe.opts.open_pr and gh_repo and settings.github_token and data.get("status") == "success"
    if not (pipe.opts.branch or want_pr):
        out["note"] = "PR body written to report.md" + ("" if settings.github_token else " (set GITHUB_TOKEN to open a real pull request)")
        return out
    if not (src / ".git").exists():
        out["note"] = "source is not a git repository; wrote report.md and changes.patch"
        return out
    if _git(["status", "--porcelain"], src).stdout.strip() and not gh_repo:
        out["note"] = "working tree has uncommitted changes; not creating a branch. Apply changes.patch manually."
        return out
    _git(["checkout", "-B", branch], src)
    for path in data["diff"]:
        target = src / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(pipe.ws.read(path), encoding="utf-8", newline="\n")
        _git(["add", path], src)
    msg = f"Upgrade {pkg} to {data['target']} ({data.get('proof', {}).get('cve') or 'security fix'})\n\nGenerated by Leaply Guard."
    c = _git(["-c", "user.name=Leaply Guard", "-c", "user.email=leaply-guard@users.noreply.github.com", "commit", "-m", msg], src)
    out["branch"] = branch
    out["commit"] = c.returncode == 0
    if not want_pr:
        out["note"] = f"committed on local branch {branch}"
        return out
    url = f"https://x-access-token:{settings.github_token}@github.com/{gh_repo}.git"
    p = _git(["push", "-f", url, f"{branch}:{branch}"], src)
    if p.returncode != 0:
        out["note"] = "push failed: " + _scrub(p.stderr[-300:]) + " (PR body is in report.md)"
        return out
    with httpx.Client(timeout=30, headers={"Authorization": f"Bearer {settings.github_token}",
                                           "Accept": "application/vnd.github+json"}) as gh:
        base = gh.get(f"https://api.github.com/repos/{gh_repo}").json().get("default_branch", "main")
        r = gh.post(f"https://api.github.com/repos/{gh_repo}/pulls", json={
            "title": f"security: upgrade {pkg} to {data['target']} ({data.get('proof', {}).get('cve') or ''})".strip(),
            "head": branch, "base": base, "body": data["report_md"][:65000], "maintainer_can_modify": True})
        if r.status_code in (200, 201):
            out["pr_url"] = r.json()["html_url"]
        else:
            out["note"] = f"GitHub API {r.status_code}: {_scrub(r.text[:200])}"
    return out


# -- SARIF 2.1.0 --------------------------------------------------------------------------------
def sarif(data: dict) -> dict:
    f = data.get("finding") or {}
    pkg = f.get("package", {})
    fixed = data.get("status") == "success"
    level = {"CRITICAL": "error", "HIGH": "error", "MODERATE": "warning", "MEDIUM": "warning", "LOW": "note"}
    rules, results = [], []
    for a in f.get("advisories", []):
        rules.append({
            "id": a["id"], "name": (a.get("cve") or a["id"]).replace("-", ""),
            "shortDescription": {"text": a["summary"][:200]},
            "helpUri": a["url"],
            "properties": {"security-severity": str(a.get("cvss_score") or 5.0), "tags": ["security", "dependency"]},
        })
        results.append({
            "ruleId": a["id"], "level": level.get(a["severity"], "warning"),
            "message": {"text": f"{pkg.get('name')} {pkg.get('version')} is affected by {a.get('cve') or a['id']}. "
                                f"Reachability: {f.get('reachability', {}).get('verdict', 'unknown')}. "
                                + (f"Fixed by Leaply Guard: upgraded to {data.get('target')}." if fixed else f"Fixed in {a.get('fixed')}.")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": pkg.get("file", "requirements.txt")},
                                                "region": {"startLine": max(1, pkg.get("line", 1))}}}],
            "properties": {"fixStatus": "fixed" if fixed else "open", "reachability": f.get("reachability", {}).get("verdict")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Leaply Guard", "informationUri": "https://github.com/", "rules": rules}},
                  "results": results}],
    }
