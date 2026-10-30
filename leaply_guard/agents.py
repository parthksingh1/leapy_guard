"""Prompts and calls for each agent role.

Ultra  (1M context): whole-repo migration plan; security regression test.
Super  (fast, strong coder): file edits as unified diffs; fixes from failing tests.
Nano   (cheap, fast): failure triage, reachability, per-file explanations, reviewer summary.
"""
from __future__ import annotations

from pathlib import Path

from .llm import LLM, extract_code, strip_reasoning
from .scan import Finding
from .triage import SKIP_DIRS

TEXT_EXT = {".py", ".txt", ".toml", ".cfg", ".ini", ".md", ".json", ".yaml", ".yml", ".js", ".ts"}


def repo_snapshot(repo: Path, max_chars: int) -> str:
    """The whole repository as one prompt section (Ultra has a 1M-token window)."""
    parts, size = [], 0
    for p in sorted(repo.rglob("*")):
        rel = p.relative_to(repo)
        if not p.is_file() or SKIP_DIRS & set(rel.parts) or p.suffix not in TEXT_EXT or p.name.startswith(".env"):
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        chunk = f"\n===== FILE: {rel.as_posix()} =====\n{text}"
        if size + len(chunk) > max_chars:
            parts.append(f"\n===== (truncated: repository larger than {max_chars} chars) =====")
            break
        parts.append(chunk)
        size += len(chunk)
    return "".join(parts)


def _advisories(f: Finding) -> str:
    return "\n".join(f"- {a.id} / {a.cve or '-'} [{a.severity}] fixed in {a.fixed or '?'}: {a.summary}" for a in f.advisories[:10])


def _research(extracts: list[dict], budget: int = 40000) -> str:
    out, size = [], 0
    for e in extracts:
        chunk = f"\n--- SOURCE: {e['url']} ---\n{e['content']}"
        if size + len(chunk) > budget:
            chunk = chunk[: max(0, budget - size)]
        out.append(chunk)
        size += len(chunk)
        if size >= budget:
            break
    return "".join(out) or "(no web research available; rely on your knowledge of the library's changelog)"


def plan_migration(llm: LLM, finding: Finding, target: str, snapshot: str, research: dict,
                   reachability: dict, failing: str, step: str = "plan") -> dict:
    prompt = f"""You are a senior engineer planning a security upgrade.

Upgrade {finding.package.name} from {finding.package.version} to {target} to close:
{_advisories(finding)}

Reachability triage: {reachability.get('verdict')} - {reachability.get('reasoning', '')}

After bumping the version with no code changes, the test suite fails like this:
{failing[:6000]}

Research (security advisory, migration guide, changelog):
{_research(research.get('extracts', []))}

The full repository:
{snapshot}

Produce a precise migration plan. Change only what the upgrade requires, keep behaviour identical, and
close the vulnerability properly (e.g. always pass an explicit algorithms allow-list when verifying JWTs).
Do NOT edit test files and do NOT edit dependency files (the version bump is done separately).

Reply with JSON only:
{{
  "summary": "one paragraph",
  "breaking_changes": ["each API change in the new version that affects this repo"],
  "files": [
    {{"path": "relative/path.py", "changes": ["exact change 1", "exact change 2"], "why": "short reason", "risk": "low|medium|high"}}
  ],
  "security_notes": "how the change closes the advisory",
  "risks": ["what a reviewer should double-check"],
  "overall_risk": "low|medium|high"
}}"""
    return llm.chat_json("ultra", "migration plan", [{"role": "user", "content": prompt}], step=step,
                         max_tokens=8192, temperature=0.1)


def write_security_test(llm: LLM, finding: Finding, snapshot: str, research: dict, advisory_id: str,
                        step: str = "proof") -> str:
    prompt = f"""You write defensive security regression tests for our own application.

Our app depends on {finding.package.name} {finding.package.version}, affected by:
{_advisories(finding)}
Focus on: {advisory_id}

Research:
{_research(research.get('extracts', []), 15000)}

Our repository:
{snapshot}

Write ONE pytest file that proves our application is protected against this specific advisory.
Rules:
- Import from our app modules exactly as the existing tests do (look at tests/conftest.py).
- Build the malicious input by hand with the standard library (base64, hmac, hashlib, json) so the test does not
  depend on the library version under test.
- The test must FAIL on the current vulnerable code (the attack is accepted) and PASS once the app is fixed
  (the attack is rejected with the app's own error type).
- Use only the public helpers our app already exposes (for keys, use the app's own key functions).
- No network, no sleeps. One or two test functions, named test_<cve>_....
Reply with only the Python file in a ```python block."""
    return extract_code(llm.chat("ultra", "security regression test", [{"role": "user", "content": prompt}],
                                 step=step, max_tokens=4096, temperature=0.1))


def edit_file(llm: LLM, path: str, content: str, item: dict, plan: dict, finding: Finding, target: str,
              feedback: str = "", step: str = "edit") -> str:
    prompt = f"""Apply this migration step to one file. Upgrade: {finding.package.name} {finding.package.version} -> {target}.

Breaking changes in the new version: {plan.get('breaking_changes')}
Planned changes for {path}:
{chr(10).join('- ' + c for c in item.get('changes', []))}
Why: {item.get('why', '')}
{('Previous attempt was rejected: ' + feedback) if feedback else ''}

Current content of {path}:
```python
{content}
```

Reply with ONLY a unified diff for this single file (--- a/{path} / +++ b/{path}, @@ hunks with 3 lines of context).
Change nothing else."""
    return strip_reasoning(llm.chat("super", f"edit {path}", [{"role": "user", "content": prompt}], step=step,
                                    max_tokens=4096, temperature=0.0))


def rewrite_file(llm: LLM, path: str, content: str, instructions: str, step: str) -> str:
    """Fallback when a diff does not apply: ask for the full file."""
    prompt = f"""Rewrite {path} applying exactly these changes and nothing else:
{instructions}

Current content:
```python
{content}
```
Reply with the complete new file in one ```python block."""
    return extract_code(llm.chat("super", f"rewrite {path}", [{"role": "user", "content": prompt}], step=step,
                                 max_tokens=8192, temperature=0.0))


def triage_failure(llm: LLM, failures: str, files: list[str], step: str) -> dict:
    prompt = f"""Classify these failing test results after a dependency upgrade.

Failures:
{failures[:8000]}

Editable source files: {files}

Reply with JSON only:
{{"category": "api_change|import_error|assertion|test_env|flaky|other", "root_cause": "one sentence",
  "files": ["source files most likely to need a fix, from the editable list"], "signature": "short stable error signature"}}"""
    return llm.chat_json("nano", "failure triage", [{"role": "user", "content": prompt}], step=step,
                         max_tokens=1024, temperature=0.0)


def fix_file(llm: LLM, path: str, content: str, failures: str, triage: dict, finding: Finding, target: str,
             step: str) -> str:
    prompt = f"""Tests fail after upgrading {finding.package.name} to {target}. Fix {path}.

Triage: {triage.get('root_cause')}
Failing output:
{failures[:6000]}

Current content of {path}:
```python
{content}
```
Reply with ONLY a unified diff for {path} (--- a/{path} / +++ b/{path}). Do not weaken security checks."""
    return strip_reasoning(llm.chat("super", f"fix {path}", [{"role": "user", "content": prompt}], step=step,
                                    max_tokens=4096, temperature=0.0))


def explain_changes(llm: LLM, diffs: dict[str, str], finding: Finding, target: str, step: str = "explain") -> dict:
    body = "\n\n".join(f"### {p}\n{d[:3000]}" for p, d in diffs.items())
    prompt = f"""For each changed file in this {finding.package.name} {finding.package.version} -> {target} security upgrade,
write one plain-English sentence (max 20 words) a reviewer can read next to the diff. Then write a reviewer summary.

{body}

Reply with JSON only:
{{"files": {{"path": "one sentence"}},
  "reviewer_summary": {{"what_changed": "2 sentences", "risk": "low|medium|high", "double_check": ["specific things a human should verify"]}}}}"""
    return llm.chat_json("nano", "explain changes", [{"role": "user", "content": prompt}], step=step,
                         max_tokens=2048, temperature=0.1)


def estimate_cost(repo: Path, finding: Finding, models: dict, max_chars: int = 1_500_000) -> dict:
    """Rough pre-run estimate (shown as an estimate, never as a result): tokens per role from repo size and usage count."""
    repo_tok = len(repo_snapshot(repo, max_chars)) // 4
    files = {u["file"] for u in (finding.reachability.get("evidence") or [])} or {"x"}
    n_files = max(len(files), (finding.reachability.get("usage_count") or 2) // 2)
    reasoning = 3  # Nemotron 3 reasons before answering; output budget is mostly thinking
    plan = {
        "ultra": (2 * repo_tok + 18000, 2 * 2000 * reasoning),
        "super": (n_files * 2 * 1500, n_files * 2 * 500 * reasoning),
        "nano": (8000, 1200 * reasoning),
    }
    rows = {r: {"tokens_in": t_in, "tokens_out": t_out, "cost_usd": round(models[r].cost(t_in, t_out), 4)} for r, (t_in, t_out) in plan.items()}
    total = sum(r["cost_usd"] for r in rows.values())
    all_ultra = sum(models["ultra"].cost(r["tokens_in"], r["tokens_out"]) for r in rows.values())
    return {"repo_tokens": repo_tok, "per_role": rows, "estimate_usd": round(total, 4),
            "range_usd": [round(total * 0.5, 4), round(total * 2, 4)], "all_ultra_usd": round(all_ultra, 4)}


def security_review(llm: LLM, diffs: dict[str, str], finding: Finding, target: str, step: str = "review") -> dict:
    """Critic agent: an adversarial review of the final diff before anything is delivered."""
    body = "\n".join(diffs.values())[:40000]
    prompt = f"""You are a strict security reviewer. An automated agent upgraded {finding.package.name}
{finding.package.version} -> {target} to close: {', '.join((a.cve or a.id) for a in finding.advisories[:6])}.

Review this final diff. Look for: weakened or removed security checks, disabled verification, broad exception
swallowing, unsafe loaders/deserialisers, algorithm allow-lists that include unsafe options, secrets, unrelated
changes, and behaviour changes that tests might not catch.

{body}

Reply with JSON only:
{{"verdict": "approve|concerns", "findings": [{{"file": "...", "severity": "low|medium|high", "issue": "one sentence"}}],
  "summary": "one sentence"}}"""
    return llm.chat_json("ultra", "security review of final diff", [{"role": "user", "content": prompt}], step=step,
                         max_tokens=4096, temperature=0.0)
