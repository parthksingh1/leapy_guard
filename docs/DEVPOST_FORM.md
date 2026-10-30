# Devpost form: copy-paste fields, in order

## 1. Project name
```
Leaply Guard
```

## 2. Elevator pitch / tagline (≤ 200 characters)
```
Your repo has a known vulnerability. The fix is a breaking major upgrade. Leaply Guard upgrades it with NVIDIA Nemotron and proves it with your tests and a real attack.
```

## 3. Track
```
Coding and Agentic Engineering
```

## 4. About the project (Markdown)
```markdown
## Inspiration
Every team has the ticket "Dependabot: bump PyJWT 1.7.1 → 2.x (CVE-2022-29217)". The PR is red because 2.x changed the API, so nobody merges it, and the vulnerable version stays in production. Scanners find the problem; nobody does the migration.

## What it does
Paste a repo and click **Scan**. OSV.dev finds the vulnerable packages, FIRST EPSS and the CISA KEV catalog add how likely each one is to be exploited, and **NVIDIA Nemotron 3 Nano** checks whether your code actually reaches the vulnerable API (REACHABLE, with `file:line` evidence). Click **Fix**:

1. **Tavily** researches the advisory and the official migration guide at runtime.
2. **Nemotron 3 Ultra** writes a security regression test: a real attack (an HS256 token forged with the service's public key). On PyJWT 1.7.1 the attack is accepted. Red.
3. Bumping to PyJWT {{TARGET_VERSION}} breaks 13 of 16 tests. Red.
4. Ultra reads the whole repository (1M-token context) plus the research and writes a migration plan; **Nemotron 3 Super** applies it as diffs behind guardrails.
5. Tests run in an isolated virtualenv; Nano triages failures and Super fixes them, with a handover to a human if the same error repeats.
6. Green: {{TESTS_AFTER}} tests pass and the attack is rejected. An OSV re-scan shows 0 known vulnerabilities. Ultra reviews the final diff as an adversary.
7. A pull request opens with a reviewer summary, per-file explanations, before/after tests, the security proof, cost per model and every source.

Recorded live run: {{ITERATIONS}} fix iteration(s), {{RUN_TIME}}, {{TOTAL_TOKENS}} tokens, **{{TOTAL_COST}}**, **{{SAVINGS_PCT}}% cheaper than running every step on Ultra**.

## How we built it
- **NVIDIA Nemotron 3 on Nebius Token Factory**, one model per job: Ultra (1M context) plans and writes the attack test and the security review; Super edits and fixes; Nano does reachability, failure triage and explanations. OpenAI-compatible client, with retries, timeouts, and per-call token and cost accounting.
- **Tavily** `search` + `extract` feed the advisory and migration guide into the plan.
- **OSV.dev, FIRST EPSS, CISA KEV** for vulnerability data and priority.
- Verification you cannot talk around: pytest in a fresh venv, plus a security test that only counts if it fails on vulnerable code for the right reason.
- Guardrails (repo scope, no `.env`/CI/lockfiles/tests), secret scan, audit log, confidence score.
- One event bus drives the CLI, a live web UI (Server-Sent Events), replays, an MCP server and a GitHub Action. Exports: SARIF, CycloneDX SBOM, OpenVEX.

## Challenges we ran into
- Model diffs with wrong line numbers: we built a content-anchored diff applier with a full-file fallback.
- Proving the security fix, not just the upgrade: a model-written attack test that fails because of an import error proves nothing, so we validate the reason it fails.
- OSV reports one issue under 2 or 3 IDs with mixed severity formats; we merge aliases and compute CVSS ourselves.

## Accomplishments that we're proud of
- The red → green moment comes from real tests and a real attack.
- Honest failure: when it cannot fix something, it stops and says what it tried.
- {{SAVINGS_PCT}}% saved by routing across three Nemotron sizes.
- Two end-to-end demos: an auth bypass (PyJWT) and remote code execution (PyYAML).

## What we learned
- With a 1M-token context, planning needs no retrieval step.
- Small models are best at deciding where to look; big models at what to write.
- Executable proof beats model confidence.

## What's next
Lockfile resolution, JavaScript end to end, more vetted attack proofs, Nebius Serverless sandboxes, org-wide mode.
```

## 5. Built with
```
nvidia-nemotron, nemotron-3-ultra, nemotron-3-super, nemotron-3-nano, nebius-token-factory, tavily, osv.dev, epss, cisa-kev, python, fastapi, server-sent-events, tailwindcss, diff2html, model-context-protocol, github-actions, docker, pytest
```

## 6. Links ("Try it out")
```
GitHub:      https://github.com/<YOUR_USER>/leaply-guard
Live demo:   https://<your-app>.onrender.com   (or https://huggingface.co/spaces/<YOUR_USER>/leaply-guard)
Video:       https://youtu.be/<VIDEO_ID>
```

## 7. Feedback on Nebius Token Factory, NVIDIA Nemotron and Tavily
Paste the edited contents of [FEEDBACK.md](../FEEDBACK.md).

## 8. Pre-existing project: what is new
```
Leaply Guard is new code written during the hackathon. It builds on ideas from my earlier project Leaply (repo "Migrator", TypeScript), which migrates customer code when an API ships a breaking change (OpenAI SDK v0→v1 pack, ast-grep rules first, validation before/after, a human approves every PR). No code was copied; Leaply Guard is a separate Python codebase.

Carried over as ideas: deterministic edits first, validate with the repo's own tests before and after, constrain what the model may touch, count numbers from the run, no auto-merge.

New during the hackathon: the security product itself (OSV scan, EPSS + CISA KEV, reachability triage), three-model routing on Nebius Token Factory with cost accounting, Tavily runtime research, the executable security proof, the fix loop with handover, the adversarial review, guardrails and audit log, the web UI with live streaming and replay, MCP server, GitHub Action, SARIF / CycloneDX / OpenVEX exports, Docker deploy, and both demo apps with their test suites.
```
