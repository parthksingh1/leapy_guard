# Leaply Guard: Devpost submission draft


**Tagline:** Your repo has a known vulnerability. The fix needs a major version bump that breaks your code. Leaply Guard upgrades it and proves it with your tests.

**Built with:** NVIDIA Nemotron 3 Ultra · Nemotron 3 Super · Nemotron 3 Nano · Nebius Token Factory · Tavily · OSV.dev · Python · FastAPI · Server-Sent Events · MCP · GitHub Actions · Docker

## Inspiration

Every team has the same ticket: "Dependabot: bump PyJWT from 1.7.1 to 2.x (CVE-2022-29217)". The PR is red because 2.x changed the API, so nobody merges it, and the vulnerable version stays. Scanners find the problem. Nobody does the migration. Before this, I built Leaply, which migrates code when an API ships a breaking change. Security upgrades are the most urgent kind of breaking change, so I pointed that idea at CVEs.

## What it does

Paste a repo, click **Scan**. OSV.dev finds the vulnerable packages, FIRST EPSS and the CISA KEV catalog add how likely each one is to be exploited, and Nemotron Nano checks whether your code actually reaches the vulnerable API, with `file:line` evidence. Pick a finding and click **Fix**:

1. Tavily researches the advisory and the official migration guide at runtime.
2. Nemotron Ultra writes a **security regression test**: a real attack (an HS256 token forged with the service's public key) that the vulnerable version accepts. It goes red.
3. The version bump breaks 13 of 16 tests. Red.
4. Ultra reads the **whole repo** (1M context) plus the research and writes a migration plan. Super applies it as diffs, behind guardrails.
5. Tests run in an isolated venv. On failure, Nano triages and Super fixes, up to 6 times, with a handover to a human if the same error repeats.
6. Green: 16/16 tests pass, and the attack is rejected. An OSV re-scan shows 0 known vulnerabilities.
7. Nemotron Ultra reviews the final diff as an adversary (weakened checks, unsafe loaders). A high concern blocks success.
8. A pull request opens with a reviewer summary, per-file explanations, before/after tests, the security proof, cost per model and sources.

Routing keeps a fix at an estimated ~$0.08 in model costs, ~43% less than running every step on Ultra. Every run measures and shows its exact tokens and cost per model.

## How we built it

- **Three Nemotron 3 sizes, one per job.** Ultra (1M context) plans with the whole repo and writes the security test. Super makes the edits and fixes. Nano does reachability, failure triage and explanations. All through Nebius Token Factory with the OpenAI client, with retries, timeouts and per-call token and cost accounting.
- **Tavily** `search` + `extract` at runtime feeds the advisory and the migration guide into the planning prompt. Sources show in the UI and the PR.
- **OSV.dev** batch queries, alias merging (GHSA/PYSEC/CVE) and CVSS 3.x scoring.
- **Verification that cannot be talked around:** pytest in a fresh venv, JUnit parsing, and a security test that only counts if it fails on vulnerable code for the right reason.
- **Guardrails:** repo-scoped edits, no `.env`/CI/lockfiles/unrelated tests, max diff size, a secret scan before any PR, and a full audit log.
- **One event bus** drives the CLI, the live web UI (SSE) and replays of recorded runs. The same engine is exposed as an **MCP server** and a **GitHub Action**.

## Challenges we ran into

- **Model diffs with wrong line numbers.** We wrote a content-anchored diff applier, with a full-file fallback.
- **Proving the security fix, not just the upgrade.** A model-written attack test that fails because of an import error proves nothing. We validate that it fails because the attack succeeded, and fall back to a vetted test when it does not.
- **Finding model IDs** before we had keys, so the IDs are resolved against `/v1/models` at runtime.
- **OSV data:** one issue under 2 or 3 IDs, and mixed severity formats.
- [fill in] anything surprising from the live runs

## Accomplishments that we're proud of

- The red → green moment comes from **real tests and a real attack**, not from a summary written by a model.
- Honest failure: when it cannot fix something, it stops, says so, and lists what it tried.
- Routing across three Nemotron sizes cuts the estimated cost per fix by ~43% compared with Ultra alone.
- One engine, four surfaces: CLI, web UI, MCP, GitHub Action, plus standard outputs: CycloneDX SBOM, OpenVEX, SARIF.
- Two end-to-end demos, an auth bypass (PyJWT) and remote code execution (PyYAML), each with an executable proof.

## What we learned

- Big context changes the design: with Ultra's 1M window, planning needs no retrieval step.
- Cheap models are best at deciding *where to look* (reachability, triage), and expensive models at *what to write*.
- Executable proof beats model confidence. Every claim in the report is counted from the run.

## What's next

- Lockfile resolution (poetry/uv/npm) and JavaScript/TypeScript fixes end to end.
- More vetted security proofs per advisory class (JWT confusion, YAML load, path traversal…).
- Running test sandboxes as Nebius Serverless jobs.
- Org-wide mode: scan every repo, fix reachable criticals first, and track time-to-fix.

---

# 3-minute video script

**0:00–0:15 · Problem**
*(Screen: a GitHub PR "Bump PyJWT from 1.7.1 to 2.x", red checks.)*
"This is CVE-2022-29217 in PyJWT. The fix is version 2. But version 2 breaks the code, so this PR has been red for months, and the vulnerable version is still in production. Leaply Guard does the migration and proves it."

**0:15–0:45 · Scan finds the CVE, Nano marks it REACHABLE**
*(Web UI landing. Click **Scan**.)*
"Leaply Guard scans the dependencies with OSV: PyJWT 1.7.1, 12 advisories, including CVE-2022-29217. EPSS and CISA KEV add exploit likelihood. Nemotron Nano checks reachability: REACHABLE. `service_auth.py` line 21 verifies tokens with a public key and no algorithm allow-list. Not just 'you have a CVE', but 'this line is exploitable'."
*(Click **Fix PyJWT**.)*

**0:45–1:30 · Ultra plans, Super fixes, red → green**
*(Timeline fills; badges TAVILY, SANDBOX, ULTRA.)*
"Tavily pulls the advisory and the official migration guide. Baseline: 15 of 15 tests pass. Now Nemotron Ultra writes a security test: a token forged with the public key. On the vulnerable version, the attack is **accepted**. That's red."
*(Proof badge red. Test bar drops to 3/16.)*
"We bump the version, and 13 tests break. This is why nobody merges these PRs. Ultra reads the whole repo, 1M-token context, and writes a plan. Super applies it file by file. Guardrails reject an edit to a test file. One test still fails; Nano triages it, Super fixes it..."
*(Bar goes green: 16/16. Proof badge turns green.)*
"16 of 16. And the same attack is now **rejected**."

**1:30–2:00 · PR, cost, routing savings**
*(Result card, then the PR on GitHub.)*
"Ultra then reviews its own team's diff as an adversary: approved. Re-scan: 0 known vulnerabilities. Leaply Guard opens a pull request with a reviewer summary, a one-line explanation per file, tests before and after, the security proof, and every source. The cost panel shows every token and every cent per model, and how much routing saved compared with Ultra for everything, because each step uses the smallest model that can do it."

**2:00–2:40 · Architecture: which Nemotron does what**
*(Mermaid diagram from the README.)*
"Three Nemotron 3 models on Nebius Token Factory. **Ultra**, with 1M context, plans with the whole repo and writes the attack test, once per fix. **Super** makes the edits and fixes, many small calls. **Nano** does reachability, failure triage and explanations, cheap and fast. Tavily researches at runtime, OSV supplies the vulnerability data, and tests run in an isolated venv. Every edit passes guardrails, every call is in an audit log, and when the loop can't fix something, it hands over to a human instead of pretending."

**2:40–3:00 · Impact and what's next**
"It runs as a CLI, a web app, an MCP server in Claude Code or Cursor, and a weekly GitHub Action that opens PRs for reachable criticals. Next: lockfiles, JavaScript, and Nebius Serverless sandboxes. Leaply Guard: security upgrades that prove themselves."
