# Video runbook (target 2:50)

## Before you hit record
- [ ] `leaply-guard finish` completed, `replays/pyjwt-demo.json` exists, `python scripts/check_submission.py` is green.
- [ ] Close Slack/WhatsApp/email; Windows **Focus assist → Alarms only**; hide the taskbar clock if you like.
- [ ] Close or collapse any editor tab showing `.env`. Never `cat .env` on screen.
- [ ] Browser: one window, zoom **125%**, dark mode, bookmarks bar hidden, no other tabs.
- [ ] Terminal: font **18pt+**, dark theme, `cls` before each shot.
- [ ] Start the UI: `leaply-guard serve` → open `http://127.0.0.1:8000` (it opens on the recorded live run).
- [ ] Have these tabs ready: the GitHub PR (if opened) and README (architecture diagram).
- [ ] Do one silent rehearsal with a timer.

Recording tip: use the **recorded live run** (it is the real run, replayed at 6×) so the timing is predictable. If you want to show it live, click **Run live demo** and narrate over it; the fallback lines below cover slow steps.

---

## 0:00 – 0:15 · The problem
**Screen:** GitHub PR "Bump PyJWT from 1.7.1 to 2.x", red checks (or the README "The problem" section).
**Say:**
> "This is CVE-2022-29217 in PyJWT. The fix is version 2, but version 2 breaks the code, so this upgrade has been red for months and the vulnerable version is still in production. Leaply Guard does the migration and proves it."

## 0:15 – 0:45 · Scan: the CVE, and is it reachable?
**Screen:** Leaply Guard UI → click **Scan**.
**Say:**
> "Leaply Guard scans the dependencies with OSV. PyJWT 1.7.1 has 12 advisories, including CVE-2022-29217. EPSS and the CISA known-exploited catalog add how likely each one is to be exploited. Then **NVIDIA Nemotron** Nano checks reachability: **REACHABLE**: `service_auth.py` line 21 verifies tokens with a public key and no algorithm allow-list. Not just 'you have a CVE', but 'this line is exploitable'."

**Click:** **Watch recorded run** (or **Fix PyJWT** for a live run).

## 0:45 – 1:30 · Plan, fix, red → green
**Screen:** timeline filling; badges TAVILY, SANDBOX, ULTRA, SUPER, NANO.
**Say:**
> "Tavily pulls the advisory and the official migration guide. Baseline: 15 of 15 tests pass. Now Nemotron Ultra writes a security test, a token forged with the public key. On the vulnerable version the attack is **accepted**. That's red."

*(Proof badge red; test bar drops to 3/16.)*
> "We bump the version and 13 tests break. This is why nobody merges these PRs. Ultra reads the whole repository in its 1-million-token context and writes a plan. Super applies it file by file. The guardrails block an edit to a test file. Failures go to Nano for triage and back to Super…"

*(Bar turns green: 16/16. Proof badge turns green.)*
> "16 of 16. And the same attack is now **rejected**."

## 1:30 – 2:00 · Proof, PR, cost
**Screen:** result card → click **View the attack test** briefly → cost table → (PR tab).
**Say:**
> "Re-scan: zero known vulnerabilities. Ultra reviews the final diff as an adversary. Leaply Guard writes the pull request: reviewer summary, an explanation per file, tests before and after, the security proof, and every source. The cost panel shows the exact tokens and cost of this run per model, and how much the routing saved compared with using Ultra for everything. (Read the two numbers off the screen.)"

## 2:00 – 2:40 · Architecture: which Nemotron does what
**Screen:** README → Mermaid diagram, then the "How we use NVIDIA Nemotron and Nebius Token Factory" table.
**Say (clearly):**
> "Everything runs on **NVIDIA Nemotron 3** through **Nebius Token Factory**. **Ultra**, with its 1M context, plans with the whole repo, writes the attack test and reviews the diff. **Super** makes the edits and fixes. **Nano** handles reachability, failure triage and explanations. Tavily researches at runtime, OSV, EPSS and KEV supply the vulnerability data, and tests run in an isolated environment. Every edit passes guardrails, every call is in an audit log, and when it can't fix something it hands over to a human instead of pretending."

## 2:40 – 2:55 · Impact
**Screen:** terminal: `leaply-guard scan --fail-on reachable-high` (pre-typed), then the MCP section of the README.
**Say:**
> "It runs as a CLI, a web app, an MCP server in Claude Code or Cursor, and a weekly GitHub Action that opens PRs for reachable criticals. Leaply Guard: security upgrades that prove themselves."

---

## Fallback lines (if something is slow or fails on camera)
- **Live run is slow:** "Ultra is reading the whole repository right now; while it thinks, here is the same run recorded earlier." → click **Watch recorded run**.
- **A step fails:** "This is the handover path: Leaply Guard stops, says what it tried, and asks a human instead of shipping a guess." → switch to the recorded run.
- **Network hiccup on Scan:** "OSV is a public API; the recorded run has the same scan." → recorded run.
- **Over time:** cut the 2:40 impact segment to one sentence: "CLI, web, MCP and GitHub Action. Security upgrades that prove themselves."

## Exact commands used on screen
```powershell
leaply-guard serve
leaply-guard scan --fail-on reachable-high
leaply-guard run --package PyJWT          # only if you show a live terminal run
```
