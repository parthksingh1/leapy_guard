# Feedback: Nebius Token Factory, NVIDIA Nemotron 3, Tavily, OSV.dev

> **Draft.** Items marked **[observed]** happened while building Leaply Guard. Items marked **[fill in]** are prompts for my own experience from live runs. Edit before submitting.

## Nebius Token Factory

**What worked**
- **[observed]** OpenAI compatibility: the standard `openai` Python client works with only `base_url` and `api_key` changed, so one code path serves three model sizes.
- **[fill in]** Latency and throughput for Ultra on large prompts (our planning prompt holds the whole repo plus the research, about N tokens): first-token time and total time.
- **[fill in]** `usage` fields: are `prompt_tokens` / `completion_tokens` present on every response, including reasoning tokens?

**What needs work**
- **[observed]** Model IDs are hard to find before you have a key. Public pages name "Nemotron 3 Ultra" but not its exact, case-sensitive API ID. We had to build auto-resolution against `/v1/models` (case fixes, closest match). A public, copy-pasteable model ID table per model would save every team this step.
- **[observed]** Mixed casing across IDs (`nvidia/Nemotron-3-Ultra-…`, `nvidia/nemotron-3-super-…`, `nvidia/NVIDIA-Nemotron-3-Nano-…`) invites typo 404s. Case-insensitive matching, or a "did you mean" in the 404 body, would help.
- **[fill in]** Rate limits: were 429s documented, and did responses include `Retry-After`?
- **[fill in]** Pricing page vs. what the dashboard bills: did per-call costs we computed match?

**Onboarding**
- **[fill in]** Time from sign-up to first successful call, credits, and any friction (verification, region selection, key creation).

## NVIDIA Nemotron 3 (Ultra, Super, Nano together)

**What worked**
- **[observed, design]** Three sizes from one family make routing natural: the same prompt style and output conventions work across Ultra, Super and Nano, so moving a step to a cheaper model is a config change, not a prompt rewrite.
- **[fill in]** Ultra with the whole repo in context: did the plan list every call site (6 in the demo, across 3 files)?
- **[fill in]** Super's unified diffs: how often did they apply cleanly? (Our applier ignores line numbers and matches hunks by content. Count how often the full-file fallback was needed.)
- **[fill in]** Nano's reachability verdicts and failure triage: correct on the demo? Was JSON-only output reliable?
- **[fill in]** Routing savings on the demo run: X% vs. all-Ultra.

**What needs work**
- **[observed, defensive code]** Reasoning output: we strip `<think>…</think>` and handle answers that are cut off during reasoning (empty content with `finish_reason=length`) by retrying with a larger budget. **[fill in]** Did this happen in practice? A documented per-request switch for reasoning on/off, the same across all three sizes, would make cost more predictable.
- **[fill in]** Any JSON-mode / structured-output support differences between the three sizes.

## Tavily

**What worked**
- **[observed]** `search` + `extract` is the right split for an agent: search finds the advisory and the migration guide; extract with a `query` returns only the relevant chunks, which keeps Ultra's prompt focused.
- **[fill in]** Quality of results for "PyJWT 1.x to 2.0 migration guide": did the official changelog rank first?

**What needs work**
- **[fill in]** Extract failures (`failed_results`) on any docs sites? Latency of `advanced` depth?
- **[fill in]** Would a "prefer official docs / changelogs" domain hint help for package research?

## OSV.dev

**What worked**
- **[observed]** No key, a fast batch endpoint (`/v1/querybatch`), and full records at `/v1/vulns/{id}`. For PyJWT 1.7.1 it returned 21 IDs that collapse to 12 distinct advisories, from CVE-2022-29217 to 2026 advisories.

**What needs work**
- **[observed]** The same issue appears under several IDs (GHSA, PYSEC, CVE aliases). Every client has to merge aliases itself; a `?dedupe=true` or an alias group ID in batch results would help.
- **[observed]** Severity is inconsistent: GHSA records carry `database_specific.severity`, while PYSEC records often carry only a CVSS vector (we compute the base score ourselves), and some have neither.
- **[observed]** Ranges use `fixed` in most records and `last_affected` in some (e.g. PYSEC-2025-183), so "what version fixes everything" needs care.

## Python MCP SDK (bonus)

- **[observed]** `mcp` 2.x renamed `FastMCP` to `MCPServer` (`mcp.server.mcpserver`). Code written against 1.x tutorials fails at import. The error message pointed to the migration guide, which helped. We support both.
