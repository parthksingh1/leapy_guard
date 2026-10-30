# Deploying the public demo (under 10 minutes)

The Docker image serves the web UI in **hosted mode** (`LEAPLY_HOSTED=1`):
- live runs only on the bundled demo repos, `LIVE_RUNS_PER_HOUR` per visitor (default 3), `LIVE_RUNS_PER_DAY` overall (default 40), at most 2 at once, no PRs;
- the page opens on the **recorded live run** (`replays/pyjwt-demo.json`), which needs no API calls at all.

**Before deploying:** run `leaply-guard finish` locally, then commit and push. The replay must be in the repo.

---

## Option A: Render (≈ 6 minutes)

1. Push the repo to GitHub (`gh repo create leaply-guard --public --source . --remote origin --push`).
2. Open **https://dashboard.render.com** → **New +** → **Blueprint**.
3. **Connect** your GitHub account if asked, then pick the `leaply-guard` repo → **Connect**.
4. Render reads `render.yaml` and shows one web service, `leaply-guard` (Docker). Fill in the two secret fields:
   - `NEBIUS_API_KEY` = your key
   - `TAVILY_API_KEY` = your key
5. Click **Apply**. The first build takes 3–5 minutes (it pre-warms the demo packages).
6. When the service shows **Live**, open the `https://leaply-guard-xxxx.onrender.com` URL. You should land on the recorded run. Check `/healthz` returns `{"ok": true}`.

Plan: `render.yaml` uses **starter** (always on, enough RAM for the test sandboxes). To use **free**, change `plan: starter` to `plan: free`; it sleeps after 15 idle minutes (the first visit then takes about 50 s).

## Option B: Hugging Face Spaces (≈ 8 minutes)

1. Open **https://huggingface.co/new-space**.
   - Owner: you · Space name: `leaply-guard` · License: MIT
   - **SDK: Docker** → template **Blank** · Hardware: **CPU basic (free)** · Visibility: **Public**
   - Click **Create Space**.
2. In the Space: **Settings → Variables and secrets → New secret**:
   - `NEBIUS_API_KEY` = your key
   - `TAVILY_API_KEY` = your key
3. Create an access token with write access at **https://huggingface.co/settings/tokens**.
4. From the repo root (clean working tree):
   ```powershell
   git remote add space https://huggingface.co/spaces/<YOUR_HF_USER>/leaply-guard
   python scripts/make_hf_space.py          # makes branch hf-space with the Space README header
   git push space hf-space:main --force     # user: your HF username, password: the token
   git checkout master
   ```
5. The Space builds (≈ 4 minutes; watch **Logs → Build**). When it says **Running**, open `https://huggingface.co/spaces/<YOUR_HF_USER>/leaply-guard`.

## Option C: any Docker host

```bash
docker build -t leaply-guard .
docker run -d -p 7860:7860 -e NEBIUS_API_KEY=... -e TAVILY_API_KEY=... leaply-guard
# http://localhost:7860
```

## Smoke test after deploy
- The page opens on the recorded run, and the badge reads **Recorded live run**.
- **Scan** shows PyJWT 1.7.1 with EPSS and the reachability verdict.
- `GET /api/config` shows `"hosted": true`.
- Optional: **Run live demo** once (it uses your credits; the rate limit protects the rest).

## Operating notes
- Each live run creates two virtualenvs; the image pre-warms the uv cache, so this takes seconds.
- Runs are written to `/app/runs` inside the container (ephemeral).
- To serve only the recording, leave `NEBIUS_API_KEY` unset: the **Run live demo** button is disabled, and the recording still plays.
