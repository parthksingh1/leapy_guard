# Deploying the public demo

The Docker image runs the web UI in **hosted mode** (`LEAPLY_HOSTED=1`):

- Live runs only on the bundled demo repo (the repo field is disabled; `/api/run` ignores any path).
- Per-visitor limit `LIVE_RUNS_PER_HOUR` (default 3), global `LIVE_RUNS_PER_DAY` (default 40), at most 2 runs at once.
- No PRs from the hosted demo.
- The replay (`replays/*.json`) works with no API calls at all.

## 0. Record the replay first (locally)

```bash
leaply-guard run --package PyJWT --save-replay pyjwt-demo
git add replays/pyjwt-demo.json && git commit -m "Add recorded live run for replay"
```

Open `http://127.0.0.1:8000/?replay=1` to check it.

## 1. Render

1. Push the repo to GitHub.
2. In Render: **New → Blueprint**, select the repo. `render.yaml` defines a Docker web service with `/healthz` as its health check.
3. Set the secret env vars `NEBIUS_API_KEY` and `TAVILY_API_KEY` when prompted.
4. Deploy. Render sets `$PORT`; the container listens on it.

Use at least the `starter` plan: free instances sleep and have little RAM for the sandbox venvs.

## 2. Hugging Face Spaces (Docker)

1. Create a Space: **SDK = Docker**, visibility Public.
2. Add the secrets `NEBIUS_API_KEY` and `TAVILY_API_KEY` in **Settings → Variables and secrets**.
3. Push this repo to the Space:

```bash
git remote add space https://huggingface.co/spaces/YOUR_USER/leaply-guard
git push space main
```

4. Add this header to the top of the Space's `README.md` (Spaces reads it):

```yaml
---
title: Leaply Guard
emoji: 🛡️
colorFrom: green
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
license: mit
---
```

(Keep the GitHub README without this header. Push a separate commit to the Space remote, or add the header only there.)

## 3. Any Docker host

```bash
docker build -t leaply-guard .
docker run -d -p 7860:7860 -e NEBIUS_API_KEY=... -e TAVILY_API_KEY=... leaply-guard
```

## Operating notes

- Each live run creates two virtualenvs (vulnerable and upgraded). The image pre-warms the uv cache, so this takes seconds.
- Runs are written to `/app/runs` inside the container (ephemeral).
- To turn live runs off and serve only the replay, leave `NEBIUS_API_KEY` unset.
