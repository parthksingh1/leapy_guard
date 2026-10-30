"""Web API + UI. Live runs stream as Server-Sent Events; saved runs can be replayed."""
from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from .config import settings
from .events import EventBus
from .pipeline import Pipeline, RunOptions, _new_run_id

WEB = Path(__file__).parent / "web"
REPLAYS = Path(os.environ.get("LEAPLY_REPLAYS_DIR", settings.replays_dir))
PRESETS = {
    "pyjwt-demo": {"label": "Acme auth service · PyJWT 1.7.1 (CVE-2022-29217)", "repo": str(settings.demo_repo), "package": "PyJWT"},
}

app = FastAPI(title="Leaply Guard", docs_url="/api/docs")
RUNS: dict[str, EventBus] = {}
_hits: dict[str, deque] = defaultdict(deque)
_day: deque = deque()
_active = threading.Semaphore(2)


def _client_ip(req: Request) -> str:
    fwd = req.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (req.client.host if req.client else "?")


def _rate_limit(req: Request, bucket: str, per_hour: int) -> None:
    now = time.time()
    key = f"{bucket}:{_client_ip(req)}"
    q = _hits[key]
    while q and now - q[0] > 3600:
        q.popleft()
    if len(q) >= per_hour:
        raise HTTPException(429, f"Rate limit: {per_hour} {bucket}s per hour. Try the replay instead.")
    if bucket == "run":
        while _day and now - _day[0] > 86400:
            _day.popleft()
        if len(_day) >= settings.live_runs_per_day_global:
            raise HTTPException(429, "Daily live-run budget for this demo is used up. The replay shows a recorded live run.")
        _day.append(now)
    q.append(now)


def _repo_for(body: dict) -> tuple[str, str | None]:
    preset = PRESETS.get(body.get("preset") or "pyjwt-demo")
    if settings.hosted or not body.get("repo"):
        if not preset:
            raise HTTPException(400, "unknown preset")
        return preset["repo"], body.get("package") or preset["package"]
    return body["repo"], body.get("package")


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


@app.get("/api/config")
def config():
    replays = []
    if REPLAYS.exists():
        for p in sorted(REPLAYS.glob("*.json")):
            try:
                meta = json.loads(p.read_text(encoding="utf-8"))
                replays.append({"name": p.stem, "saved_at": meta.get("saved_at"), "status": meta.get("status"),
                                "events": len(meta.get("events", []))})
            except (json.JSONDecodeError, OSError):
                continue
    return {
        "live_enabled": settings.llm_enabled,
        "tavily_enabled": bool(settings.tavily_api_key),
        "github_enabled": bool(settings.github_token),
        "hosted": settings.hosted,
        "presets": [{"id": k, "label": v["label"]} for k, v in PRESETS.items()],
        "replays": replays,
        "models": {r: s.model_id for r, s in settings.models.items()},
        "prices": {r: [s.price_in, s.price_out] for r, s in settings.models.items()},
        "limits": {"max_iterations": settings.max_iterations, "max_diff_lines": settings.max_diff_lines,
                   "same_error_limit": settings.same_error_limit, "live_runs_per_hour": settings.live_runs_per_hour},
    }


@app.post("/api/scan")
async def scan(req: Request):
    body = await req.json()
    _rate_limit(req, "scan", 20)
    repo, _ = _repo_for(body)

    def work():
        from .llm import LLM
        from .pipeline import resolve_repo
        from .scan import scan_repo
        from .triage import triage

        bus = EventBus("scan")
        path, _ = resolve_repo(repo, bus)
        deps, findings = scan_repo(path)
        llm = LLM(bus) if settings.llm_enabled else None
        for f in findings:
            triage(path, f, llm)
        findings.sort(key=lambda f: -f.score)
        return {"dependencies": len(deps), "findings": [f.to_dict() for f in findings],
                "cost": llm.ledger.summary(settings.models) if llm else None}

    try:
        return await asyncio.to_thread(work)
    except (FileNotFoundError, RuntimeError) as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/run")
async def start_run(req: Request):
    if not settings.llm_enabled:
        raise HTTPException(503, "Live runs need NEBIUS_API_KEY on the server. Use the replay.")
    body = await req.json()
    _rate_limit(req, "run", settings.live_runs_per_hour if settings.hosted else 1000)
    if not _active.acquire(blocking=False):
        raise HTTPException(429, "Two live runs are already in progress. Try again in a minute or watch the replay.")
    repo, package = _repo_for(body)
    run_id = _new_run_id()
    bus = EventBus(run_id)
    RUNS[run_id] = bus
    opts = RunOptions(repo=repo, package=package, target=None if settings.hosted else body.get("target"),
                      open_pr=bool(body.get("open_pr")) and not settings.hosted)

    def work():
        try:
            Pipeline(opts, bus).run()
        finally:
            _active.release()

    threading.Thread(target=work, daemon=True).start()
    return {"run_id": run_id}


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str, request: Request):
    bus = RUNS.get(run_id)
    if bus is None:
        raise HTTPException(404, "unknown run")

    async def stream():
        i = 0
        last_ping = time.time()
        while True:
            if await request.is_disconnected():
                return
            while i < len(bus.events):
                yield f"data: {json.dumps(bus.events[i], default=str)}\n\n"
                i += 1
            if bus.done and i >= len(bus.events):
                yield "event: end\ndata: {}\n\n"
                return
            if time.time() - last_ping > 15:
                yield ": ping\n\n"
                last_ping = time.time()
            await asyncio.sleep(0.2)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/replays/{name}")
def replay(name: str):
    path = (REPLAYS / f"{name}.json").resolve()
    if path.parent != REPLAYS.resolve() or not path.exists():
        raise HTTPException(404, "replay not found")
    return FileResponse(path, media_type="application/json")


@app.get("/api/runs/{run_id}")
def run_file(run_id: str):
    path = (settings.runs_dir / f"{run_id}.json").resolve()
    if path.parent != settings.runs_dir.resolve() or not path.exists():
        raise HTTPException(404, "run not found (still running?)")
    return FileResponse(path, media_type="application/json")


@app.get("/healthz")
def health():
    return JSONResponse({"ok": True})
