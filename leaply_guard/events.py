"""Run events: every step of the pipeline is an event. The UI, the CLI and replays all consume the same stream."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable

Listener = Callable[[dict], None]


class EventBus:
    def __init__(self, run_id: str, mode: str = "live"):
        self.run_id = run_id
        self.mode = mode  # live | replay
        self.events: list[dict] = []
        self.started = time.time()
        self._listeners: list[Listener] = []
        self._lock = threading.Lock()
        self.cost_usd = 0.0
        self.done = False

    def subscribe(self, fn: Listener) -> None:
        self._listeners.append(fn)

    def emit(self, kind: str, step: str = "", actor: str = "system", **data: Any) -> dict:
        with self._lock:
            event = {
                "seq": len(self.events),
                "t": round(time.time() - self.started, 3),
                "run_id": self.run_id,
                "kind": kind,
                "step": step,
                "actor": actor,
                "cost_so_far": round(self.cost_usd, 6),
                **data,
            }
            self.events.append(event)
        for fn in list(self._listeners):
            try:
                fn(event)
            except Exception:  # a broken listener must never break a run
                pass
        return event

    def save(self, path: Path, extra: dict | None = None) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"run_id": self.run_id, "mode": self.mode, "saved_at": time.time(), "events": self.events}
        if extra:
            payload.update(extra)
        path.write_text(json.dumps(payload, indent=1, default=str), encoding="utf-8")
        return path
