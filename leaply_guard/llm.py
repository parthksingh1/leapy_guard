"""Nebius Token Factory client: Nemotron 3 Ultra / Super / Nano behind one interface.

Every call is retried with exponential backoff, has a timeout, and is recorded
(model, purpose, tokens, latency, cost) in the run's audit log.
"""
from __future__ import annotations

import json
import random
import re
import time
from dataclasses import dataclass, field

from .config import ModelSpec, Settings, settings as default_settings
from .events import EventBus


class LLMError(RuntimeError):
    pass


@dataclass
class Usage:
    calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost: float = 0.0
    latency: float = 0.0


@dataclass
class Ledger:
    """Token and cost accounting, per model role, plus the per-call audit trail."""
    per_role: dict[str, Usage] = field(default_factory=dict)
    calls: list[dict] = field(default_factory=list)

    def add(self, spec: ModelSpec, purpose: str, tokens_in: int, tokens_out: int, latency: float, step: str) -> dict:
        u = self.per_role.setdefault(spec.role, Usage())
        cost = spec.cost(tokens_in, tokens_out)
        u.calls += 1
        u.tokens_in += tokens_in
        u.tokens_out += tokens_out
        u.cost += cost
        u.latency += latency
        rec = {
            "role": spec.role, "model": spec.model_id, "purpose": purpose, "step": step,
            "tokens_in": tokens_in, "tokens_out": tokens_out,
            "cost_usd": round(cost, 6), "latency_s": round(latency, 2), "ts": time.time(),
        }
        self.calls.append(rec)
        return rec

    @property
    def total_cost(self) -> float:
        return sum(u.cost for u in self.per_role.values())

    def summary(self, models: dict[str, ModelSpec]) -> dict:
        ultra = models["ultra"]
        rows = []
        all_ultra = 0.0
        for role in ("ultra", "super", "nano"):
            u = self.per_role.get(role, Usage())
            rows.append({
                "role": role, "model": models[role].model_id, "calls": u.calls,
                "tokens_in": u.tokens_in, "tokens_out": u.tokens_out,
                "cost_usd": round(u.cost, 6), "latency_s": round(u.latency, 1),
            })
            all_ultra += ultra.cost(u.tokens_in, u.tokens_out)
        total = self.total_cost
        saved = (1 - total / all_ultra) * 100 if all_ultra > 0 else 0.0
        return {
            "rows": rows,
            "total_cost_usd": round(total, 6),
            "all_ultra_cost_usd": round(all_ultra, 6),
            "routing_savings_pct": round(saved, 1),
            "total_tokens": sum(r["tokens_in"] + r["tokens_out"] for r in rows),
        }


_THINK = re.compile(r"<think>.*?</think>", re.S)


def strip_reasoning(text: str) -> str:
    text = _THINK.sub("", text or "")
    if "</think>" in text:  # opening tag was in the prompt template
        text = text.split("</think>", 1)[1]
    return text.strip()


def extract_json(text: str):
    """Parse the first JSON object/array in a model answer (fenced or bare)."""
    text = strip_reasoning(text)
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    candidates = [fence.group(1)] if fence else []
    candidates.append(text)
    for c in candidates:
        c = c.strip()
        try:
            return json.loads(c)
        except json.JSONDecodeError:
            pass
        for open_c, close_c in (("{", "}"), ("[", "]")):
            start, end = c.find(open_c), c.rfind(close_c)
            if start != -1 and end > start:
                try:
                    return json.loads(c[start:end + 1])
                except json.JSONDecodeError:
                    continue
    raise LLMError("model did not return valid JSON")


def extract_code(text: str, lang: str = "") -> str:
    text = strip_reasoning(text)
    blocks = re.findall(r"```[\w+-]*\n(.*?)```", text, re.S)
    if blocks:
        return max(blocks, key=len)
    return text


class LLM:
    """Routes a request to Ultra, Super or Nano and records what it cost."""

    def __init__(self, bus: EventBus | None = None, cfg: Settings | None = None):
        self.cfg = cfg or default_settings
        self.bus = bus
        self.ledger = Ledger()
        self._client = None
        self._resolved = False
        self.simulated = False

    # -- model id resolution -------------------------------------------------
    def client(self):
        if self._client is None:
            if not self.cfg.nebius_api_key:
                raise LLMError("NEBIUS_API_KEY is not set. Add it to .env (see .env.example).")
            from openai import OpenAI

            self._client = OpenAI(
                base_url=self.cfg.nebius_base_url,
                api_key=self.cfg.nebius_api_key,
                timeout=self.cfg.llm_timeout,
                max_retries=0,  # we retry ourselves, with logging
            )
        return self._client

    def list_models(self) -> list[str]:
        return sorted(m.id for m in self.client().models.list().data)

    def resolve_models(self) -> dict[str, str]:
        """Confirm configured ids against /models; fix case or pick the closest Nemotron 3 match."""
        if self._resolved:
            return {r: s.model_id for r, s in self.cfg.models.items()}
        try:
            available = self.list_models()
        except Exception:
            self._resolved = True
            return {r: s.model_id for r, s in self.cfg.models.items()}
        lower = {m.lower(): m for m in available}
        for spec in self.cfg.models.values():
            if spec.model_id in available:
                continue
            if spec.model_id.lower() in lower:
                spec.model_id = lower[spec.model_id.lower()]
                continue
            nemo = [m for m in available if "nemotron" in m.lower() and "3" in m]
            for hint in spec.hints:
                match = [m for m in nemo if hint in m.lower()]
                if match:
                    spec.model_id = sorted(match, key=len)[0]
                    break
        self._resolved = True
        return {r: s.model_id for r, s in self.cfg.models.items()}

    # -- calls ---------------------------------------------------------------
    def chat(
        self,
        role: str,
        purpose: str,
        messages: list[dict],
        *,
        step: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> str:
        spec = self.cfg.models[role]
        client = self.client()
        self.resolve_models()
        last_exc: Exception | None = None
        for attempt in range(self.cfg.llm_retries):
            started = time.time()
            try:
                resp = client.chat.completions.create(
                    model=spec.model_id,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                latency = time.time() - started
                usage = resp.usage
                t_in = getattr(usage, "prompt_tokens", 0) or 0
                t_out = getattr(usage, "completion_tokens", 0) or 0
                msg = resp.choices[0].message
                text = msg.content or ""
                if not strip_reasoning(text) and resp.choices[0].finish_reason == "length":
                    max_tokens = min(max_tokens * 2, 32768)
                    raise LLMError("answer truncated during reasoning; retrying with a larger budget")
                rec = self.ledger.add(spec, purpose, t_in, t_out, latency, step)
                if self.bus:
                    self.bus.cost_usd = self.ledger.total_cost
                    self.bus.emit("model_call", actor=role, **rec)
                return text
            except Exception as exc:  # noqa: BLE001 - openai raises many types
                last_exc = exc
                status = getattr(exc, "status_code", None)
                if status in (400, 401, 403, 404, 422):
                    break  # not retryable
                wait = min(2 ** attempt + random.random(), 20)
                if self.bus:
                    self.bus.emit("log", step=step, actor=role, level="warn",
                                  message=f"{role} call failed ({type(exc).__name__}); retry {attempt + 1} in {wait:.0f}s")
                time.sleep(wait)
        raise LLMError(f"{role} ({spec.model_id}) failed for '{purpose}': {last_exc}")

    def chat_json(self, role: str, purpose: str, messages: list[dict], **kw):
        text = self.chat(role, purpose, messages, **kw)
        try:
            return extract_json(text)
        except LLMError:
            repair = messages + [
                {"role": "assistant", "content": text[-6000:]},
                {"role": "user", "content": "That was not valid JSON. Reply with only the JSON object, no prose."},
            ]
            return extract_json(self.chat(role, purpose + " (json repair)", repair, **kw))
