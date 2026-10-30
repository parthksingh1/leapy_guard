"""Runtime configuration. Everything is overridable through environment variables (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

_SRC = Path(__file__).resolve().parent.parent
# source checkout: the repo root; installed package (Docker, GitHub Actions): the working directory
ROOT = Path(os.environ.get("LEAPLY_HOME") or (_SRC if (_SRC / "pyproject.toml").exists() else Path.cwd()))
load_dotenv(ROOT / ".env")


def _f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _key(name: str) -> str:
    """Return a key only if it looks real (placeholders like 'xxxxxxxx' are ignored)."""
    value = os.environ.get(name, "").strip()
    if len(value) < 16 or value.lower().startswith(("your", "xxx", "changeme", "<")):
        return ""
    return value


@dataclass
class ModelSpec:
    role: str           # ultra | super | nano
    model_id: str       # Token Factory model id (case-sensitive)
    price_in: float     # USD per 1M input tokens
    price_out: float    # USD per 1M output tokens
    hints: tuple[str, ...] = ()  # substrings used to auto-resolve the id from /models

    def cost(self, tokens_in: int, tokens_out: int) -> float:
        return tokens_in / 1e6 * self.price_in + tokens_out / 1e6 * self.price_out


@dataclass
class Settings:
    nebius_api_key: str = field(default_factory=lambda: _key("NEBIUS_API_KEY"))
    nebius_base_url: str = field(
        default_factory=lambda: os.environ.get(
            "NEBIUS_BASE_URL", "https://api.tokenfactory.us-central1.nebius.com/v1/"
        )
    )
    tavily_api_key: str = field(default_factory=lambda: _key("TAVILY_API_KEY"))
    github_token: str = field(default_factory=lambda: _key("GITHUB_TOKEN"))

    llm_timeout: float = field(default_factory=lambda: _f("LLM_TIMEOUT_SECONDS", 180))
    llm_retries: int = field(default_factory=lambda: _i("LLM_MAX_RETRIES", 4))
    max_iterations: int = field(default_factory=lambda: _i("MAX_FIX_ITERATIONS", 6))
    same_error_limit: int = field(default_factory=lambda: _i("SAME_ERROR_LIMIT", 3))
    max_diff_lines: int = field(default_factory=lambda: _i("MAX_DIFF_LINES", 400))
    test_timeout: int = field(default_factory=lambda: _i("TEST_TIMEOUT_SECONDS", 300))
    max_repo_chars: int = field(default_factory=lambda: _i("MAX_REPO_CHARS", 1_500_000))

    # Hosted demo protections
    hosted: bool = field(default_factory=lambda: os.environ.get("LEAPLY_HOSTED", "0") == "1")
    live_runs_per_hour: int = field(default_factory=lambda: _i("LIVE_RUNS_PER_HOUR", 3))
    live_runs_per_day_global: int = field(default_factory=lambda: _i("LIVE_RUNS_PER_DAY", 40))

    models: dict[str, ModelSpec] = field(default_factory=lambda: {
        "ultra": ModelSpec(
            "ultra",
            os.environ.get("MODEL_ULTRA", "nvidia/Nemotron-3-Ultra-550b-a55b"),
            _f("PRICE_ULTRA_IN", 1.00), _f("PRICE_ULTRA_OUT", 3.00),
            ("ultra",),
        ),
        "super": ModelSpec(
            "super",
            os.environ.get("MODEL_SUPER", "nvidia/nemotron-3-super-120b-a12b"),
            _f("PRICE_SUPER_IN", 0.30), _f("PRICE_SUPER_OUT", 0.90),
            ("super-120b", "super"),
        ),
        "nano": ModelSpec(
            "nano",
            os.environ.get("MODEL_NANO", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"),
            _f("PRICE_NANO_IN", 0.06), _f("PRICE_NANO_OUT", 0.24),
            ("nano-30b", "nano"),
        ),
    })

    runs_dir: Path = ROOT / "runs"
    replays_dir: Path = ROOT / "replays"
    demo_repo: Path = ROOT / "demo" / "vulnerable-app"

    @property
    def llm_enabled(self) -> bool:
        return bool(self.nebius_api_key)


settings = Settings()
