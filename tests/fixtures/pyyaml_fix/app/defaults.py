"""Organisation-wide defaults, shipped with the service."""
from pathlib import Path

import yaml

DEFAULTS_FILE = Path(__file__).with_name("defaults.yml")


def load_defaults(path: Path = DEFAULTS_FILE) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def apply_defaults(job: dict, defaults: dict | None = None) -> dict:
    defaults = load_defaults() if defaults is None else defaults
    merged = {**defaults.get("job", {}), **job}
    merged["env"] = {**defaults.get("env", {}), **job.get("env", {})}
    return merged
