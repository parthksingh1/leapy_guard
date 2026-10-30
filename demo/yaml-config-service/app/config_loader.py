"""Parse job definitions submitted as YAML."""
import yaml


class ConfigError(ValueError):
    pass


REQUIRED = ("name", "image", "steps")


def load_config(text: str) -> dict:
    try:
        data = yaml.load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("a job definition must be a mapping")
    missing = [k for k in REQUIRED if k not in data]
    if missing:
        raise ConfigError(f"missing keys: {', '.join(missing)}")
    if not isinstance(data["steps"], list) or not data["steps"]:
        raise ConfigError("steps must be a non-empty list")
    data.setdefault("timeout", 600)
    data.setdefault("env", {})
    return data


def load_many(text: str) -> list[dict]:
    """A file may hold several jobs separated by '---'."""
    try:
        docs = [d for d in yaml.load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc
    return [load_config(yaml.dump(d)) for d in docs]
