import pytest

from app.config_loader import ConfigError, load_config, load_many
from app.defaults import apply_defaults, load_defaults

JOB = """
name: build
image: python:3.11
steps:
  - pip install -r requirements.txt
  - pytest -q
env:
  DEBUG: "1"
"""


def test_load_valid_job():
    job = load_config(JOB)
    assert job["name"] == "build"
    assert job["steps"][1] == "pytest -q"
    assert job["timeout"] == 600


def test_missing_keys_rejected():
    with pytest.raises(ConfigError, match="missing keys: image"):
        load_config("name: x\nsteps: [a]\n")


def test_empty_steps_rejected():
    with pytest.raises(ConfigError, match="non-empty"):
        load_config("name: x\nimage: y\nsteps: []\n")


def test_not_a_mapping_rejected():
    with pytest.raises(ConfigError):
        load_config("- just\n- a list\n")


def test_invalid_yaml_rejected():
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config("name: [unclosed\n")


def test_load_many_documents():
    jobs = load_many(JOB + "---\nname: lint\nimage: node:20\nsteps: [npm run lint]\n")
    assert [j["name"] for j in jobs] == ["build", "lint"]


def test_defaults_file_loads():
    d = load_defaults()
    assert d["env"]["CI"] == "true"


def test_apply_defaults_merges_env():
    job = apply_defaults(load_config(JOB))
    assert job["env"] == {"CI": "true", "REGION": "eu-west-1", "DEBUG": "1"}
    assert job["retries"] == 1
