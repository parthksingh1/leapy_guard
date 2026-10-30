"""Security regression test for CVE-2020-14343 (PyYAML FullLoader arbitrary code execution).

A job definition that uses python/object/new + python/name:eval runs code when parsed by
yaml.load() with the default FullLoader (PyYAML < 5.4). The payload here is harmless: it only sets
an environment variable, which the test checks. The fixed code must refuse the document.
"""
import os

import pytest

from app.config_loader import ConfigError, load_config

PAYLOAD = """
name: !!python/object/new:tuple [!!python/object/new:map [!!python/name:eval , [ "__import__('os').environ.__setitem__('LEAPLY_POC_EXECUTED', '1')" ]]]
image: python:3.11
steps: [echo hi]
"""


def test_cve_2020_14343_job_definition_cannot_execute_code():
    os.environ.pop("LEAPLY_POC_EXECUTED", None)
    try:
        with pytest.raises(ConfigError):
            load_config(PAYLOAD)
    finally:
        executed = os.environ.pop("LEAPLY_POC_EXECUTED", None)
    assert executed is None, "the YAML payload executed Python code"
