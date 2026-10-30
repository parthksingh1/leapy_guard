import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.config import Config  # noqa: E402


@pytest.fixture
def cfg():
    return Config(secret_key="test-secret")


@pytest.fixture
def client(cfg):
    app = create_app(cfg)
    app.config["TESTING"] = True
    return app.test_client()
