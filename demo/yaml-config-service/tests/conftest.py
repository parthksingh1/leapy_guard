import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app  # noqa: E402
from app.api import QUEUE  # noqa: E402


@pytest.fixture
def client():
    QUEUE.clear()
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()
