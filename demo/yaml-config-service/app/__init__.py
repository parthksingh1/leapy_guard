"""Job service: accepts CI job definitions as YAML and queues them."""
from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)

    from .api import bp

    app.register_blueprint(bp)
    return app
