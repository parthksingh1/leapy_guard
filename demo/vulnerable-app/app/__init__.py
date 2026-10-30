"""Acme auth service: issues user sessions and verifies service-to-service tokens."""
from flask import Flask

from .config import Config


def create_app(config: Config | None = None) -> Flask:
    app = Flask(__name__)
    app.config["AUTH"] = config or Config()

    from .routes import bp

    app.register_blueprint(bp)
    return app
