"""Aplicação Flask de exemplo para demonstrar a esteira CI/CD."""

import os
import secrets

from flask import Flask

from app.models import TaskStore
from app.routes import bp


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    app.config["JSON_SORT_KEYS"] = False
    if config:
        app.config.update(config)

    app.extensions["task_store"] = TaskStore()
    app.register_blueprint(bp)
    return app
