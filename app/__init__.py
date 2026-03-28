"""
app/__init__.py  —  Division 3
Added: Flask-Limiter, health blueprint, ML module init.
"""
import eventlet
eventlet.monkey_patch()

from flask import Flask
from .extensions import db, migrate, login_manager, bcrypt, socketio
from .security import limiter
from .config import config_map
import os


def create_app(env=None):
    app = Flask(__name__, template_folder="templates")
    if env is None:
        env = os.environ.get("FLASK_ENV", "development")
    app.config.from_object(config_map.get(env, config_map["development"]))

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    socketio.init_app(app)
    limiter.init_app(app)

    # Import models
    from .models import User, Attack, BlockedIP, ResponseLog, SimulatorConfig  # noqa

    # Register blueprints
    from .blueprints.auth import auth_bp
    from .blueprints.dashboard import dashboard_bp
    from .blueprints.api import api_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(dashboard_bp, url_prefix="/")
    app.register_blueprint(api_bp, url_prefix="/api")

    # Register health + metrics routes (imported inside api_bp)
    from .blueprints.api import health  # noqa

    # Register audit routes (imported inside dashboard_bp)
    from .blueprints.dashboard import audit  # noqa

    # Register SocketIO events
    from .blueprints import socket_events  # noqa

    return app
