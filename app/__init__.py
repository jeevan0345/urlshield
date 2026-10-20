import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.config import BaseConfig, get_config
from app.core.database import ScanDatabase
from app.core.predictor import URLPredictor
from app.routes.api import api_bp
from app.routes.web import web_bp


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["120 per minute"],
    storage_uri="memory://",
)


def create_app(config_class: type[BaseConfig] | None = None) -> Flask:
    """Application factory for URLShield | Phishing Intelligence."""
    if config_class is None:
        config_class = get_config()

    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configure structured logging
    logging.basicConfig(
        level=logging.INFO if not app.debug else logging.DEBUG,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    )
    logger = logging.getLogger("urlshield")

    # Initialize CORS
    CORS(app, origins=app.config.get("CORS_ALLOWED_ORIGINS", ["*"]))

    # Initialize Rate Limiter
    limiter.init_app(app)

    # Initialize Extensions
    app.extensions["db"] = ScanDatabase(app.config.get("SQLALCHEMY_DATABASE_URI"))
    app.extensions["predictor"] = URLPredictor(
        model_path=app.config.get("MODEL_PATH"),
        metadata_path=app.config.get("METADATA_PATH"),
        schema_path=app.config.get("SCHEMA_PATH"),
    )

    # Apply route rate limit specifically to API scan endpoint
    limiter.limit(app.config.get("RATELIMIT_SCAN", "30 per minute"))(api_bp)

    # Register Blueprints
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    # Standardized Error Handlers
    @app.errorhandler(400)
    def handle_bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Bad Request",
                "message": getattr(e, "description", "Malformed request body or parameters.")
            }), 400
        return e

    @app.errorhandler(404)
    def handle_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Not Found",
                "message": "The requested API endpoint was not found."
            }), 404
        return e

    @app.errorhandler(405)
    def handle_method_not_allowed(e):
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Method Not Allowed",
                "message": f"HTTP method {request.method} is not supported for this endpoint."
            }), 405
        return e

    @app.errorhandler(413)
    def handle_payload_too_large(e):
        return jsonify({
            "success": False,
            "error": "Payload Too Large",
            "message": "Input payload exceeds maximum allowed size (16 KB)."
        }), 413

    @app.errorhandler(429)
    def handle_rate_limit_exceeded(e):
        return jsonify({
            "success": False,
            "error": "Too Many Requests",
            "message": "Rate limit threshold reached. Please wait before submitting additional scans."
        }), 429

    @app.errorhandler(500)
    def handle_internal_server_error(e):
        logger.error("Unhandled internal server error: %s", e)
        if request.path.startswith("/api/"):
            return jsonify({
                "success": False,
                "error": "Internal Server Error",
                "message": "An unexpected server error occurred."
            }), 500
        return e

    return app
