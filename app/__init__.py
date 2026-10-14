"""GOVNEXIS 3.0 — Flask Application Factory.

Intelligent Government Web Security Auditing Platform.
Tagline: "See the Risk. Fix the Gap. Build Trust."
Version: 3.0.0
"""

import os
from flask import Flask, render_template, request, jsonify
from flask_wtf.csrf import CSRFError

from config import config_by_name, APP_NAME, APP_VERSION, APP_TAGLINE, APP_DESCRIPTION
from app.extensions import csrf
from app.database.db import init_db, seed_demo_history
from core.mock_site import start_mock_server


def create_app(config_name: str = None) -> Flask:
    """Create and configure the Flask application using the factory pattern."""
    if not config_name:
        config_name = os.environ.get("FLASK_ENV", "development").lower()

    app = Flask(__name__, template_folder="templates", static_folder="static")
    config_obj = config_by_name.get(config_name, config_by_name["default"])
    app.config.from_object(config_obj)

    # Initialize extensions
    csrf.init_app(app)

    # Initialize database tables and start demo sandbox
    with app.app_context():
        try:
            init_db(app.config.get("DATABASE_PATH"))
            seed_demo_history(app.config.get("DATABASE_PATH"))
        except Exception as e:
            app.logger.warning(f"Database initialization notice: {e}")

        # Start isolated local demo sandbox on 127.0.0.1:8765
        try:
            start_mock_server()
        except Exception as e:
            app.logger.warning(f"Demo sandbox startup notice: {e}")

    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.scanner import scanner_bp
    from app.routes.findings import findings_bp
    from app.routes.remediation import remediation_bp
    from app.routes.verification import verification_bp
    from app.routes.history import history_bp
    from app.routes.reports import reports_bp
    from app.routes.demo_lab import demo_lab_bp
    from app.routes.settings import settings_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(findings_bp)
    app.register_blueprint(remediation_bp)
    app.register_blueprint(verification_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(demo_lab_bp)
    app.register_blueprint(settings_bp)

    # Register security response headers for the GOVNEXIS platform itself
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Permissive enough for local scripts & Chart.js from CDN
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "frame-ancestors 'none';"
        )
        return response

    # Global context processor
    @app.context_processor
    def inject_global_metadata():
        return {
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "app_tagline": APP_TAGLINE,
            "app_description": APP_DESCRIPTION,
        }

    # Custom Jinja template filters
    @app.template_filter("score_color")
    def score_color_filter(score):
        try:
            s = float(score)
            if s >= 80:
                return "#10b981"  # Emerald
            elif s >= 60:
                return "#f59e0b"  # Amber
            return "#ef4444"      # Red
        except Exception:
            return "#64748b"

    @app.template_filter("cvss_color")
    def cvss_color_filter(cvss):
        try:
            c = float(cvss or 0.0)
            if c >= 9.0:
                return "#ef4444"  # Critical
            elif c >= 7.0:
                return "#f97316"  # High
            elif c >= 4.0:
                return "#eab308"  # Medium
            elif c > 0.0:
                return "#3b82f6"  # Low
            return "#10b981"      # None / Safe
        except Exception:
            return "#64748b"

    # Centralized Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Resource not found"}), 404
        return render_template("404.html"), 404

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "CSRF validation failed", "details": e.description}), 400
        return render_template("404.html", error_title="CSRF Token Mismatch", error_message="Session validation token expired or missing. Please refresh and try again."), 400

    @app.errorhandler(500)
    def internal_server_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        return render_template("500.html"), 500

    return app
