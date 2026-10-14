"""Routes package for GOVNEXIS 3.0."""

from app.routes.main import main_bp
from app.routes.scanner import scanner_bp
from app.routes.findings import findings_bp
from app.routes.remediation import remediation_bp
from app.routes.verification import verification_bp
from app.routes.history import history_bp
from app.routes.reports import reports_bp
from app.routes.demo_lab import demo_lab_bp
from app.routes.settings import settings_bp

__all__ = [
    "main_bp",
    "scanner_bp",
    "findings_bp",
    "remediation_bp",
    "verification_bp",
    "history_bp",
    "reports_bp",
    "demo_lab_bp",
    "settings_bp",
]
