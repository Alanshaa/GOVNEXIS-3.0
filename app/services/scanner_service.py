"""Website Security Configuration Scanner Service for GOVNEXIS 3.0."""

import time
from urllib.parse import urlparse
from typing import Dict, Any, Tuple, Optional

from config import LOCAL_DEMO_PORT, LOCAL_DEMO_HOST, LOCAL_DEMO_URL
from core.scanner import execute_scan, ScanResult, ScanError
from core.url_validator import (
    validate_and_resolve_url,
    ValidationError,
    SSRFSecurityError,
)
from app.database.db import save_scan, get_scan


class ScannerService:
    """Service layer coordinating website audits and safety validations."""

    @staticmethod
    def validate_target(raw_url: str, allow_local_demo: bool = False) -> Tuple[str, list]:
        """Validate target URL syntax and enforce SSRF protections."""
        return validate_and_resolve_url(raw_url, allow_local_demo=allow_local_demo)

    @staticmethod
    def run_scan(
        target_url: str,
        user_confirmed_authorization: bool,
        allow_local_demo: Optional[bool] = None,
        save_to_db: bool = True
    ) -> Tuple[ScanResult, Optional[int]]:
        """Execute a full defensive configuration scan and optionally persist it.

        Returns:
            Tuple of (ScanResult, scan_id)
        """
        if not user_confirmed_authorization:
            raise ValidationError("Explicit authorization confirmation is required before scanning.")

        # Auto-detect if this is the authorized local demo sandbox
        if allow_local_demo is None:
            clean = target_url if "://" in target_url else f"https://{target_url}"
            try:
                parsed = urlparse(clean)
                allow_local_demo = (
                    parsed.hostname in ("127.0.0.1", "localhost", LOCAL_DEMO_HOST)
                    and (parsed.port == LOCAL_DEMO_PORT)
                )
            except Exception:
                allow_local_demo = False

        scan_result = execute_scan(
            target_url=target_url,
            user_confirmed_authorization=user_confirmed_authorization,
            allow_local_demo=allow_local_demo
        )

        scan_id = None
        if save_to_db:
            scan_id = save_scan(scan_result)

        return scan_result, scan_id

    @staticmethod
    def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve scan record by ID."""
        return get_scan(scan_id)
