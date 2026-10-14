"""Professional Report Generation Service for GOVNEXIS 3.0."""

from typing import Dict, Any, Optional, Tuple
from core.reports import (
    generate_json_report,
    generate_html_report,
    generate_csv_report,
    generate_pdf_report,
)
from app.database.db import get_scan


class ReportService:
    """Service layer producing multi-format executive cybersecurity audit exports."""

    @staticmethod
    def get_scan_report_data(scan_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve and format scan record for reporting."""
        scan_data = get_scan(scan_id)
        if not scan_data:
            return None
        scan_dict = scan_data.get("details", {})
        if "findings" not in scan_dict:
            scan_dict["findings"] = scan_data.get("findings", [])
        return scan_dict

    @staticmethod
    def build_json(scan_dict: Dict[str, Any]) -> str:
        """Produce JSON export string."""
        return generate_json_report(scan_dict)

    @staticmethod
    def build_csv(scan_dict: Dict[str, Any]) -> str:
        """Produce CSV export string."""
        return generate_csv_report(scan_dict)

    @staticmethod
    def build_html(scan_dict: Dict[str, Any]) -> str:
        """Produce standalone HTML report string."""
        return generate_html_report(scan_dict)

    @staticmethod
    def build_pdf(scan_dict: Dict[str, Any]) -> bytes:
        """Produce executive ReportLab PDF binary bytes."""
        return generate_pdf_report(scan_dict)
