"""Database package for GOVNEXIS 3.0."""

from app.database.db import (
    get_connection, init_db, save_scan, get_scan, get_all_scans,
    get_scans_count, delete_scan, delete_all_scans, get_scan_trends,
    get_remediation_tasks, update_remediation_status, get_distinct_hosts,
    search_findings, seed_demo_history
)

__all__ = [
    "get_connection", "init_db", "save_scan", "get_scan", "get_all_scans",
    "get_scans_count", "delete_scan", "delete_all_scans", "get_scan_trends",
    "get_remediation_tasks", "update_remediation_status", "get_distinct_hosts",
    "search_findings", "seed_demo_history"
]
