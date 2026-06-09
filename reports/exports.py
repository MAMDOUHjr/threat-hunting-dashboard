"""
reports/exports.py
------------------
Functions to format and export HuntReport objects as:
  - Human-readable text (.txt)
  - Machine-readable JSON (.json)

All exported files are written to the 'reports/' directory (created if missing).
"""

import json
import logging
from datetime import datetime
from pathlib import Path

from hunting.models import HuntReport, Severity

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).parent.parent / "reports"

# Severity display order: most critical first
SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


# ────────────────────────────────────────────────────────────────────────────
# Text formatter
# ────────────────────────────────────────────────────────────────────────────

def format_report_text(report: HuntReport) -> str:
    """
    Render a HuntReport as a formatted text string.

    Args:
        report: The completed HuntReport to format.

    Returns:
        Multi-line string suitable for display or file export.
    """
    lines: list[str] = []
    sep = "=" * 60
    dash = "-" * 40

    ts = report.completed or report.started
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

    lines.append(sep)
    lines.append(f"VM:        {report.vm.name}")
    lines.append(f"Host:      {report.vm.host}:{report.vm.port}")
    lines.append(f"Generated: {ts_str}")

    if report.error:
        lines.append("")
        lines.append(f"  !! HUNT FAILED: {report.error}")
        lines.append(sep)
        return "\n".join(lines)

    lines.append(sep)

    # ── Findings ──────────────────────────────────────────────────────────
    if report.findings:
        for finding in report.sorted_findings():
            lines.append("")
            lines.append(f"  [{finding.severity.value}]")
            lines.append(f"  {finding.title}")
            lines.append(dash)
            lines.append(f"  Description:")
            for part in finding.description.splitlines():
                lines.append(f"    {part}")
            lines.append("")
            lines.append(f"  Evidence:")
            for ev_line in finding.evidence.splitlines():
                lines.append(f"    {ev_line}")
            lines.append(f"  Source: {finding.source_log}")
            lines.append(f"  Detected: {finding.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(dash)
    else:
        lines.append("")
        lines.append("  No findings detected.")

    # ── Warnings ──────────────────────────────────────────────────────────
    if report.warnings:
        lines.append("")
        lines.append("  Warnings (non-fatal):")
        for w in report.warnings:
            lines.append(f"    - {w}")

    # ── Summary ───────────────────────────────────────────────────────────
    lines.append("")
    lines.append(sep)
    lines.append("  SUMMARY")
    lines.append(sep)
    lines.append(f"  Total Findings : {len(report.findings)}")
    for sev in SEVERITY_ORDER:
        count = report.count_by_severity(sev)
        lines.append(f"  {sev.value:<10}: {count}")

    duration = ""
    if report.completed:
        delta = report.completed - report.started
        duration = f"{delta.total_seconds():.1f}s"
    lines.append(f"  Duration       : {duration or 'N/A'}")
    lines.append(sep)

    return "\n".join(lines)


# ────────────────────────────────────────────────────────────────────────────
# Export functions
# ────────────────────────────────────────────────────────────────────────────

def _ensure_reports_dir() -> Path:
    """Create the reports output directory if it does not exist."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return REPORTS_DIR


def _build_filename(vm_name: str, extension: str) -> Path:
    """Return a timestamped output file path."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = vm_name.replace(" ", "_").replace("/", "_")
    return _ensure_reports_dir() / f"report_{safe_name}_{ts}.{extension}"


def export_txt(report: HuntReport) -> Path:
    """
    Write the report to a .txt file.

    Args:
        report: The HuntReport to export.

    Returns:
        Path to the written file.
    """
    path = _build_filename(report.vm.name, "txt")
    text = format_report_text(report)
    path.write_text(text, encoding="utf-8")
    logger.info("TXT report exported to %s", path)
    return path


def export_json(report: HuntReport) -> Path:
    """
    Write the report to a .json file containing all Finding fields.

    Args:
        report: The HuntReport to export.

    Returns:
        Path to the written file.
    """
    path = _build_filename(report.vm.name, "json")

    payload = {
        "vm": {
            "name": report.vm.name,
            "host": report.vm.host,
            "port": report.vm.port,
            "username": report.vm.username,
        },
        "started": report.started.isoformat(),
        "completed": report.completed.isoformat() if report.completed else None,
        "error": report.error,
        "findings": [f.to_dict() for f in report.sorted_findings()],
        "warnings": report.warnings,
        "summary": report.summary,
    }

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("JSON report exported to %s", path)
    return path
