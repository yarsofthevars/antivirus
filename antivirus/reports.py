"""Report generation for scan results in JSON and HTML formats."""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional

from .config import get_reports_dir
from .scanner import ScanResult


@dataclass
class ScanStatistics:
    """Statistics for a scan session."""
    files_scanned: int = 0
    threats_found: int = 0
    heuristic_alerts: int = 0
    files_skipped: int = 0
    files_quarantined: int = 0
    total_size_scanned: int = 0  # bytes
    scan_duration: float = 0.0  # seconds
    start_time: str = ""  # ISO timestamp
    end_time: str = ""  # ISO timestamp

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "files_scanned": self.files_scanned,
            "threats_found": self.threats_found,
            "heuristic_alerts": self.heuristic_alerts,
            "files_skipped": self.files_skipped,
            "files_quarantined": self.files_quarantined,
            "total_size_scanned": self.total_size_scanned,
            "scan_duration": self.scan_duration,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


@dataclass
class ScanReport:
    """Complete scan report."""
    id: str
    scan_type: str  # manual, scheduled, monitor
    paths_scanned: List[str]
    statistics: ScanStatistics
    threats: List[Dict]  # Serialized ScanResults for threats
    heuristic_alerts: List[Dict]  # Files with heuristic matches
    errors: List[Dict]  # Files with scan errors
    exclusions_applied: List[str]
    report_generated: str  # ISO timestamp

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "paths_scanned": self.paths_scanned,
            "statistics": self.statistics.to_dict(),
            "threats": self.threats,
            "heuristic_alerts": self.heuristic_alerts,
            "errors": self.errors,
            "exclusions_applied": self.exclusions_applied,
            "report_generated": self.report_generated,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanReport":
        """Create from dictionary."""
        stats_data = data.get("statistics", {})
        statistics = ScanStatistics(
            files_scanned=stats_data.get("files_scanned", 0),
            threats_found=stats_data.get("threats_found", 0),
            heuristic_alerts=stats_data.get("heuristic_alerts", 0),
            files_skipped=stats_data.get("files_skipped", 0),
            files_quarantined=stats_data.get("files_quarantined", 0),
            total_size_scanned=stats_data.get("total_size_scanned", 0),
            scan_duration=stats_data.get("scan_duration", 0.0),
            start_time=stats_data.get("start_time", ""),
            end_time=stats_data.get("end_time", ""),
        )
        return cls(
            id=data["id"],
            scan_type=data.get("scan_type", "manual"),
            paths_scanned=data.get("paths_scanned", []),
            statistics=statistics,
            threats=data.get("threats", []),
            heuristic_alerts=data.get("heuristic_alerts", []),
            errors=data.get("errors", []),
            exclusions_applied=data.get("exclusions_applied", []),
            report_generated=data.get("report_generated", ""),
        )


# HTML report template using string.Template
HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antivirus Scan Report - ${report_id}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header .meta { opacity: 0.8; font-size: 14px; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card h3 { font-size: 32px; margin-bottom: 5px; }
        .stat-card p { color: #666; font-size: 14px; }
        .stat-card.danger { border-left: 4px solid #e74c3c; }
        .stat-card.warning { border-left: 4px solid #f39c12; }
        .stat-card.success { border-left: 4px solid #27ae60; }
        .stat-card.info { border-left: 4px solid #3498db; }
        .section {
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }
        .section-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #eee;
            font-weight: 600;
        }
        .section-content { padding: 20px; }
        .threat-item {
            background: #fee;
            border-left: 4px solid #e74c3c;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 0 5px 5px 0;
        }
        .threat-item:last-child { margin-bottom: 0; }
        .threat-item .path { font-family: monospace; font-size: 13px; word-break: break-all; }
        .threat-item .threat-name { color: #c0392b; font-weight: 600; margin-top: 5px; }
        .heuristic-item {
            background: #fff8e1;
            border-left: 4px solid #f39c12;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 0 5px 5px 0;
        }
        .heuristic-item:last-child { margin-bottom: 0; }
        .heuristic-item .path { font-family: monospace; font-size: 13px; word-break: break-all; }
        .heuristic-item .matches { margin-top: 10px; }
        .heuristic-match {
            background: rgba(0,0,0,0.05);
            padding: 8px 12px;
            margin-top: 5px;
            border-radius: 4px;
            font-size: 13px;
        }
        .severity-critical { color: #c0392b; font-weight: 600; }
        .severity-high { color: #e67e22; font-weight: 600; }
        .severity-medium { color: #f39c12; }
        .severity-low { color: #7f8c8d; }
        .error-item {
            background: #f5f5f5;
            padding: 10px 15px;
            margin-bottom: 5px;
            border-radius: 5px;
            font-size: 13px;
        }
        .error-item .path { font-family: monospace; }
        .error-item .error { color: #e74c3c; }
        .empty-message {
            text-align: center;
            color: #999;
            padding: 30px;
        }
        .footer {
            text-align: center;
            color: #999;
            font-size: 12px;
            margin-top: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 10px 15px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th { background: #f8f9fa; font-weight: 600; }
        .risk-score {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .risk-high { background: #fee; color: #c0392b; }
        .risk-medium { background: #fff8e1; color: #e67e22; }
        .risk-low { background: #e8f5e9; color: #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Antivirus Scan Report</h1>
            <div class="meta">
                Report ID: ${report_id}<br>
                Generated: ${generated_time}<br>
                Scan Type: ${scan_type}<br>
                Duration: ${duration}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card info">
                <h3>${files_scanned}</h3>
                <p>Files Scanned</p>
            </div>
            <div class="stat-card danger">
                <h3>${threats_found}</h3>
                <p>Threats Found</p>
            </div>
            <div class="stat-card warning">
                <h3>${heuristic_alerts}</h3>
                <p>Heuristic Alerts</p>
            </div>
            <div class="stat-card success">
                <h3>${files_clean}</h3>
                <p>Clean Files</p>
            </div>
        </div>

        <div class="section">
            <div class="section-header">Paths Scanned</div>
            <div class="section-content">
                ${paths_section}
            </div>
        </div>

        <div class="section">
            <div class="section-header">Threats Detected (${threats_found})</div>
            <div class="section-content">
                ${threats_section}
            </div>
        </div>

        <div class="section">
            <div class="section-header">Heuristic Alerts (${heuristic_alerts})</div>
            <div class="section-content">
                ${heuristics_section}
            </div>
        </div>

        <div class="section">
            <div class="section-header">Errors (${errors_count})</div>
            <div class="section-content">
                ${errors_section}
            </div>
        </div>

        <div class="footer">
            Generated by Antivirus v1.2.0
        </div>
    </div>
</body>
</html>""")


def _format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def _format_size(bytes_size: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_size < 1024:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.1f} TB"


def generate_report(
    results: List[ScanResult],
    paths_scanned: List[str],
    scan_type: str = "manual",
    start_time: Optional[datetime] = None,
    exclusions_applied: Optional[List[str]] = None,
    quarantined_count: int = 0,
) -> ScanReport:
    """
    Generate a scan report from results.

    Args:
        results: List of ScanResult from scanning
        paths_scanned: Original paths that were scanned
        scan_type: Type of scan (manual, scheduled, monitor)
        start_time: When the scan started
        exclusions_applied: List of exclusion patterns that were applied
        quarantined_count: Number of files that were quarantined

    Returns:
        ScanReport object
    """
    end_time = datetime.now()
    if start_time is None:
        # Estimate start time from scan durations
        total_duration = sum(r.scan_time or 0 for r in results)
        start_time = end_time

    # Calculate statistics
    files_scanned = 0
    threats_found = 0
    heuristic_alerts = 0
    files_skipped = 0
    total_size = 0
    total_duration = 0.0

    threats: List[Dict] = []
    heuristic_results: List[Dict] = []
    errors: List[Dict] = []

    for result in results:
        if result.error:
            if not result.error.startswith("Excluded:"):
                errors.append({
                    "path": str(result.path),
                    "error": result.error,
                })
            files_skipped += 1
            continue

        files_scanned += 1
        if result.file_size:
            total_size += result.file_size
        if result.scan_time:
            total_duration += result.scan_time

        if result.is_threat:
            threats_found += 1
            threats.append(result.to_dict())

        # Track heuristic alerts separately
        if result.heuristic_result and result.heuristic_result.matches:
            heuristic_alerts += 1
            heuristic_results.append({
                "path": str(result.path),
                "entropy": result.heuristic_result.entropy,
                "risk_score": result.heuristic_result.risk_score,
                "is_suspicious": result.heuristic_result.is_suspicious,
                "matches": [m.to_dict() for m in result.heuristic_result.matches],
            })

    statistics = ScanStatistics(
        files_scanned=files_scanned,
        threats_found=threats_found,
        heuristic_alerts=heuristic_alerts,
        files_skipped=files_skipped,
        files_quarantined=quarantined_count,
        total_size_scanned=total_size,
        scan_duration=total_duration,
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
    )

    return ScanReport(
        id=str(uuid.uuid4())[:8],
        scan_type=scan_type,
        paths_scanned=paths_scanned,
        statistics=statistics,
        threats=threats,
        heuristic_alerts=heuristic_results,
        errors=errors,
        exclusions_applied=exclusions_applied or [],
        report_generated=end_time.isoformat(),
    )


def generate_json_report(report: ScanReport) -> str:
    """Generate JSON report string."""
    return json.dumps(report.to_dict(), indent=2)


def generate_html_report(report: ScanReport) -> str:
    """Generate HTML report string."""
    stats = report.statistics

    # Build paths section
    if report.paths_scanned:
        paths_html = "<ul>" + "".join(
            f"<li><code>{p}</code></li>" for p in report.paths_scanned
        ) + "</ul>"
    else:
        paths_html = '<p class="empty-message">No paths recorded</p>'

    # Build threats section
    if report.threats:
        threats_html = ""
        for threat in report.threats:
            threats_html += f'''
            <div class="threat-item">
                <div class="path">{threat["path"]}</div>
                <div class="threat-name">{threat["threat_name"]}</div>
            </div>
            '''
    else:
        threats_html = '<p class="empty-message">No threats detected</p>'

    # Build heuristics section
    if report.heuristic_alerts:
        heuristics_html = ""
        for alert in report.heuristic_alerts:
            risk_class = "risk-high" if alert["risk_score"] >= 50 else "risk-medium" if alert["risk_score"] >= 25 else "risk-low"
            matches_html = ""
            for match in alert.get("matches", []):
                severity_class = f"severity-{match['severity']}"
                matches_html += f'''
                <div class="heuristic-match">
                    <span class="{severity_class}">[{match["severity"].upper()}]</span>
                    {match["name"]}: {match["description"]}
                </div>
                '''
            heuristics_html += f'''
            <div class="heuristic-item">
                <div class="path">{alert["path"]}</div>
                <div>
                    <span class="risk-score {risk_class}">Risk: {alert["risk_score"]:.0f}</span>
                    Entropy: {alert["entropy"]:.2f}
                </div>
                <div class="matches">{matches_html}</div>
            </div>
            '''
    else:
        heuristics_html = '<p class="empty-message">No heuristic alerts</p>'

    # Build errors section
    if report.errors:
        errors_html = ""
        for error in report.errors:
            errors_html += f'''
            <div class="error-item">
                <span class="path">{error["path"]}</span>:
                <span class="error">{error["error"]}</span>
            </div>
            '''
    else:
        errors_html = '<p class="empty-message">No errors</p>'

    # Calculate clean files
    files_clean = stats.files_scanned - stats.threats_found

    return HTML_TEMPLATE.substitute(
        report_id=report.id,
        generated_time=report.report_generated,
        scan_type=report.scan_type.capitalize(),
        duration=_format_duration(stats.scan_duration),
        files_scanned=stats.files_scanned,
        threats_found=stats.threats_found,
        heuristic_alerts=stats.heuristic_alerts,
        files_clean=files_clean,
        paths_section=paths_html,
        threats_section=threats_html,
        heuristics_section=heuristics_html,
        errors_section=errors_html,
        errors_count=len(report.errors),
    )


def save_report(report: ScanReport, format: str = "json", output_path: Optional[Path] = None) -> Path:
    """
    Save a report to file.

    Args:
        report: ScanReport to save
        format: "json" or "html"
        output_path: Optional custom output path

    Returns:
        Path to saved report
    """
    if output_path is None:
        reports_dir = get_reports_dir()
        extension = "html" if format == "html" else "json"
        output_path = reports_dir / f"report_{report.id}.{extension}"

    if format == "html":
        content = generate_html_report(report)
    else:
        content = generate_json_report(report)

    with open(output_path, "w") as f:
        f.write(content)

    return output_path


def list_reports() -> List[Dict[str, Any]]:
    """List all saved reports."""
    reports_dir = get_reports_dir()
    reports = []

    for report_file in reports_dir.glob("report_*.json"):
        try:
            with open(report_file, "r") as f:
                data = json.load(f)
            reports.append({
                "id": data.get("id", report_file.stem.replace("report_", "")),
                "file": str(report_file),
                "format": "json",
                "scan_type": data.get("scan_type", "unknown"),
                "generated": data.get("report_generated", ""),
                "threats": data.get("statistics", {}).get("threats_found", 0),
            })
        except (json.JSONDecodeError, KeyError):
            continue

    for report_file in reports_dir.glob("report_*.html"):
        # For HTML files, extract ID from filename
        report_id = report_file.stem.replace("report_", "")
        reports.append({
            "id": report_id,
            "file": str(report_file),
            "format": "html",
            "scan_type": "unknown",
            "generated": datetime.fromtimestamp(report_file.stat().st_mtime).isoformat(),
            "threats": -1,  # Unknown for HTML
        })

    # Sort by generation time (newest first)
    reports.sort(key=lambda r: r.get("generated", ""), reverse=True)

    return reports


def load_report(report_id: str) -> Optional[ScanReport]:
    """Load a report by ID."""
    reports_dir = get_reports_dir()

    # Try JSON first
    json_path = reports_dir / f"report_{report_id}.json"
    if json_path.exists():
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
            return ScanReport.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return None

    return None


def delete_report(report_id: str) -> bool:
    """Delete a report by ID. Returns True if deleted."""
    reports_dir = get_reports_dir()
    deleted = False

    for pattern in [f"report_{report_id}.json", f"report_{report_id}.html"]:
        report_path = reports_dir / pattern
        if report_path.exists():
            report_path.unlink()
            deleted = True

    return deleted


def get_report_path(report_id: str, format: str = "json") -> Optional[Path]:
    """Get the path to a report file."""
    reports_dir = get_reports_dir()
    extension = "html" if format == "html" else "json"
    report_path = reports_dir / f"report_{report_id}.{extension}"

    if report_path.exists():
        return report_path
    return None
