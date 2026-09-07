"""Tests for the reports module."""

import pytest
import json
from pathlib import Path
from datetime import datetime

from antivirus.reports import (
    ScanStatistics,
    ScanReport,
    generate_report,
    generate_json_report,
    generate_html_report,
    save_report,
    list_reports,
    load_report,
    delete_report,
)
from antivirus.scanner import ScanResult


class TestScanStatistics:
    """Tests for ScanStatistics dataclass."""

    def test_default_values(self):
        """Should have sensible defaults."""
        stats = ScanStatistics()
        assert stats.files_scanned == 0
        assert stats.threats_found == 0
        assert stats.scan_duration == 0.0

    def test_to_dict(self):
        """Should serialize to dictionary."""
        stats = ScanStatistics(
            files_scanned=100,
            threats_found=5,
            scan_duration=10.5,
        )
        d = stats.to_dict()
        assert d["files_scanned"] == 100
        assert d["threats_found"] == 5
        assert d["scan_duration"] == 10.5


class TestGenerateReport:
    """Tests for report generation."""

    def test_empty_results(self):
        """Should handle empty results."""
        report = generate_report(
            results=[],
            paths_scanned=["/test"],
        )
        assert report.statistics.files_scanned == 0
        assert report.statistics.threats_found == 0
        assert len(report.threats) == 0

    def test_with_threats(self, temp_dir):
        """Should count threats correctly."""
        results = [
            ScanResult(
                path=temp_dir / "clean.txt",
                is_threat=False,
            ),
            ScanResult(
                path=temp_dir / "malware.exe",
                is_threat=True,
                threat_name="Test.Malware",
            ),
        ]
        report = generate_report(
            results=results,
            paths_scanned=[str(temp_dir)],
        )
        assert report.statistics.files_scanned == 2
        assert report.statistics.threats_found == 1
        assert len(report.threats) == 1

    def test_with_errors(self, temp_dir):
        """Should track errors."""
        results = [
            ScanResult(
                path=temp_dir / "error.txt",
                is_threat=False,
                error="Permission denied",
            ),
        ]
        report = generate_report(
            results=results,
            paths_scanned=[str(temp_dir)],
        )
        assert report.statistics.files_skipped == 1
        assert len(report.errors) == 1

    def test_report_id_generated(self):
        """Should generate unique report ID."""
        report = generate_report(results=[], paths_scanned=["/test"])
        assert report.id is not None
        assert len(report.id) == 8


class TestGenerateJsonReport:
    """Tests for JSON report generation."""

    def test_valid_json(self):
        """Should generate valid JSON."""
        report = generate_report(results=[], paths_scanned=["/test"])
        json_str = generate_json_report(report)
        parsed = json.loads(json_str)
        assert "id" in parsed
        assert "statistics" in parsed

    def test_includes_all_fields(self, temp_dir):
        """Should include all report fields."""
        results = [
            ScanResult(
                path=temp_dir / "file.txt",
                is_threat=True,
                threat_name="Test",
            ),
        ]
        report = generate_report(results=results, paths_scanned=[str(temp_dir)])
        json_str = generate_json_report(report)
        parsed = json.loads(json_str)

        assert "threats" in parsed
        assert "statistics" in parsed
        assert "paths_scanned" in parsed


class TestGenerateHtmlReport:
    """Tests for HTML report generation."""

    def test_valid_html(self):
        """Should generate valid HTML."""
        report = generate_report(results=[], paths_scanned=["/test"])
        html = generate_html_report(report)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_includes_statistics(self):
        """Should include statistics in HTML."""
        report = generate_report(results=[], paths_scanned=["/test"])
        report.statistics.files_scanned = 42
        html = generate_html_report(report)
        assert "42" in html

    def test_includes_threats(self, temp_dir):
        """Should include threats in HTML."""
        results = [
            ScanResult(
                path=temp_dir / "malware.exe",
                is_threat=True,
                threat_name="Evil.Trojan",
            ),
        ]
        report = generate_report(results=results, paths_scanned=[str(temp_dir)])
        html = generate_html_report(report)
        assert "Evil.Trojan" in html


class TestReportPersistence:
    """Tests for report persistence."""

    def test_save_json_report(self, clean_config):
        """Should save JSON report to file."""
        report = generate_report(results=[], paths_scanned=["/test"])
        path = save_report(report, format="json")
        assert path.exists()
        assert path.suffix == ".json"

    def test_save_html_report(self, clean_config):
        """Should save HTML report to file."""
        report = generate_report(results=[], paths_scanned=["/test"])
        path = save_report(report, format="html")
        assert path.exists()
        assert path.suffix == ".html"

    def test_save_to_custom_path(self, temp_dir):
        """Should save to custom path."""
        report = generate_report(results=[], paths_scanned=["/test"])
        custom_path = temp_dir / "custom_report.json"
        path = save_report(report, format="json", output_path=custom_path)
        assert path == custom_path
        assert path.exists()

    def test_list_reports(self, clean_config):
        """Should list saved reports."""
        report = generate_report(results=[], paths_scanned=["/test"])
        save_report(report, format="json")

        reports = list_reports()
        assert len(reports) >= 1
        assert any(r["id"] == report.id for r in reports)

    def test_load_report(self, clean_config):
        """Should load saved report."""
        report = generate_report(results=[], paths_scanned=["/test"])
        save_report(report, format="json")

        loaded = load_report(report.id)
        assert loaded is not None
        assert loaded.id == report.id

    def test_delete_report(self, clean_config):
        """Should delete report."""
        report = generate_report(results=[], paths_scanned=["/test"])
        save_report(report, format="json")

        assert delete_report(report.id) is True
        assert delete_report(report.id) is False  # Already deleted
        assert load_report(report.id) is None


class TestScanReportSerialization:
    """Tests for ScanReport serialization."""

    def test_to_dict(self):
        """Should convert to dictionary."""
        report = generate_report(results=[], paths_scanned=["/test"])
        d = report.to_dict()
        assert "id" in d
        assert "statistics" in d
        assert "threats" in d

    def test_from_dict(self):
        """Should create from dictionary."""
        report = generate_report(results=[], paths_scanned=["/test"])
        d = report.to_dict()
        restored = ScanReport.from_dict(d)
        assert restored.id == report.id
        assert restored.scan_type == report.scan_type
