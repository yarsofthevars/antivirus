"""Tests for scanner YARA integration."""

import pytest
from pathlib import Path

from antivirus.scanner import scan_file, scan_path, ScanResult
from antivirus.yara_rules import add_rule, YaraMatch


class TestScanFileWithYara:
    """Tests for scan_file with YARA detection."""

    def test_detects_yara_threat(self, sample_yara_rule, malicious_file, mock_rules_dir):
        """Should detect threat via YARA rule."""
        add_rule(sample_yara_rule)
        result = scan_file(malicious_file)

        assert result.is_threat is True
        assert result.threat_name is not None
        assert "YARA" in result.threat_name
        assert len(result.yara_matches) > 0

    def test_clean_file_no_threat(self, sample_yara_rule, clean_file, mock_rules_dir):
        """Clean file should not be flagged as threat."""
        add_rule(sample_yara_rule)
        result = scan_file(clean_file)

        assert result.is_threat is False
        assert result.threat_name is None
        assert result.yara_matches == []

    def test_scan_result_includes_yara_matches(self, sample_yara_rule, malicious_file, mock_rules_dir):
        """ScanResult should include YARA match details."""
        add_rule(sample_yara_rule)
        result = scan_file(malicious_file)

        assert isinstance(result.yara_matches, list)
        assert len(result.yara_matches) == 1

        match = result.yara_matches[0]
        assert isinstance(match, YaraMatch)
        assert match.rule_name == "TestRule"

    def test_threat_name_format(self, sample_yara_rule, malicious_file, mock_rules_dir):
        """Threat name should be prefixed with YARA: when only YARA matches."""
        add_rule(sample_yara_rule)
        result = scan_file(malicious_file)

        assert result.threat_name.startswith("YARA:")

    def test_scan_without_yara_rules(self, clean_file, mock_rules_dir):
        """Should work without any YARA rules loaded."""
        result = scan_file(clean_file)

        assert result.is_threat is False
        assert result.yara_matches == []
        assert result.error is None

    def test_scan_nonexistent_file(self, temp_dir):
        """Should handle nonexistent file gracefully."""
        result = scan_file(temp_dir / "nonexistent.txt")

        assert result.is_threat is False
        assert result.error is not None


class TestScanPathWithYara:
    """Tests for scan_path with YARA detection."""

    def test_scan_directory_with_threats(self, sample_yara_rule, temp_dir, mock_rules_dir):
        """Should detect threats in directory scan."""
        add_rule(sample_yara_rule)

        # Create a separate scan directory to avoid scanning rule files
        scan_dir = temp_dir / "scan_target"
        scan_dir.mkdir()

        # Create files
        (scan_dir / "malicious.txt").write_text("Contains MALWARE_TEST_STRING here")
        (scan_dir / "clean.txt").write_text("Clean file content")

        results = scan_path(scan_dir)

        threats = [r for r in results if r.is_threat]
        clean = [r for r in results if not r.is_threat and not r.error]

        assert len(threats) == 1
        assert len(clean) == 1

    def test_scan_single_file(self, sample_yara_rule, malicious_file, mock_rules_dir):
        """Should scan single file via scan_path."""
        add_rule(sample_yara_rule)
        results = scan_path(malicious_file)

        assert len(results) == 1
        assert results[0].is_threat is True


class TestScanResultDataclass:
    """Tests for ScanResult with YARA fields."""

    def test_scan_result_default_yara_matches(self, clean_file, mock_rules_dir):
        """ScanResult should default to empty yara_matches list."""
        result = scan_file(clean_file)
        assert result.yara_matches == []

    def test_scan_result_all_fields(self, sample_yara_rule, malicious_file, mock_rules_dir):
        """ScanResult should have all expected fields."""
        add_rule(sample_yara_rule)
        result = scan_file(malicious_file)

        assert hasattr(result, 'path')
        assert hasattr(result, 'is_threat')
        assert hasattr(result, 'threat_name')
        assert hasattr(result, 'yara_matches')
        assert hasattr(result, 'error')


class TestCombinedDetection:
    """Tests for combined hash signature and YARA detection."""

    def test_yara_only_detection(self, sample_yara_rule, malicious_file, mock_rules_dir):
        """File detected only by YARA should have YARA: prefix."""
        add_rule(sample_yara_rule)
        result = scan_file(malicious_file)

        assert result.is_threat is True
        assert result.threat_name.startswith("YARA:")
        assert len(result.yara_matches) > 0

    def test_multiple_yara_matches(self, temp_dir, mock_rules_dir):
        """File matching multiple YARA rules should report all matches."""
        # Create rules that both match
        rule1 = temp_dir / "rule1.yar"
        rule1.write_text('''rule Rule1 {
            strings: $a = "MULTI"
            condition: $a
        }''')

        rule2 = temp_dir / "rule2.yar"
        rule2.write_text('''rule Rule2 {
            strings: $b = "MATCH"
            condition: $b
        }''')

        add_rule(rule1)
        add_rule(rule2)

        # Create file matching both
        test_file = temp_dir / "multi_match.txt"
        test_file.write_text("This has MULTI and MATCH patterns")

        result = scan_file(test_file)

        assert result.is_threat is True
        assert len(result.yara_matches) == 2
        rule_names = [m.rule_name for m in result.yara_matches]
        assert "Rule1" in rule_names
        assert "Rule2" in rule_names
