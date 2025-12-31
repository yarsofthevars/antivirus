"""Tests for YARA rules module."""

import pytest
from pathlib import Path

from antivirus import yara_rules
from antivirus.yara_rules import (
    is_available,
    get_rules_dir,
    get_rule_files,
    load_rules,
    add_rule,
    add_rules_from_dir,
    list_rules,
    remove_rule,
    scan_with_yara,
    YaraMatch,
)


class TestYaraAvailability:
    """Tests for YARA availability check."""

    def test_is_available_returns_bool(self):
        """is_available should return a boolean."""
        result = is_available()
        assert isinstance(result, bool)

    def test_yara_is_available(self):
        """YARA should be available (installed for tests)."""
        assert is_available() is True


class TestGetRulesDir:
    """Tests for get_rules_dir function."""

    def test_returns_path(self):
        """Should return a Path object."""
        result = get_rules_dir()
        assert isinstance(result, Path)

    def test_directory_exists(self):
        """Should create directory if it doesn't exist."""
        result = get_rules_dir()
        assert result.exists()
        assert result.is_dir()

    def test_returns_correct_location(self):
        """Should return ~/.antivirus/rules."""
        result = get_rules_dir()
        assert result.name == "rules"
        assert result.parent.name == ".antivirus"


class TestAddRule:
    """Tests for add_rule function."""

    def test_add_valid_rule(self, sample_yara_rule, mock_rules_dir):
        """Should successfully add a valid YARA rule."""
        result = add_rule(sample_yara_rule)
        assert result is True
        assert (mock_rules_dir / sample_yara_rule.name).exists()

    def test_add_nonexistent_file(self, temp_dir, mock_rules_dir):
        """Should return False for nonexistent file."""
        result = add_rule(temp_dir / "nonexistent.yar")
        assert result is False

    def test_add_invalid_extension(self, temp_dir, mock_rules_dir):
        """Should reject files without .yar/.yara extension."""
        txt_file = temp_dir / "rule.txt"
        txt_file.write_text("rule Test { condition: true }")
        result = add_rule(txt_file)
        assert result is False

    def test_add_invalid_rule_syntax(self, invalid_yara_rule, mock_rules_dir):
        """Should reject rules that don't compile."""
        result = add_rule(invalid_yara_rule)
        assert result is False

    def test_rule_copied_to_rules_dir(self, sample_yara_rule, mock_rules_dir):
        """Rule file should be copied to rules directory."""
        add_rule(sample_yara_rule)
        copied_rule = mock_rules_dir / sample_yara_rule.name
        assert copied_rule.exists()
        assert copied_rule.read_text() == sample_yara_rule.read_text()


class TestAddRulesFromDir:
    """Tests for add_rules_from_dir function."""

    def test_add_multiple_rules(self, sample_yara_rules_dir, mock_rules_dir):
        """Should add all valid rules from directory."""
        added = add_rules_from_dir(sample_yara_rules_dir)
        assert len(added) == 2
        assert "rule1.yar" in added
        assert "rule2.yara" in added

    def test_returns_empty_for_nonexistent_dir(self, temp_dir, mock_rules_dir):
        """Should return empty list for nonexistent directory."""
        result = add_rules_from_dir(temp_dir / "nonexistent")
        assert result == []

    def test_returns_empty_for_file(self, sample_yara_rule, mock_rules_dir):
        """Should return empty list when given a file instead of directory."""
        result = add_rules_from_dir(sample_yara_rule)
        assert result == []

    def test_skips_invalid_rules(self, temp_dir, mock_rules_dir):
        """Should skip invalid rules and add valid ones."""
        rules_dir = temp_dir / "mixed_rules"
        rules_dir.mkdir()

        # Valid rule
        (rules_dir / "valid.yar").write_text("rule Valid { condition: true }")
        # Invalid rule
        (rules_dir / "invalid.yar").write_text("not valid yara {{{")

        added = add_rules_from_dir(rules_dir)
        assert len(added) == 1
        assert "valid.yar" in added


class TestListRules:
    """Tests for list_rules function."""

    def test_empty_when_no_rules(self, mock_rules_dir):
        """Should return empty list when no rules loaded."""
        result = list_rules()
        assert result == []

    def test_lists_added_rules(self, sample_yara_rule, mock_rules_dir):
        """Should list rules after they're added."""
        add_rule(sample_yara_rule)
        result = list_rules()
        assert len(result) == 1
        assert result[0]["name"] == sample_yara_rule.name

    def test_includes_metadata(self, sample_yara_rule, mock_rules_dir):
        """Should include name, path, and size."""
        add_rule(sample_yara_rule)
        result = list_rules()
        rule = result[0]
        assert "name" in rule
        assert "path" in rule
        assert "size" in rule
        assert isinstance(rule["size"], int)


class TestRemoveRule:
    """Tests for remove_rule function."""

    def test_remove_existing_rule(self, sample_yara_rule, mock_rules_dir):
        """Should successfully remove an existing rule."""
        add_rule(sample_yara_rule)
        result = remove_rule(sample_yara_rule.name)
        assert result is True
        assert not (mock_rules_dir / sample_yara_rule.name).exists()

    def test_remove_nonexistent_rule(self, mock_rules_dir):
        """Should return False for nonexistent rule."""
        result = remove_rule("nonexistent.yar")
        assert result is False

    def test_remove_by_name_without_extension(self, sample_yara_rule, mock_rules_dir):
        """Should find rule even without extension."""
        add_rule(sample_yara_rule)
        # Try removing without .yar extension
        result = remove_rule("test_rule")
        assert result is True


class TestLoadRules:
    """Tests for load_rules function."""

    def test_returns_none_when_no_rules(self, mock_rules_dir):
        """Should return None when no rules are present."""
        result = load_rules()
        assert result is None

    def test_returns_compiled_rules(self, sample_yara_rule, mock_rules_dir):
        """Should return compiled YARA rules object."""
        add_rule(sample_yara_rule)
        result = load_rules()
        assert result is not None


class TestScanWithYara:
    """Tests for scan_with_yara function."""

    def test_detects_matching_file(self, sample_yara_rule, malicious_file, mock_rules_dir):
        """Should detect file matching YARA rule."""
        add_rule(sample_yara_rule)
        matches = scan_with_yara(malicious_file)
        assert len(matches) == 1
        assert matches[0].rule_name == "TestRule"

    def test_no_match_for_clean_file(self, sample_yara_rule, clean_file, mock_rules_dir):
        """Should return empty list for clean file."""
        add_rule(sample_yara_rule)
        matches = scan_with_yara(clean_file)
        assert matches == []

    def test_returns_empty_when_no_rules(self, malicious_file, mock_rules_dir):
        """Should return empty list when no rules loaded."""
        matches = scan_with_yara(malicious_file)
        assert matches == []

    def test_returns_empty_for_nonexistent_file(self, mock_rules_dir):
        """Should return empty list for nonexistent file."""
        matches = scan_with_yara(Path("/nonexistent/file.txt"))
        assert matches == []

    def test_match_includes_metadata(self, sample_yara_rule, malicious_file, mock_rules_dir):
        """Match should include rule name, file, and tags."""
        add_rule(sample_yara_rule)
        matches = scan_with_yara(malicious_file)
        match = matches[0]
        assert isinstance(match, YaraMatch)
        assert match.rule_name == "TestRule"
        assert match.rule_file == "test_rule"
        assert "test" in match.tags


class TestYaraMatchDataclass:
    """Tests for YaraMatch dataclass."""

    def test_create_yara_match(self):
        """Should create YaraMatch with all fields."""
        match = YaraMatch(
            rule_name="TestRule",
            rule_file="test.yar",
            tags=["malware", "trojan"]
        )
        assert match.rule_name == "TestRule"
        assert match.rule_file == "test.yar"
        assert match.tags == ["malware", "trojan"]

    def test_empty_tags(self):
        """Should handle empty tags list."""
        match = YaraMatch(
            rule_name="TestRule",
            rule_file="test.yar",
            tags=[]
        )
        assert match.tags == []
