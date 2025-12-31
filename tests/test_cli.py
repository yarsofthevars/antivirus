"""Tests for CLI module."""

import argparse
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from antivirus.cli import (
    cmd_scan,
    cmd_quarantine,
    cmd_list_quarantine,
    cmd_restore,
    cmd_delete,
    cmd_add_signature,
    cmd_list_signatures,
    cmd_add_rule,
    cmd_add_rules,
    cmd_list_rules,
    cmd_remove_rule,
    main,
)


@pytest.fixture
def mock_antivirus_dirs(temp_dir, monkeypatch):
    """Mock all antivirus directories."""
    # Mock quarantine
    quarantine_dir = temp_dir / "quarantine"
    quarantine_dir.mkdir()
    log_path = temp_dir / "quarantine_log.json"

    from antivirus import quarantine
    monkeypatch.setattr(quarantine, "get_quarantine_dir", lambda: quarantine_dir)
    monkeypatch.setattr(quarantine, "get_log_path", lambda: log_path)

    # Mock signatures
    signatures_path = temp_dir / "signatures.json"

    from antivirus import signatures
    monkeypatch.setattr(signatures, "get_db_path", lambda: signatures_path)

    # Mock YARA rules
    rules_dir = temp_dir / "rules"
    rules_dir.mkdir()

    from antivirus import yara_rules
    monkeypatch.setattr(yara_rules, "get_rules_dir", lambda: rules_dir)

    return {
        "quarantine_dir": quarantine_dir,
        "log_path": log_path,
        "signatures_path": signatures_path,
        "rules_dir": rules_dir,
    }


@pytest.fixture
def make_args():
    """Factory to create argparse Namespace objects."""
    def _make_args(**kwargs):
        return argparse.Namespace(**kwargs)
    return _make_args


class TestCmdScan:
    """Tests for cmd_scan command."""

    def test_scan_clean_file(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should scan clean file with no threats."""
        clean_file = temp_dir / "clean.txt"
        clean_file.write_text("Clean content")

        args = make_args(
            path=str(clean_file),
            quarantine=False,
            verbose=False,
            no_recursive=False
        )
        result = cmd_scan(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "0 threats found" in captured.out

    def test_scan_directory(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should scan directory recursively."""
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        (temp_dir / "file1.txt").write_text("content1")
        (subdir / "file2.txt").write_text("content2")

        args = make_args(
            path=str(temp_dir),
            quarantine=False,
            verbose=False,
            no_recursive=False
        )
        result = cmd_scan(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "files scanned" in captured.out

    def test_scan_verbose_output(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should show all files in verbose mode."""
        clean_file = temp_dir / "clean.txt"
        clean_file.write_text("Clean content")

        args = make_args(
            path=str(clean_file),
            quarantine=False,
            verbose=True,
            no_recursive=False
        )
        cmd_scan(args)

        captured = capsys.readouterr()
        assert "[OK]" in captured.out

    def test_scan_with_threat_detection(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should detect threats via YARA rules."""
        # Add a YARA rule
        rule_file = temp_dir / "test.yar"
        rule_file.write_text('rule Test { strings: $a = "THREAT" condition: $a }')

        from antivirus.yara_rules import add_rule
        add_rule(rule_file)

        # Create threat file
        threat_file = temp_dir / "threat.txt"
        threat_file.write_text("Contains THREAT pattern")

        args = make_args(
            path=str(threat_file),
            quarantine=False,
            verbose=False,
            no_recursive=False
        )
        result = cmd_scan(args)

        assert result == 1  # Exit code 1 when threats found
        captured = capsys.readouterr()
        assert "[THREAT]" in captured.out
        assert "1 threats found" in captured.out

    def test_scan_with_auto_quarantine(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should quarantine threats when --quarantine flag used."""
        # Add a YARA rule
        rule_file = temp_dir / "test.yar"
        rule_file.write_text('rule Test { strings: $a = "QUARANTINE_ME" condition: $a }')

        from antivirus.yara_rules import add_rule
        add_rule(rule_file)

        # Create threat file
        threat_file = temp_dir / "threat.txt"
        threat_file.write_text("Contains QUARANTINE_ME pattern")

        args = make_args(
            path=str(threat_file),
            quarantine=True,
            verbose=False,
            no_recursive=False
        )
        cmd_scan(args)

        captured = capsys.readouterr()
        assert "Quarantined" in captured.out
        assert not threat_file.exists()


class TestCmdQuarantine:
    """Tests for cmd_quarantine command."""

    def test_quarantine_file(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should quarantine a file manually."""
        file_path = temp_dir / "file.txt"
        file_path.write_text("content")

        args = make_args(path=str(file_path), threat="ManualThreat")
        result = cmd_quarantine(args)

        assert result == 0
        assert not file_path.exists()
        captured = capsys.readouterr()
        assert "Quarantined" in captured.out

    def test_quarantine_nonexistent_file(self, temp_dir, make_args, capsys):
        """Should error on nonexistent file."""
        args = make_args(path=str(temp_dir / "nonexistent.txt"), threat=None)
        result = cmd_quarantine(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out

    def test_quarantine_default_threat_name(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should use default threat name when not specified."""
        file_path = temp_dir / "file.txt"
        file_path.write_text("content")

        args = make_args(path=str(file_path), threat=None)
        cmd_quarantine(args)

        from antivirus.quarantine import list_quarantine
        entries = list_quarantine()
        assert entries[0].threat_name == "Manual-Quarantine"


class TestCmdListQuarantine:
    """Tests for cmd_list_quarantine command."""

    def test_empty_quarantine(self, mock_antivirus_dirs, make_args, capsys):
        """Should show message when quarantine is empty."""
        args = make_args()
        result = cmd_list_quarantine(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "empty" in captured.out.lower()

    def test_list_quarantined_files(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should list quarantined files."""
        file_path = temp_dir / "file.txt"
        file_path.write_text("content")

        from antivirus.quarantine import quarantine_file
        entry = quarantine_file(file_path, "TestThreat")

        args = make_args()
        cmd_list_quarantine(args)

        captured = capsys.readouterr()
        assert entry.id in captured.out
        assert "TestThreat" in captured.out


class TestCmdRestore:
    """Tests for cmd_restore command."""

    def test_restore_file(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should restore quarantined file."""
        file_path = temp_dir / "file.txt"
        file_path.write_text("content")

        from antivirus.quarantine import quarantine_file
        entry = quarantine_file(file_path, "TestThreat")

        args = make_args(id=entry.id)
        result = cmd_restore(args)

        assert result == 0
        assert file_path.exists()
        captured = capsys.readouterr()
        assert "Restored" in captured.out

    def test_restore_nonexistent_id(self, mock_antivirus_dirs, make_args, capsys):
        """Should error on nonexistent ID."""
        args = make_args(id="nonexistent")
        result = cmd_restore(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out


class TestCmdDelete:
    """Tests for cmd_delete command."""

    def test_delete_quarantined(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should delete quarantined file."""
        file_path = temp_dir / "file.txt"
        file_path.write_text("content")

        from antivirus.quarantine import quarantine_file
        entry = quarantine_file(file_path, "TestThreat")

        args = make_args(id=entry.id)
        result = cmd_delete(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Deleted" in captured.out

    def test_delete_nonexistent_id(self, mock_antivirus_dirs, make_args, capsys):
        """Should error on nonexistent ID."""
        args = make_args(id="nonexistent")
        result = cmd_delete(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out


class TestCmdAddSignature:
    """Tests for cmd_add_signature command."""

    def test_add_signature(self, mock_antivirus_dirs, make_args, capsys):
        """Should add a signature."""
        args = make_args(
            hash="abc123def456",
            name="TestMalware"
        )
        result = cmd_add_signature(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Added signature" in captured.out
        assert "TestMalware" in captured.out


class TestCmdListSignatures:
    """Tests for cmd_list_signatures command."""

    def test_list_signatures(self, mock_antivirus_dirs, make_args, capsys):
        """Should list all signatures."""
        # Add a signature first
        from antivirus.signatures import add_signature
        add_signature("abc123", "TestMalware")

        args = make_args()
        result = cmd_list_signatures(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "TestMalware" in captured.out


class TestCmdAddRule:
    """Tests for cmd_add_rule command."""

    def test_add_rule(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should add a YARA rule."""
        rule_file = temp_dir / "test.yar"
        rule_file.write_text("rule Test { condition: true }")

        args = make_args(path=str(rule_file))
        result = cmd_add_rule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Added YARA rule" in captured.out

    def test_add_nonexistent_rule(self, temp_dir, make_args, capsys):
        """Should error on nonexistent file."""
        args = make_args(path=str(temp_dir / "nonexistent.yar"))
        result = cmd_add_rule(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out

    def test_add_invalid_rule(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should error on invalid YARA rule."""
        rule_file = temp_dir / "invalid.yar"
        rule_file.write_text("this is not valid yara {{{")

        args = make_args(path=str(rule_file))
        result = cmd_add_rule(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out or "Failed" in captured.out


class TestCmdAddRules:
    """Tests for cmd_add_rules command."""

    def test_add_rules_from_dir(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should add all YARA rules from directory."""
        rules_dir = temp_dir / "my_rules"
        rules_dir.mkdir()
        (rules_dir / "rule1.yar").write_text("rule Rule1 { condition: true }")
        (rules_dir / "rule2.yara").write_text("rule Rule2 { condition: true }")

        args = make_args(path=str(rules_dir))
        result = cmd_add_rules(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Added" in captured.out
        assert "2" in captured.out

    def test_add_rules_nonexistent_dir(self, temp_dir, make_args, capsys):
        """Should error on nonexistent directory."""
        args = make_args(path=str(temp_dir / "nonexistent"))
        result = cmd_add_rules(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out


class TestCmdListRules:
    """Tests for cmd_list_rules command."""

    def test_list_empty_rules(self, mock_antivirus_dirs, make_args, capsys):
        """Should show message when no rules loaded."""
        args = make_args()
        result = cmd_list_rules(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No YARA rules" in captured.out

    def test_list_rules(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should list loaded rules."""
        rule_file = temp_dir / "test.yar"
        rule_file.write_text("rule Test { condition: true }")

        from antivirus.yara_rules import add_rule
        add_rule(rule_file)

        args = make_args()
        cmd_list_rules(args)

        captured = capsys.readouterr()
        assert "test.yar" in captured.out


class TestCmdRemoveRule:
    """Tests for cmd_remove_rule command."""

    def test_remove_rule(self, temp_dir, mock_antivirus_dirs, make_args, capsys):
        """Should remove a YARA rule."""
        rule_file = temp_dir / "test.yar"
        rule_file.write_text("rule Test { condition: true }")

        from antivirus.yara_rules import add_rule
        add_rule(rule_file)

        args = make_args(name="test.yar")
        result = cmd_remove_rule(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Removed" in captured.out

    def test_remove_nonexistent_rule(self, mock_antivirus_dirs, make_args, capsys):
        """Should error on nonexistent rule."""
        args = make_args(name="nonexistent.yar")
        result = cmd_remove_rule(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error" in captured.out


class TestMain:
    """Tests for main entry point."""

    def test_main_with_help(self):
        """Should show help and exit."""
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["antivirus", "--help"]):
                main()
        assert exc_info.value.code == 0

    def test_main_requires_command(self):
        """Should error when no command provided."""
        with pytest.raises(SystemExit) as exc_info:
            with patch("sys.argv", ["antivirus"]):
                main()
        assert exc_info.value.code != 0
