"""Tests for __main__ module."""

import pytest
import subprocess
import sys


class TestMainModule:
    """Tests for __main__.py entry point."""

    def test_module_runnable(self):
        """Should be runnable as python -m antivirus."""
        result = subprocess.run(
            [sys.executable, "-m", "antivirus", "--help"],
            capture_output=True,
            text=True,
            cwd="/Users/enriquesantiago"
        )
        assert result.returncode == 0
        assert "antivirus" in result.stdout.lower()

    def test_shows_help(self):
        """Should show help message."""
        result = subprocess.run(
            [sys.executable, "-m", "antivirus", "--help"],
            capture_output=True,
            text=True,
            cwd="/Users/enriquesantiago"
        )
        assert "scan" in result.stdout
        assert "quarantine" in result.stdout
        assert "monitor" in result.stdout

    def test_requires_command(self):
        """Should require a command."""
        result = subprocess.run(
            [sys.executable, "-m", "antivirus"],
            capture_output=True,
            text=True,
            cwd="/Users/enriquesantiago"
        )
        assert result.returncode != 0

    def test_scan_command_exists(self):
        """Should have scan command."""
        result = subprocess.run(
            [sys.executable, "-m", "antivirus", "scan", "--help"],
            capture_output=True,
            text=True,
            cwd="/Users/enriquesantiago"
        )
        assert result.returncode == 0
        assert "path" in result.stdout.lower()

    def test_list_signatures_command(self):
        """Should list signatures."""
        result = subprocess.run(
            [sys.executable, "-m", "antivirus", "list-signatures"],
            capture_output=True,
            text=True,
            cwd="/Users/enriquesantiago"
        )
        assert result.returncode == 0
        assert "Signatures" in result.stdout or "EICAR" in result.stdout

    def test_list_rules_command(self):
        """Should list rules."""
        result = subprocess.run(
            [sys.executable, "-m", "antivirus", "list-rules"],
            capture_output=True,
            text=True,
            cwd="/Users/enriquesantiago"
        )
        assert result.returncode == 0

    def test_list_quarantine_command(self):
        """Should list quarantine."""
        result = subprocess.run(
            [sys.executable, "-m", "antivirus", "list-quarantine"],
            capture_output=True,
            text=True,
            cwd="/Users/enriquesantiago"
        )
        assert result.returncode == 0

    def test_invalid_command(self):
        """Should error on invalid command."""
        result = subprocess.run(
            [sys.executable, "-m", "antivirus", "invalid-command"],
            capture_output=True,
            text=True,
            cwd="/Users/enriquesantiago"
        )
        assert result.returncode != 0


class TestMainImport:
    """Tests for importing __main__ module."""

    def test_imports_main_function(self):
        """Should import main from cli."""
        from antivirus.__main__ import main
        assert callable(main)

    def test_main_is_cli_main(self):
        """main should be the same as cli.main."""
        from antivirus.__main__ import main as main_main
        from antivirus.cli import main as cli_main
        assert main_main is cli_main
