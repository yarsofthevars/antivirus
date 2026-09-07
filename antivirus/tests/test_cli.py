"""Tests for the CLI module."""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch
from io import StringIO

from antivirus.cli import main


class TestCLI:
    """Tests for CLI commands."""

    def test_scan_help(self):
        """Should show scan help."""
        with patch.object(sys, 'argv', ['antivirus', 'scan', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_exclude_help(self):
        """Should show exclude help."""
        with patch.object(sys, 'argv', ['antivirus', 'exclude', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_report_help(self):
        """Should show report help."""
        with patch.object(sys, 'argv', ['antivirus', 'report', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_schedule_help(self):
        """Should show schedule help."""
        with patch.object(sys, 'argv', ['antivirus', 'schedule', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_config_help(self):
        """Should show config help."""
        with patch.object(sys, 'argv', ['antivirus', 'config', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_scan_clean_file(self, sample_file):
        """Should scan clean file successfully."""
        with patch.object(sys, 'argv', ['antivirus', 'scan', str(sample_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0  # No threats

    def test_scan_nonexistent(self, temp_dir):
        """Should handle nonexistent path."""
        with patch.object(sys, 'argv', ['antivirus', 'scan', str(temp_dir / 'nonexistent')]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0  # No threats (file doesn't exist)

    def test_scan_with_heuristics(self, sample_file):
        """Should scan with heuristics flag."""
        with patch.object(sys, 'argv', ['antivirus', 'scan', str(sample_file), '--heuristics']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_config_show(self, clean_config):
        """Should show config."""
        with patch.object(sys, 'argv', ['antivirus', 'config', 'show']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_exclude_list_empty(self, clean_config):
        """Should list empty exclusions."""
        with patch.object(sys, 'argv', ['antivirus', 'exclude', 'list']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_schedule_list_empty(self, clean_config):
        """Should list empty schedule."""
        with patch.object(sys, 'argv', ['antivirus', 'schedule', 'list']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_report_list_empty(self, clean_config):
        """Should list empty reports."""
        with patch.object(sys, 'argv', ['antivirus', 'report', 'list']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_daemon_status(self, clean_config):
        """Should show daemon status."""
        with patch.object(sys, 'argv', ['antivirus', 'daemon', 'status']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_list_signatures(self):
        """Should list signatures."""
        with patch.object(sys, 'argv', ['antivirus', 'list-signatures']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_list_rules(self):
        """Should list YARA rules."""
        with patch.object(sys, 'argv', ['antivirus', 'list-rules']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

    def test_list_quarantine(self):
        """Should list quarantine."""
        with patch.object(sys, 'argv', ['antivirus', 'list-quarantine']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0
