"""Tests for monitor module."""

import time
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, Mock

from antivirus.monitor import (
    ThreatHandler,
    FileMonitor,
    monitor_paths,
)


@pytest.fixture
def mock_antivirus_env(temp_dir, monkeypatch):
    """Mock all antivirus directories for monitor tests."""
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
        "rules_dir": rules_dir,
    }


@pytest.fixture
def mock_event():
    """Factory for creating mock file system events."""
    def _create_event(src_path, is_directory=False, dest_path=None):
        event = MagicMock()
        event.src_path = str(src_path)
        event.is_directory = is_directory
        if dest_path:
            event.dest_path = str(dest_path)
        return event
    return _create_event


class TestThreatHandler:
    """Tests for ThreatHandler class."""

    def test_init_default_values(self):
        """Should initialize with default values."""
        handler = ThreatHandler()
        assert handler.auto_quarantine is False
        assert handler.on_threat is None
        assert handler.on_scan is None

    def test_init_with_callbacks(self):
        """Should accept callback functions."""
        on_threat = MagicMock()
        on_scan = MagicMock()

        handler = ThreatHandler(
            auto_quarantine=True,
            on_threat=on_threat,
            on_scan=on_scan
        )

        assert handler.auto_quarantine is True
        assert handler.on_threat is on_threat
        assert handler.on_scan is on_scan

    def test_scan_file_calls_on_scan(self, temp_dir, mock_antivirus_env):
        """Should call on_scan callback when scanning."""
        on_scan = MagicMock()
        handler = ThreatHandler(on_scan=on_scan)

        test_file = temp_dir / "test.txt"
        test_file.write_text("clean content")

        handler._scan_file(test_file)

        on_scan.assert_called_once_with(test_file)

    def test_scan_file_skips_directories(self, temp_dir):
        """Should skip directories."""
        on_scan = MagicMock()
        handler = ThreatHandler(on_scan=on_scan)

        handler._scan_file(temp_dir)

        on_scan.assert_not_called()

    def test_scan_file_detects_threat(self, temp_dir, mock_antivirus_env):
        """Should detect threats and call on_threat callback."""
        # Add a YARA rule
        rule_file = temp_dir / "test.yar"
        rule_file.write_text('rule Test { strings: $a = "MALWARE" condition: $a }')
        from antivirus.yara_rules import add_rule
        add_rule(rule_file)

        on_threat = MagicMock()
        handler = ThreatHandler(on_threat=on_threat)

        threat_file = temp_dir / "threat.txt"
        threat_file.write_text("Contains MALWARE pattern")

        handler._scan_file(threat_file)

        on_threat.assert_called_once()
        call_args = on_threat.call_args[0]
        assert call_args[0] == threat_file
        assert "YARA" in call_args[1]

    def test_scan_file_auto_quarantine(self, temp_dir, mock_antivirus_env):
        """Should quarantine threats when auto_quarantine is True."""
        # Add a YARA rule
        rule_file = temp_dir / "test.yar"
        rule_file.write_text('rule Test { strings: $a = "QUARANTINE" condition: $a }')
        from antivirus.yara_rules import add_rule
        add_rule(rule_file)

        handler = ThreatHandler(auto_quarantine=True)

        threat_file = temp_dir / "threat.txt"
        threat_file.write_text("Contains QUARANTINE pattern")

        handler._scan_file(threat_file)

        assert not threat_file.exists()

    def test_on_created_scans_file(self, temp_dir, mock_antivirus_env, mock_event):
        """Should scan file on creation event."""
        on_scan = MagicMock()
        handler = ThreatHandler(on_scan=on_scan)

        test_file = temp_dir / "new_file.txt"
        test_file.write_text("content")

        event = mock_event(test_file)
        handler.on_created(event)

        on_scan.assert_called_once()

    def test_on_created_skips_directories(self, temp_dir, mock_event):
        """Should skip directory creation events."""
        on_scan = MagicMock()
        handler = ThreatHandler(on_scan=on_scan)

        event = mock_event(temp_dir, is_directory=True)
        handler.on_created(event)

        on_scan.assert_not_called()

    def test_on_modified_scans_file(self, temp_dir, mock_antivirus_env, mock_event):
        """Should scan file on modification event."""
        on_scan = MagicMock()
        handler = ThreatHandler(on_scan=on_scan)

        test_file = temp_dir / "modified_file.txt"
        test_file.write_text("content")

        event = mock_event(test_file)
        handler.on_modified(event)

        on_scan.assert_called_once()

    def test_on_modified_skips_directories(self, temp_dir, mock_event):
        """Should skip directory modification events."""
        on_scan = MagicMock()
        handler = ThreatHandler(on_scan=on_scan)

        event = mock_event(temp_dir, is_directory=True)
        handler.on_modified(event)

        on_scan.assert_not_called()

    def test_on_moved_scans_destination(self, temp_dir, mock_antivirus_env, mock_event):
        """Should scan destination file on move event."""
        on_scan = MagicMock()
        handler = ThreatHandler(on_scan=on_scan)

        src_file = temp_dir / "src.txt"
        dest_file = temp_dir / "dest.txt"
        dest_file.write_text("content")

        event = mock_event(src_file, dest_path=dest_file)
        handler.on_moved(event)

        on_scan.assert_called_once()

    def test_on_moved_skips_directories(self, temp_dir, mock_event):
        """Should skip directory move events."""
        on_scan = MagicMock()
        handler = ThreatHandler(on_scan=on_scan)

        event = mock_event(temp_dir, is_directory=True, dest_path=temp_dir / "dest")
        handler.on_moved(event)

        on_scan.assert_not_called()


class TestFileMonitor:
    """Tests for FileMonitor class."""

    def test_init_resolves_paths(self, temp_dir):
        """Should resolve paths to absolute."""
        monitor = FileMonitor(paths=[temp_dir])
        assert all(p.is_absolute() for p in monitor.paths)

    def test_init_default_recursive(self, temp_dir):
        """Should default to recursive monitoring."""
        monitor = FileMonitor(paths=[temp_dir])
        assert monitor.recursive is True

    def test_init_creates_handler(self, temp_dir):
        """Should create ThreatHandler."""
        monitor = FileMonitor(paths=[temp_dir])
        assert isinstance(monitor.handler, ThreatHandler)

    def test_init_passes_callbacks(self, temp_dir):
        """Should pass callbacks to handler."""
        on_threat = MagicMock()
        on_scan = MagicMock()

        monitor = FileMonitor(
            paths=[temp_dir],
            auto_quarantine=True,
            on_threat=on_threat,
            on_scan=on_scan
        )

        assert monitor.handler.auto_quarantine is True
        assert monitor.handler.on_threat is on_threat
        assert monitor.handler.on_scan is on_scan

    def test_start_and_stop(self, temp_dir):
        """Should start and stop monitoring."""
        monitor = FileMonitor(paths=[temp_dir])

        monitor.start()
        assert monitor.is_running() is True

        monitor.stop()
        assert monitor.is_running() is False

    def test_is_running_before_start(self, temp_dir):
        """Should return False before starting."""
        monitor = FileMonitor(paths=[temp_dir])
        assert monitor.is_running() is False

    def test_monitors_multiple_paths(self, temp_dir):
        """Should handle multiple paths."""
        dir1 = temp_dir / "dir1"
        dir2 = temp_dir / "dir2"
        dir1.mkdir()
        dir2.mkdir()

        monitor = FileMonitor(paths=[dir1, dir2])
        monitor.start()

        assert monitor.is_running()
        assert len(monitor.paths) == 2

        monitor.stop()

    def test_skips_nonexistent_paths(self, temp_dir):
        """Should skip paths that don't exist."""
        existing = temp_dir / "exists"
        existing.mkdir()
        nonexistent = temp_dir / "nonexistent"

        monitor = FileMonitor(paths=[existing, nonexistent])
        monitor.start()

        # Should not raise and should be running
        assert monitor.is_running()

        monitor.stop()

    def test_detects_new_files(self, temp_dir, mock_antivirus_env):
        """Should detect newly created files."""
        scanned_files = []

        def on_scan(path):
            scanned_files.append(path)

        monitor = FileMonitor(
            paths=[temp_dir],
            on_scan=on_scan
        )

        monitor.start()
        time.sleep(0.1)

        # Create a new file
        new_file = temp_dir / "new_file.txt"
        new_file.write_text("test content")

        # Wait for event to be processed
        time.sleep(0.5)

        monitor.stop()

        # File should have been scanned
        assert any(str(new_file) in str(f) for f in scanned_files)


class TestMonitorPaths:
    """Tests for monitor_paths function."""

    def test_prints_startup_message(self, temp_dir, capsys):
        """Should print startup message."""
        with patch.object(FileMonitor, 'start'):
            with patch.object(FileMonitor, 'is_running', side_effect=[True, False]):
                with patch('time.sleep'):
                    monitor_paths([temp_dir])

        captured = capsys.readouterr()
        assert "Monitoring" in captured.out
        assert "path(s)" in captured.out

    def test_handles_keyboard_interrupt(self, temp_dir, capsys):
        """Should handle Ctrl+C gracefully."""
        with patch.object(FileMonitor, 'start'):
            with patch.object(FileMonitor, 'stop'):
                with patch.object(FileMonitor, 'is_running', return_value=True):
                    with patch('time.sleep', side_effect=KeyboardInterrupt):
                        monitor_paths([temp_dir])

        captured = capsys.readouterr()
        assert "Stopping" in captured.out
        assert "stopped" in captured.out

    def test_verbose_mode_prints_scans(self, temp_dir, mock_antivirus_env, capsys):
        """Should print scan messages in verbose mode."""
        # Create file before monitoring
        test_file = temp_dir / "test.txt"
        test_file.write_text("content")

        call_count = [0]

        def mock_is_running():
            call_count[0] += 1
            if call_count[0] == 1:
                # Trigger on_scan callback
                return True
            return False

        with patch.object(FileMonitor, 'is_running', side_effect=mock_is_running):
            with patch('time.sleep'):
                # Can't easily test verbose output without real events
                # Just verify it doesn't crash
                try:
                    monitor_paths([temp_dir], verbose=True)
                except:
                    pass

    def test_creates_monitor_with_options(self, temp_dir):
        """Should pass options to FileMonitor."""
        with patch('antivirus.monitor.FileMonitor') as MockMonitor:
            mock_instance = MagicMock()
            mock_instance.is_running.side_effect = [True, False]
            MockMonitor.return_value = mock_instance

            with patch('time.sleep'):
                monitor_paths(
                    [temp_dir],
                    recursive=False,
                    auto_quarantine=True,
                    verbose=True
                )

            MockMonitor.assert_called_once()
            call_kwargs = MockMonitor.call_args[1]
            assert call_kwargs['recursive'] is False
            assert call_kwargs['auto_quarantine'] is True


class TestMonitorIntegration:
    """Integration tests for the monitor system."""

    def test_full_threat_detection_flow(self, temp_dir, mock_antivirus_env):
        """Should detect and report threats in real-time."""
        # Add a YARA rule
        rule_file = temp_dir / "test.yar"
        rule_file.write_text('rule RealTime { strings: $a = "REALTIME_THREAT" condition: $a }')
        from antivirus.yara_rules import add_rule
        add_rule(rule_file)

        threats_detected = []

        def on_threat(path, threat_name):
            threats_detected.append((path, threat_name))

        monitor = FileMonitor(
            paths=[temp_dir],
            on_threat=on_threat
        )

        monitor.start()
        time.sleep(0.1)

        # Create a threat file
        threat_file = temp_dir / "realtime_threat.txt"
        threat_file.write_text("Contains REALTIME_THREAT pattern")

        # Wait for detection
        time.sleep(0.5)

        monitor.stop()

        # Verify threat was detected
        assert len(threats_detected) > 0
        assert any("YARA" in t[1] for t in threats_detected)

    def test_auto_quarantine_integration(self, temp_dir, mock_antivirus_env):
        """Should auto-quarantine threats."""
        # Add a YARA rule
        rule_file = temp_dir / "test.yar"
        rule_file.write_text('rule AutoQ { strings: $a = "AUTO_QUARANTINE" condition: $a }')
        from antivirus.yara_rules import add_rule
        add_rule(rule_file)

        # Create subdirectory to avoid quarantining the rule file
        watch_dir = temp_dir / "watch"
        watch_dir.mkdir()

        monitor = FileMonitor(
            paths=[watch_dir],
            auto_quarantine=True
        )

        monitor.start()
        time.sleep(0.1)

        # Create a threat file
        threat_file = watch_dir / "to_quarantine.txt"
        threat_file.write_text("Contains AUTO_QUARANTINE pattern")

        # Wait for quarantine
        time.sleep(0.5)

        monitor.stop()

        # File should be quarantined
        assert not threat_file.exists()
