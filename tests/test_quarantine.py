"""Tests for quarantine module."""

import json
import pytest
from pathlib import Path

from antivirus.quarantine import (
    QuarantineEntry,
    get_quarantine_dir,
    get_log_path,
    load_log,
    save_log,
    quarantine_file,
    list_quarantine,
    restore_file,
    delete_quarantined,
)


@pytest.fixture
def mock_quarantine_dir(temp_dir, monkeypatch):
    """Mock the quarantine directory to use a temp directory."""
    quarantine_dir = temp_dir / "quarantine"
    quarantine_dir.mkdir()
    log_path = temp_dir / "quarantine_log.json"

    from antivirus import quarantine
    monkeypatch.setattr(quarantine, "get_quarantine_dir", lambda: quarantine_dir)
    monkeypatch.setattr(quarantine, "get_log_path", lambda: log_path)

    return quarantine_dir, log_path


@pytest.fixture
def sample_file(temp_dir):
    """Create a sample file to quarantine."""
    file_path = temp_dir / "infected.txt"
    file_path.write_text("This is an infected file.")
    return file_path


class TestQuarantineEntry:
    """Tests for QuarantineEntry dataclass."""

    def test_create_entry(self):
        """Should create QuarantineEntry with all fields."""
        entry = QuarantineEntry(
            id="abc12345",
            original_path="/path/to/file.txt",
            quarantine_name="abc12345_file.txt.quarantined",
            threat_name="TestThreat",
            date="2025-01-01T12:00:00"
        )
        assert entry.id == "abc12345"
        assert entry.original_path == "/path/to/file.txt"
        assert entry.quarantine_name == "abc12345_file.txt.quarantined"
        assert entry.threat_name == "TestThreat"
        assert entry.date == "2025-01-01T12:00:00"


class TestGetQuarantineDir:
    """Tests for get_quarantine_dir function."""

    def test_returns_path(self):
        """Should return a Path object."""
        result = get_quarantine_dir()
        assert isinstance(result, Path)

    def test_directory_exists(self):
        """Should create directory if it doesn't exist."""
        result = get_quarantine_dir()
        assert result.exists()
        assert result.is_dir()

    def test_returns_correct_location(self):
        """Should return ~/.antivirus/quarantine."""
        result = get_quarantine_dir()
        assert result.name == "quarantine"
        assert result.parent.name == ".antivirus"


class TestGetLogPath:
    """Tests for get_log_path function."""

    def test_returns_path(self):
        """Should return a Path object."""
        result = get_log_path()
        assert isinstance(result, Path)

    def test_returns_correct_location(self):
        """Should return ~/.antivirus/quarantine_log.json."""
        result = get_log_path()
        assert result.name == "quarantine_log.json"
        assert result.parent.name == ".antivirus"


class TestLoadSaveLog:
    """Tests for load_log and save_log functions."""

    def test_load_empty_log(self, mock_quarantine_dir):
        """Should return empty list when no log exists."""
        result = load_log()
        assert result == []

    def test_save_and_load_log(self, mock_quarantine_dir):
        """Should save and load log entries."""
        entries = [
            {"id": "abc123", "original_path": "/path/file.txt", "threat_name": "Test"}
        ]
        save_log(entries)
        result = load_log()
        assert result == entries

    def test_load_preserves_data(self, mock_quarantine_dir):
        """Should preserve all entry data."""
        entries = [
            {
                "id": "abc123",
                "original_path": "/path/file.txt",
                "quarantine_name": "abc123_file.txt.quarantined",
                "threat_name": "TestThreat",
                "date": "2025-01-01T12:00:00"
            }
        ]
        save_log(entries)
        result = load_log()
        assert result[0]["id"] == "abc123"
        assert result[0]["threat_name"] == "TestThreat"


class TestQuarantineFile:
    """Tests for quarantine_file function."""

    def test_moves_file_to_quarantine(self, mock_quarantine_dir, sample_file):
        """Should move file to quarantine directory."""
        quarantine_dir, _ = mock_quarantine_dir
        entry = quarantine_file(sample_file, "TestThreat")

        # Original file should be gone
        assert not sample_file.exists()

        # File should be in quarantine
        quarantine_path = quarantine_dir / entry.quarantine_name
        assert quarantine_path.exists()

    def test_returns_quarantine_entry(self, mock_quarantine_dir, sample_file):
        """Should return a QuarantineEntry."""
        entry = quarantine_file(sample_file, "TestThreat")

        assert isinstance(entry, QuarantineEntry)
        assert len(entry.id) == 8
        assert entry.threat_name == "TestThreat"
        assert str(sample_file) in entry.original_path

    def test_creates_log_entry(self, mock_quarantine_dir, sample_file):
        """Should add entry to quarantine log."""
        entry = quarantine_file(sample_file, "TestThreat")

        log = load_log()
        assert len(log) == 1
        assert log[0]["id"] == entry.id

    def test_quarantine_name_format(self, mock_quarantine_dir, sample_file):
        """Quarantine name should have correct format."""
        entry = quarantine_file(sample_file, "TestThreat")

        assert entry.quarantine_name.endswith(".quarantined")
        assert sample_file.name in entry.quarantine_name
        assert entry.id in entry.quarantine_name

    def test_multiple_quarantines(self, mock_quarantine_dir, temp_dir):
        """Should handle multiple quarantined files."""
        file1 = temp_dir / "file1.txt"
        file2 = temp_dir / "file2.txt"
        file1.write_text("content1")
        file2.write_text("content2")

        entry1 = quarantine_file(file1, "Threat1")
        entry2 = quarantine_file(file2, "Threat2")

        log = load_log()
        assert len(log) == 2
        assert entry1.id != entry2.id


class TestListQuarantine:
    """Tests for list_quarantine function."""

    def test_empty_quarantine(self, mock_quarantine_dir):
        """Should return empty list when no files quarantined."""
        result = list_quarantine()
        assert result == []

    def test_lists_quarantined_files(self, mock_quarantine_dir, sample_file):
        """Should list all quarantined files."""
        entry = quarantine_file(sample_file, "TestThreat")

        result = list_quarantine()
        assert len(result) == 1
        assert result[0].id == entry.id
        assert result[0].threat_name == "TestThreat"

    def test_returns_quarantine_entries(self, mock_quarantine_dir, sample_file):
        """Should return QuarantineEntry objects."""
        quarantine_file(sample_file, "TestThreat")

        result = list_quarantine()
        assert isinstance(result[0], QuarantineEntry)


class TestRestoreFile:
    """Tests for restore_file function."""

    def test_restore_quarantined_file(self, mock_quarantine_dir, sample_file):
        """Should restore file to original location."""
        original_content = sample_file.read_text()
        entry = quarantine_file(sample_file, "TestThreat")

        restored_path = restore_file(entry.id)

        assert restored_path is not None
        assert restored_path.exists()
        assert restored_path.read_text() == original_content

    def test_removes_from_quarantine(self, mock_quarantine_dir, sample_file):
        """Should remove file from quarantine directory."""
        quarantine_dir, _ = mock_quarantine_dir
        entry = quarantine_file(sample_file, "TestThreat")
        quarantine_path = quarantine_dir / entry.quarantine_name

        restore_file(entry.id)

        assert not quarantine_path.exists()

    def test_removes_log_entry(self, mock_quarantine_dir, sample_file):
        """Should remove entry from quarantine log."""
        entry = quarantine_file(sample_file, "TestThreat")

        restore_file(entry.id)

        log = load_log()
        assert len(log) == 0

    def test_restore_nonexistent_id(self, mock_quarantine_dir):
        """Should return None for nonexistent entry ID."""
        result = restore_file("nonexistent")
        assert result is None

    def test_restore_creates_parent_dirs(self, mock_quarantine_dir, temp_dir):
        """Should create parent directories if they don't exist."""
        nested_dir = temp_dir / "nested" / "path"
        nested_dir.mkdir(parents=True)
        file_path = nested_dir / "file.txt"
        file_path.write_text("content")

        entry = quarantine_file(file_path, "TestThreat")

        # Remove parent directory
        nested_dir.rmdir()
        (temp_dir / "nested").rmdir()

        # Restore should recreate directories
        restored_path = restore_file(entry.id)
        assert restored_path is not None
        assert restored_path.exists()


class TestDeleteQuarantined:
    """Tests for delete_quarantined function."""

    def test_delete_quarantined_file(self, mock_quarantine_dir, sample_file):
        """Should permanently delete quarantined file."""
        quarantine_dir, _ = mock_quarantine_dir
        entry = quarantine_file(sample_file, "TestThreat")
        quarantine_path = quarantine_dir / entry.quarantine_name

        result = delete_quarantined(entry.id)

        assert result is True
        assert not quarantine_path.exists()

    def test_removes_log_entry(self, mock_quarantine_dir, sample_file):
        """Should remove entry from quarantine log."""
        entry = quarantine_file(sample_file, "TestThreat")

        delete_quarantined(entry.id)

        log = load_log()
        assert len(log) == 0

    def test_delete_nonexistent_id(self, mock_quarantine_dir):
        """Should return False for nonexistent entry ID."""
        result = delete_quarantined("nonexistent")
        assert result is False

    def test_delete_already_deleted_file(self, mock_quarantine_dir, sample_file):
        """Should handle case where file was manually deleted."""
        quarantine_dir, _ = mock_quarantine_dir
        entry = quarantine_file(sample_file, "TestThreat")

        # Manually delete the quarantined file
        quarantine_path = quarantine_dir / entry.quarantine_name
        quarantine_path.unlink()

        # Should still succeed and clean up log
        result = delete_quarantined(entry.id)
        assert result is True
        assert len(load_log()) == 0
