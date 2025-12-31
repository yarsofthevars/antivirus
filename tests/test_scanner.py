"""Tests for scanner module."""

import pytest
from pathlib import Path

from antivirus.scanner import (
    compute_hash,
    scan_file,
    scan_directory,
    scan_path,
    ScanResult,
)


@pytest.fixture
def mock_scanner_env(temp_dir, monkeypatch):
    """Mock environment for scanner tests."""
    # Mock signatures
    signatures_path = temp_dir / "signatures.json"
    from antivirus import signatures
    monkeypatch.setattr(signatures, "get_db_path", lambda: signatures_path)

    # Mock YARA rules
    rules_dir = temp_dir / "rules"
    rules_dir.mkdir()
    from antivirus import yara_rules
    monkeypatch.setattr(yara_rules, "get_rules_dir", lambda: rules_dir)

    return {"signatures_path": signatures_path, "rules_dir": rules_dir}


class TestComputeHash:
    """Tests for compute_hash function."""

    def test_returns_hex_string(self, temp_dir):
        """Should return a hexadecimal string."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test content")

        result = compute_hash(test_file)

        assert isinstance(result, str)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_consistent_hash(self, temp_dir):
        """Should return same hash for same content."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test content")

        hash1 = compute_hash(test_file)
        hash2 = compute_hash(test_file)

        assert hash1 == hash2

    def test_different_content_different_hash(self, temp_dir):
        """Should return different hash for different content."""
        file1 = temp_dir / "file1.txt"
        file2 = temp_dir / "file2.txt"
        file1.write_text("content 1")
        file2.write_text("content 2")

        hash1 = compute_hash(file1)
        hash2 = compute_hash(file2)

        assert hash1 != hash2

    def test_handles_binary_files(self, temp_dir):
        """Should hash binary files correctly."""
        binary_file = temp_dir / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\xfd")

        result = compute_hash(binary_file)

        assert isinstance(result, str)
        assert len(result) == 64

    def test_handles_empty_file(self, temp_dir):
        """Should hash empty files."""
        empty_file = temp_dir / "empty.txt"
        empty_file.write_text("")

        result = compute_hash(empty_file)

        # SHA-256 of empty string
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_handles_large_files(self, temp_dir):
        """Should handle large files efficiently."""
        large_file = temp_dir / "large.bin"
        # Create a 1MB file
        large_file.write_bytes(b"x" * (1024 * 1024))

        result = compute_hash(large_file)

        assert isinstance(result, str)
        assert len(result) == 64


class TestScanFile:
    """Tests for scan_file function."""

    def test_returns_scan_result(self, temp_dir, mock_scanner_env):
        """Should return a ScanResult."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("clean content")

        result = scan_file(test_file)

        assert isinstance(result, ScanResult)

    def test_clean_file_not_threat(self, temp_dir, mock_scanner_env):
        """Clean file should not be a threat."""
        test_file = temp_dir / "clean.txt"
        test_file.write_text("clean content")

        result = scan_file(test_file)

        assert result.is_threat is False
        assert result.threat_name is None
        assert result.error is None

    def test_scan_result_contains_path(self, temp_dir, mock_scanner_env):
        """ScanResult should contain file path."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("content")

        result = scan_file(test_file)

        assert result.path == test_file

    def test_detects_signature_match(self, temp_dir, mock_scanner_env):
        """Should detect files matching signatures."""
        from antivirus.signatures import add_signature

        # Create file and get its hash
        test_file = temp_dir / "malware.txt"
        test_file.write_text("malware content")
        file_hash = compute_hash(test_file)

        # Add signature
        add_signature(file_hash, "TestMalware")

        result = scan_file(test_file)

        assert result.is_threat is True
        assert result.threat_name == "TestMalware"

    def test_handles_not_a_file(self, temp_dir, mock_scanner_env):
        """Should handle non-file paths."""
        result = scan_file(temp_dir)  # Directory, not file

        assert result.is_threat is False
        assert result.error == "Not a file"

    def test_handles_permission_error(self, temp_dir, mock_scanner_env, monkeypatch):
        """Should handle permission errors gracefully."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("content")

        # Mock compute_hash to raise PermissionError
        def mock_hash(path):
            raise PermissionError("Access denied")

        from antivirus import scanner
        monkeypatch.setattr(scanner, "compute_hash", mock_hash)

        result = scan_file(test_file)

        assert result.is_threat is False
        assert result.error == "Permission denied"

    def test_handles_other_errors(self, temp_dir, mock_scanner_env, monkeypatch):
        """Should handle other exceptions gracefully."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("content")

        def mock_hash(path):
            raise IOError("Disk error")

        from antivirus import scanner
        monkeypatch.setattr(scanner, "compute_hash", mock_hash)

        result = scan_file(test_file)

        assert result.is_threat is False
        assert "Disk error" in result.error


class TestScanDirectory:
    """Tests for scan_directory function."""

    def test_scans_all_files(self, temp_dir, mock_scanner_env):
        """Should scan all files in directory."""
        (temp_dir / "file1.txt").write_text("content 1")
        (temp_dir / "file2.txt").write_text("content 2")
        (temp_dir / "file3.txt").write_text("content 3")

        results = scan_directory(temp_dir)

        assert len(results) == 3

    def test_recursive_by_default(self, temp_dir, mock_scanner_env):
        """Should scan subdirectories by default."""
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        (temp_dir / "file1.txt").write_text("content")
        (subdir / "file2.txt").write_text("content")

        results = scan_directory(temp_dir, recursive=True)

        assert len(results) == 2

    def test_non_recursive_option(self, temp_dir, mock_scanner_env):
        """Should skip subdirectories when non-recursive."""
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        (temp_dir / "file1.txt").write_text("content")
        (subdir / "file2.txt").write_text("content")

        results = scan_directory(temp_dir, recursive=False)

        assert len(results) == 1

    def test_handles_not_a_directory(self, temp_dir, mock_scanner_env):
        """Should handle non-directory paths."""
        test_file = temp_dir / "file.txt"
        test_file.write_text("content")

        results = scan_directory(test_file)

        assert len(results) == 1
        assert results[0].error == "Not a directory"

    def test_returns_list_of_scan_results(self, temp_dir, mock_scanner_env):
        """Should return list of ScanResult objects."""
        (temp_dir / "file.txt").write_text("content")

        results = scan_directory(temp_dir)

        assert isinstance(results, list)
        assert all(isinstance(r, ScanResult) for r in results)

    def test_skips_directories_in_results(self, temp_dir, mock_scanner_env):
        """Should only include files, not directories."""
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        (temp_dir / "file.txt").write_text("content")

        results = scan_directory(temp_dir, recursive=False)

        # Should only have the file, not the directory
        assert len(results) == 1
        assert results[0].path.is_file()


class TestScanPath:
    """Tests for scan_path function."""

    def test_scans_single_file(self, temp_dir, mock_scanner_env):
        """Should scan a single file."""
        test_file = temp_dir / "file.txt"
        test_file.write_text("content")

        results = scan_path(test_file)

        assert len(results) == 1
        assert results[0].path == test_file

    def test_scans_directory(self, temp_dir, mock_scanner_env):
        """Should scan a directory."""
        (temp_dir / "file1.txt").write_text("content")
        (temp_dir / "file2.txt").write_text("content")

        results = scan_path(temp_dir)

        assert len(results) == 2

    def test_handles_nonexistent_path(self, temp_dir, mock_scanner_env):
        """Should handle nonexistent paths."""
        results = scan_path(temp_dir / "nonexistent")

        assert len(results) == 1
        assert results[0].error == "Path does not exist"

    def test_passes_recursive_option(self, temp_dir, mock_scanner_env):
        """Should pass recursive option to scan_directory."""
        # Create a clean subdirectory for testing
        scan_dir = temp_dir / "scan_target"
        scan_dir.mkdir()
        subdir = scan_dir / "subdir"
        subdir.mkdir()
        (scan_dir / "file1.txt").write_text("content")
        (subdir / "file2.txt").write_text("content")

        results_recursive = scan_path(scan_dir, recursive=True)
        results_non_recursive = scan_path(scan_dir, recursive=False)

        assert len(results_recursive) == 2
        assert len(results_non_recursive) == 1


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_create_scan_result(self, temp_dir):
        """Should create ScanResult with all fields."""
        result = ScanResult(
            path=temp_dir / "file.txt",
            is_threat=True,
            threat_name="TestThreat",
            error=None
        )

        assert result.path == temp_dir / "file.txt"
        assert result.is_threat is True
        assert result.threat_name == "TestThreat"
        assert result.error is None

    def test_default_values(self, temp_dir):
        """Should have correct default values."""
        result = ScanResult(
            path=temp_dir / "file.txt",
            is_threat=False
        )

        assert result.threat_name is None
        assert result.yara_matches == []
        assert result.error is None

    def test_yara_matches_field(self, temp_dir):
        """Should support yara_matches field."""
        from antivirus.yara_rules import YaraMatch

        match = YaraMatch(rule_name="Test", rule_file="test.yar", tags=[])
        result = ScanResult(
            path=temp_dir / "file.txt",
            is_threat=True,
            yara_matches=[match]
        )

        assert len(result.yara_matches) == 1
        assert result.yara_matches[0].rule_name == "Test"
