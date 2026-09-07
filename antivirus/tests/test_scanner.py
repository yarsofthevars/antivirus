"""Tests for the scanner module."""

import pytest
from pathlib import Path

from antivirus.scanner import (
    compute_hash,
    scan_file,
    scan_directory,
    scan_path,
    ScanResult,
)
from antivirus.exclusions import ExclusionConfig, ExclusionRule, ExclusionType


class TestComputeHash:
    """Tests for hash computation."""

    def test_empty_file(self, temp_dir):
        """Empty file should have known hash."""
        empty_file = temp_dir / "empty.txt"
        empty_file.touch()
        hash_value = compute_hash(empty_file)
        # SHA-256 of empty string
        assert hash_value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_known_content(self, temp_dir):
        """File with known content should have expected hash."""
        file_path = temp_dir / "test.txt"
        file_path.write_text("hello")
        hash_value = compute_hash(file_path)
        # SHA-256 of "hello"
        assert hash_value == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

    def test_binary_file(self, temp_dir):
        """Binary file should be hashed correctly."""
        file_path = temp_dir / "binary.bin"
        file_path.write_bytes(bytes([0, 1, 2, 3, 4, 5]))
        hash_value = compute_hash(file_path)
        assert len(hash_value) == 64  # SHA-256 hex length


class TestScanFile:
    """Tests for single file scanning."""

    def test_clean_file(self, sample_file):
        """Clean file should not be a threat."""
        result = scan_file(sample_file)
        assert result.is_threat is False
        assert result.threat_name is None
        assert result.error is None

    def test_nonexistent_file(self, temp_dir):
        """Nonexistent file should return error."""
        result = scan_file(temp_dir / "nonexistent.txt")
        assert result.is_threat is False
        assert result.error is not None

    def test_directory_path(self, temp_dir):
        """Directory path should return error."""
        result = scan_file(temp_dir)
        assert result.is_threat is False
        assert "Not a file" in result.error

    def test_with_heuristics(self, malicious_file):
        """Should detect threats with heuristics enabled."""
        result = scan_file(malicious_file, use_heuristics=True)
        assert result.heuristic_result is not None
        assert len(result.heuristic_result.matches) > 0

    def test_heuristics_only(self, sample_file):
        """Heuristics-only mode should skip signatures."""
        result = scan_file(sample_file, heuristics_only=True)
        assert result.file_hash is None  # Hash not computed in heuristics-only mode

    def test_with_exclusion(self, sample_file):
        """Excluded file should be skipped."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern=".txt"),
        ])
        result = scan_file(sample_file, exclusion_config=config)
        assert result.error is not None
        assert "Excluded" in result.error

    def test_scan_time_recorded(self, sample_file):
        """Scan time should be recorded."""
        result = scan_file(sample_file)
        assert result.scan_time is not None
        assert result.scan_time >= 0

    def test_file_size_recorded(self, sample_file):
        """File size should be recorded."""
        result = scan_file(sample_file)
        assert result.file_size is not None
        assert result.file_size > 0


class TestScanDirectory:
    """Tests for directory scanning."""

    def test_empty_directory(self, temp_dir):
        """Empty directory should return no results."""
        results = scan_directory(temp_dir)
        assert len(results) == 0

    def test_directory_with_files(self, temp_dir):
        """Should scan all files in directory."""
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "file2.txt").write_text("content2")
        (temp_dir / "file3.txt").write_text("content3")

        results = scan_directory(temp_dir)
        assert len(results) == 3

    def test_recursive_scan(self, temp_dir):
        """Should scan subdirectories recursively."""
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        (temp_dir / "root.txt").write_text("root")
        (subdir / "sub.txt").write_text("sub")

        results = scan_directory(temp_dir, recursive=True)
        assert len(results) == 2

    def test_non_recursive_scan(self, temp_dir):
        """Should not scan subdirectories when recursive=False."""
        subdir = temp_dir / "subdir"
        subdir.mkdir()
        (temp_dir / "root.txt").write_text("root")
        (subdir / "sub.txt").write_text("sub")

        results = scan_directory(temp_dir, recursive=False)
        assert len(results) == 1

    def test_not_a_directory(self, sample_file):
        """Should return error for non-directory path."""
        results = scan_directory(sample_file)
        assert len(results) == 1
        assert results[0].error is not None

    def test_with_exclusions(self, temp_dir):
        """Should apply exclusions to all files."""
        (temp_dir / "keep.txt").write_text("keep")
        (temp_dir / "skip.log").write_text("skip")

        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern=".log"),
        ])

        results = scan_directory(temp_dir, exclusion_config=config)
        scanned = [r for r in results if r.error is None or "Excluded" not in r.error]
        assert len(scanned) == 1


class TestScanPath:
    """Tests for scan_path function."""

    def test_file_path(self, sample_file):
        """Should scan single file."""
        results = scan_path(sample_file)
        assert len(results) == 1

    def test_directory_path(self, temp_dir):
        """Should scan directory."""
        (temp_dir / "file.txt").write_text("content")
        results = scan_path(temp_dir)
        assert len(results) == 1

    def test_nonexistent_path(self, temp_dir):
        """Should return error for nonexistent path."""
        results = scan_path(temp_dir / "nonexistent")
        assert len(results) == 1
        assert results[0].error is not None


class TestScanResult:
    """Tests for ScanResult dataclass."""

    def test_to_dict(self, temp_dir):
        """Should serialize to dictionary."""
        result = ScanResult(
            path=temp_dir / "test.txt",
            is_threat=True,
            threat_name="Test.Malware",
            file_hash="abc123",
        )
        d = result.to_dict()
        assert d["is_threat"] is True
        assert d["threat_name"] == "Test.Malware"
        assert d["file_hash"] == "abc123"

    def test_to_dict_with_heuristics(self, malicious_file):
        """Should include heuristic result in dict."""
        result = scan_file(malicious_file, use_heuristics=True)
        d = result.to_dict()
        assert "heuristic_result" in d
