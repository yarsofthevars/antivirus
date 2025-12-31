"""Tests for signatures module."""

import json
import pytest
from pathlib import Path

from antivirus.signatures import (
    DEFAULT_SIGNATURES,
    get_db_path,
    load_signatures,
    save_signatures,
    add_signature,
    check_signature,
)


@pytest.fixture
def mock_signatures_path(temp_dir, monkeypatch):
    """Mock the signatures database path."""
    db_path = temp_dir / "signatures.json"

    from antivirus import signatures
    monkeypatch.setattr(signatures, "get_db_path", lambda: db_path)

    return db_path


class TestDefaultSignatures:
    """Tests for default signatures."""

    def test_contains_eicar(self):
        """Should contain EICAR test file signature."""
        assert len(DEFAULT_SIGNATURES) > 0
        assert "EICAR-Test-File" in DEFAULT_SIGNATURES.values()

    def test_eicar_hash_format(self):
        """EICAR hash should be valid SHA-256."""
        for hash_val in DEFAULT_SIGNATURES.keys():
            assert len(hash_val) == 64
            assert all(c in "0123456789abcdef" for c in hash_val)


class TestGetDbPath:
    """Tests for get_db_path function."""

    def test_returns_path(self):
        """Should return a Path object."""
        result = get_db_path()
        assert isinstance(result, Path)

    def test_returns_correct_location(self):
        """Should return ~/.antivirus/signatures.json."""
        result = get_db_path()
        assert result.name == "signatures.json"
        assert result.parent.name == ".antivirus"

    def test_creates_parent_directory(self):
        """Should create parent directory if needed."""
        result = get_db_path()
        assert result.parent.exists()


class TestLoadSignatures:
    """Tests for load_signatures function."""

    def test_creates_default_if_not_exists(self, mock_signatures_path):
        """Should create default signatures if file doesn't exist."""
        result = load_signatures()

        assert mock_signatures_path.exists()
        assert "EICAR-Test-File" in result.values()

    def test_loads_existing_file(self, mock_signatures_path):
        """Should load signatures from existing file."""
        custom_sigs = {"abc123": "CustomThreat"}
        mock_signatures_path.write_text(json.dumps(custom_sigs))

        result = load_signatures()

        assert result == custom_sigs

    def test_returns_dict(self, mock_signatures_path):
        """Should return a dictionary."""
        result = load_signatures()
        assert isinstance(result, dict)

    def test_preserves_all_entries(self, mock_signatures_path):
        """Should preserve all signature entries."""
        sigs = {
            "hash1": "Threat1",
            "hash2": "Threat2",
            "hash3": "Threat3",
        }
        mock_signatures_path.write_text(json.dumps(sigs))

        result = load_signatures()

        assert len(result) == 3
        assert result["hash1"] == "Threat1"
        assert result["hash2"] == "Threat2"
        assert result["hash3"] == "Threat3"


class TestSaveSignatures:
    """Tests for save_signatures function."""

    def test_creates_file(self, mock_signatures_path):
        """Should create signatures file."""
        save_signatures({"test": "value"})
        assert mock_signatures_path.exists()

    def test_saves_json(self, mock_signatures_path):
        """Should save valid JSON."""
        save_signatures({"hash": "threat"})

        content = json.loads(mock_signatures_path.read_text())
        assert content == {"hash": "threat"}

    def test_overwrites_existing(self, mock_signatures_path):
        """Should overwrite existing file."""
        save_signatures({"old": "data"})
        save_signatures({"new": "data"})

        content = json.loads(mock_signatures_path.read_text())
        assert content == {"new": "data"}

    def test_pretty_prints(self, mock_signatures_path):
        """Should format JSON with indentation."""
        save_signatures({"hash": "threat"})

        content = mock_signatures_path.read_text()
        assert "\n" in content  # Indented JSON has newlines


class TestAddSignature:
    """Tests for add_signature function."""

    def test_adds_new_signature(self, mock_signatures_path):
        """Should add a new signature."""
        add_signature("abc123def456", "NewThreat")

        sigs = load_signatures()
        assert "abc123def456" in sigs
        assert sigs["abc123def456"] == "NewThreat"

    def test_lowercases_hash(self, mock_signatures_path):
        """Should lowercase the hash value."""
        add_signature("ABC123DEF456", "NewThreat")

        sigs = load_signatures()
        assert "abc123def456" in sigs
        assert "ABC123DEF456" not in sigs

    def test_preserves_existing(self, mock_signatures_path):
        """Should preserve existing signatures."""
        add_signature("hash1", "Threat1")
        add_signature("hash2", "Threat2")

        sigs = load_signatures()
        assert "hash1" in sigs
        assert "hash2" in sigs

    def test_overwrites_duplicate_hash(self, mock_signatures_path):
        """Should overwrite signature with same hash."""
        add_signature("samehash", "OldName")
        add_signature("samehash", "NewName")

        sigs = load_signatures()
        assert sigs["samehash"] == "NewName"


class TestCheckSignature:
    """Tests for check_signature function."""

    def test_returns_threat_name_on_match(self, mock_signatures_path):
        """Should return threat name when hash matches."""
        add_signature("abc123", "TestThreat")

        result = check_signature("abc123")

        assert result == "TestThreat"

    def test_returns_none_on_no_match(self, mock_signatures_path):
        """Should return None when hash doesn't match."""
        result = check_signature("nonexistent")
        assert result is None

    def test_case_insensitive(self, mock_signatures_path):
        """Should match hashes case-insensitively."""
        add_signature("abc123", "TestThreat")

        assert check_signature("ABC123") == "TestThreat"
        assert check_signature("Abc123") == "TestThreat"

    def test_checks_eicar(self, mock_signatures_path):
        """Should detect EICAR test file hash."""
        # Force creation of default signatures
        load_signatures()

        eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        result = check_signature(eicar_hash)

        assert result == "EICAR-Test-File"


class TestSignaturesIntegration:
    """Integration tests for signatures module."""

    def test_full_workflow(self, mock_signatures_path):
        """Should support full add/check workflow."""
        # Initially no custom signatures
        result = check_signature("customhash123")
        assert result is None

        # Add signature
        add_signature("customhash123", "CustomMalware")

        # Now it should match
        result = check_signature("customhash123")
        assert result == "CustomMalware"

        # Verify persistence
        sigs = load_signatures()
        assert "customhash123" in sigs

    def test_multiple_signatures(self, mock_signatures_path):
        """Should handle multiple signatures."""
        hashes = [
            ("hash1", "Trojan.Gen"),
            ("hash2", "Worm.Win32"),
            ("hash3", "Adware.Generic"),
        ]

        for hash_val, name in hashes:
            add_signature(hash_val, name)

        for hash_val, name in hashes:
            assert check_signature(hash_val) == name
