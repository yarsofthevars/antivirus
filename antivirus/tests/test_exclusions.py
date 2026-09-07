"""Tests for the exclusions module."""

import pytest
from pathlib import Path

from antivirus.exclusions import (
    ExclusionType,
    ExclusionRule,
    ExclusionConfig,
    should_exclude,
    add_exclusion,
    remove_exclusion,
    load_exclusions,
    save_exclusions,
    clear_exclusions,
    get_exclusion_reason,
)


class TestExclusionConfig:
    """Tests for ExclusionConfig class."""

    def test_empty_config(self):
        """Empty config should have no rules."""
        config = ExclusionConfig()
        assert len(config.rules) == 0
        assert len(config.get_enabled_rules()) == 0

    def test_get_enabled_rules(self):
        """Should filter to enabled rules only."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern=".log", enabled=True),
            ExclusionRule(id="2", type=ExclusionType.EXTENSION, pattern=".tmp", enabled=False),
        ])
        enabled = config.get_enabled_rules()
        assert len(enabled) == 1
        assert enabled[0].pattern == ".log"

    def test_get_rules_by_type(self):
        """Should filter by rule type."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern=".log"),
            ExclusionRule(id="2", type=ExclusionType.PATH_PATTERN, pattern="*.tmp"),
            ExclusionRule(id="3", type=ExclusionType.EXTENSION, pattern=".cache"),
        ])
        ext_rules = config.get_rules_by_type(ExclusionType.EXTENSION)
        assert len(ext_rules) == 2

    def test_get_size_limits(self):
        """Should get min/max size limits."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.SIZE_MIN, pattern="100"),
            ExclusionRule(id="2", type=ExclusionType.SIZE_MAX, pattern="1000000"),
        ])
        assert config.get_size_min() == 100
        assert config.get_size_max() == 1000000


class TestShouldExclude:
    """Tests for should_exclude function."""

    def test_extension_exclusion(self, temp_dir):
        """Should exclude by extension."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern=".log"),
        ])
        log_file = temp_dir / "app.log"
        log_file.touch()
        txt_file = temp_dir / "readme.txt"
        txt_file.touch()

        assert should_exclude(log_file, config) is True
        assert should_exclude(txt_file, config) is False

    def test_extension_without_dot(self, temp_dir):
        """Should handle extension without leading dot."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern="log"),
        ])
        log_file = temp_dir / "app.log"
        log_file.touch()
        assert should_exclude(log_file, config) is True

    def test_path_pattern_simple(self, temp_dir):
        """Should exclude by simple glob pattern."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.PATH_PATTERN, pattern="*.tmp"),
        ])
        tmp_file = temp_dir / "cache.tmp"
        tmp_file.touch()
        txt_file = temp_dir / "data.txt"
        txt_file.touch()

        assert should_exclude(tmp_file, config) is True
        assert should_exclude(txt_file, config) is False

    def test_directory_exclusion(self, temp_dir):
        """Should exclude files in excluded directory."""
        subdir = temp_dir / "excluded"
        subdir.mkdir()
        file_in_dir = subdir / "file.txt"
        file_in_dir.touch()

        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.DIRECTORY, pattern=str(subdir)),
        ])

        assert should_exclude(file_in_dir, config) is True

    def test_size_max_exclusion(self, temp_dir):
        """Should exclude files larger than max size."""
        large_file = temp_dir / "large.bin"
        large_file.write_bytes(b"x" * 1000)
        small_file = temp_dir / "small.bin"
        small_file.write_bytes(b"x" * 10)

        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.SIZE_MAX, pattern="500"),
        ])

        assert should_exclude(large_file, config) is True
        assert should_exclude(small_file, config) is False

    def test_size_min_exclusion(self, temp_dir):
        """Should exclude files smaller than min size."""
        large_file = temp_dir / "large.bin"
        large_file.write_bytes(b"x" * 1000)
        small_file = temp_dir / "small.bin"
        small_file.write_bytes(b"x" * 10)

        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.SIZE_MIN, pattern="500"),
        ])

        assert should_exclude(large_file, config) is False
        assert should_exclude(small_file, config) is True

    def test_disabled_rule(self, temp_dir):
        """Disabled rules should not exclude."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern=".log", enabled=False),
        ])
        log_file = temp_dir / "app.log"
        log_file.touch()

        assert should_exclude(log_file, config) is False


class TestGetExclusionReason:
    """Tests for get_exclusion_reason function."""

    def test_returns_reason(self, temp_dir):
        """Should return reason for exclusion."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern=".log"),
        ])
        log_file = temp_dir / "app.log"
        log_file.touch()

        reason = get_exclusion_reason(log_file, config)
        assert reason is not None
        assert ".log" in reason

    def test_returns_none_for_included(self, temp_dir):
        """Should return None for non-excluded files."""
        config = ExclusionConfig(rules=[
            ExclusionRule(id="1", type=ExclusionType.EXTENSION, pattern=".log"),
        ])
        txt_file = temp_dir / "readme.txt"
        txt_file.touch()

        reason = get_exclusion_reason(txt_file, config)
        assert reason is None


class TestExclusionPersistence:
    """Tests for exclusion persistence."""

    def test_add_and_load(self, clean_config):
        """Should persist and load exclusions."""
        rule = add_exclusion(ExclusionType.EXTENSION, ".test", "Test rule")
        assert rule.id is not None

        loaded = load_exclusions()
        assert len(loaded.rules) >= 1
        assert any(r.pattern == ".test" for r in loaded.rules)

    def test_remove_exclusion(self, clean_config):
        """Should remove exclusion by ID."""
        rule = add_exclusion(ExclusionType.EXTENSION, ".test2")
        assert remove_exclusion(rule.id) is True
        assert remove_exclusion(rule.id) is False  # Already removed

    def test_clear_exclusions(self, clean_config):
        """Should clear all exclusions."""
        add_exclusion(ExclusionType.EXTENSION, ".a")
        add_exclusion(ExclusionType.EXTENSION, ".b")

        count = clear_exclusions()
        assert count >= 2

        loaded = load_exclusions()
        assert len(loaded.rules) == 0


class TestExclusionSerialization:
    """Tests for exclusion serialization."""

    def test_to_dict(self):
        """Should convert to dictionary."""
        rule = ExclusionRule(
            id="test123",
            type=ExclusionType.EXTENSION,
            pattern=".log",
            description="Log files",
            enabled=True,
        )
        d = rule.to_dict()
        assert d["id"] == "test123"
        assert d["type"] == "extension"
        assert d["pattern"] == ".log"

    def test_from_dict(self):
        """Should create from dictionary."""
        d = {
            "id": "test456",
            "type": "path_pattern",
            "pattern": "*.tmp",
            "enabled": False,
        }
        rule = ExclusionRule.from_dict(d)
        assert rule.id == "test456"
        assert rule.type == ExclusionType.PATH_PATTERN
        assert rule.enabled is False
