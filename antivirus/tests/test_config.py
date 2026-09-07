"""Tests for the config module."""

import pytest
from pathlib import Path

from antivirus.config import (
    AntivirusConfig,
    HeuristicsConfig,
    SchedulerConfig,
    ReportsConfig,
    ScanConfig,
    load_config,
    save_config,
    get_config_value,
    set_config_value,
    reset_config,
    get_config_path,
)


class TestAntivirusConfig:
    """Tests for AntivirusConfig dataclass."""

    def test_default_values(self):
        """Should have sensible defaults."""
        config = AntivirusConfig()
        assert config.version == "1.0"
        assert config.heuristics.enabled is True
        assert config.heuristics.entropy_threshold == 7.5
        assert config.scheduler.enabled is False
        assert config.scan.default_recursive is True

    def test_nested_config(self):
        """Should support nested configuration."""
        config = AntivirusConfig(
            heuristics=HeuristicsConfig(entropy_threshold=7.0),
        )
        assert config.heuristics.entropy_threshold == 7.0


class TestConfigPersistence:
    """Tests for config persistence."""

    def test_save_and_load(self, clean_config):
        """Should save and load config."""
        config = AntivirusConfig()
        config.heuristics.entropy_threshold = 6.5
        save_config(config)

        loaded = load_config()
        assert loaded.heuristics.entropy_threshold == 6.5

    def test_load_creates_default(self, clean_config):
        """Should create default config if none exists."""
        config = load_config()
        assert config is not None
        assert config.version == "1.0"

    def test_reset_config(self, clean_config):
        """Should reset to defaults."""
        config = load_config()
        config.heuristics.entropy_threshold = 5.0
        save_config(config)

        reset_config()

        loaded = load_config()
        assert loaded.heuristics.entropy_threshold == 7.5


class TestGetSetConfigValue:
    """Tests for get/set config value functions."""

    def test_get_simple_value(self, clean_config):
        """Should get simple config value."""
        value = get_config_value("version")
        assert value == "1.0"

    def test_get_nested_value(self, clean_config):
        """Should get nested config value."""
        value = get_config_value("heuristics.entropy_threshold")
        assert value == 7.5

    def test_get_invalid_key(self, clean_config):
        """Should raise error for invalid key."""
        with pytest.raises(KeyError):
            get_config_value("invalid.key")

    def test_set_value(self, clean_config):
        """Should set config value."""
        set_config_value("heuristics.entropy_threshold", 7.0)
        value = get_config_value("heuristics.entropy_threshold")
        assert value == 7.0

    def test_set_boolean_value(self, clean_config):
        """Should handle boolean string conversion."""
        set_config_value("heuristics.enabled", "false")
        value = get_config_value("heuristics.enabled")
        assert value is False

        set_config_value("heuristics.enabled", "true")
        value = get_config_value("heuristics.enabled")
        assert value is True

    def test_set_invalid_key(self, clean_config):
        """Should raise error for invalid key."""
        with pytest.raises(KeyError):
            set_config_value("invalid.key", "value")


class TestHeuristicsConfig:
    """Tests for HeuristicsConfig."""

    def test_defaults(self):
        """Should have correct defaults."""
        config = HeuristicsConfig()
        assert config.enabled is True
        assert config.entropy_threshold == 7.5
        assert config.severity_threshold == "medium"
        assert config.detect_shell_commands is True
        assert config.detect_base64 is True


class TestSchedulerConfig:
    """Tests for SchedulerConfig."""

    def test_defaults(self):
        """Should have correct defaults."""
        config = SchedulerConfig()
        assert config.enabled is False
        assert config.log_file is None
        assert config.pid_file is None


class TestReportsConfig:
    """Tests for ReportsConfig."""

    def test_defaults(self):
        """Should have correct defaults."""
        config = ReportsConfig()
        assert "reports" in config.directory
        assert config.auto_generate is False
        assert config.default_format == "json"
        assert config.retention_days == 30


class TestScanConfig:
    """Tests for ScanConfig."""

    def test_defaults(self):
        """Should have correct defaults."""
        config = ScanConfig()
        assert config.default_recursive is True
        assert config.default_auto_quarantine is False
        assert config.default_heuristics is False
        assert config.verbose is False
