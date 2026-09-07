"""Unified configuration management for the antivirus."""

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class HeuristicsConfig:
    """Configuration for heuristic detection."""
    enabled: bool = True
    entropy_threshold: float = 7.5  # Bits (max 8.0)
    severity_threshold: str = "medium"  # low, medium, high, critical
    detect_shell_commands: bool = True
    detect_base64: bool = True
    detect_network_indicators: bool = True
    detect_obfuscation: bool = True


@dataclass
class SchedulerConfig:
    """Configuration for the scheduler daemon."""
    enabled: bool = False
    log_file: Optional[str] = None
    pid_file: Optional[str] = None


@dataclass
class ReportsConfig:
    """Configuration for report generation."""
    directory: str = "~/.antivirus/reports"
    auto_generate: bool = False
    default_format: str = "json"  # json or html
    retention_days: int = 30


@dataclass
class ScanConfig:
    """Configuration for scanning behavior."""
    default_recursive: bool = True
    default_auto_quarantine: bool = False
    default_heuristics: bool = False
    verbose: bool = False


@dataclass
class AntivirusConfig:
    """Master configuration for the antivirus."""
    version: str = "1.0"
    heuristics: HeuristicsConfig = field(default_factory=HeuristicsConfig)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    reports: ReportsConfig = field(default_factory=ReportsConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)


def get_config_dir() -> Path:
    """Get the path to the configuration directory."""
    config_dir = Path.home() / ".antivirus"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_config_path() -> Path:
    """Get the path to the configuration file."""
    return get_config_dir() / "config.json"


def _dataclass_to_dict(obj: Any) -> Any:
    """Recursively convert dataclass to dict."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _dataclass_to_dict(v) for k, v in asdict(obj).items()}
    return obj


def _dict_to_heuristics_config(data: Dict) -> HeuristicsConfig:
    """Convert dict to HeuristicsConfig."""
    return HeuristicsConfig(
        enabled=data.get("enabled", True),
        entropy_threshold=data.get("entropy_threshold", 7.5),
        severity_threshold=data.get("severity_threshold", "medium"),
        detect_shell_commands=data.get("detect_shell_commands", True),
        detect_base64=data.get("detect_base64", True),
        detect_network_indicators=data.get("detect_network_indicators", True),
        detect_obfuscation=data.get("detect_obfuscation", True),
    )


def _dict_to_scheduler_config(data: Dict) -> SchedulerConfig:
    """Convert dict to SchedulerConfig."""
    return SchedulerConfig(
        enabled=data.get("enabled", False),
        log_file=data.get("log_file"),
        pid_file=data.get("pid_file"),
    )


def _dict_to_reports_config(data: Dict) -> ReportsConfig:
    """Convert dict to ReportsConfig."""
    return ReportsConfig(
        directory=data.get("directory", "~/.antivirus/reports"),
        auto_generate=data.get("auto_generate", False),
        default_format=data.get("default_format", "json"),
        retention_days=data.get("retention_days", 30),
    )


def _dict_to_scan_config(data: Dict) -> ScanConfig:
    """Convert dict to ScanConfig."""
    return ScanConfig(
        default_recursive=data.get("default_recursive", True),
        default_auto_quarantine=data.get("default_auto_quarantine", False),
        default_heuristics=data.get("default_heuristics", False),
        verbose=data.get("verbose", False),
    )


def _dict_to_config(data: Dict) -> AntivirusConfig:
    """Convert dict to AntivirusConfig."""
    return AntivirusConfig(
        version=data.get("version", "1.0"),
        heuristics=_dict_to_heuristics_config(data.get("heuristics", {})),
        scheduler=_dict_to_scheduler_config(data.get("scheduler", {})),
        reports=_dict_to_reports_config(data.get("reports", {})),
        scan=_dict_to_scan_config(data.get("scan", {})),
    )


def load_config() -> AntivirusConfig:
    """Load configuration from file. Returns defaults if file doesn't exist."""
    config_path = get_config_path()

    if not config_path.exists():
        config = AntivirusConfig()
        save_config(config)
        return config

    try:
        with open(config_path, "r") as f:
            data = json.load(f)
        return _dict_to_config(data)
    except (json.JSONDecodeError, KeyError):
        # Return defaults if config is corrupted
        return AntivirusConfig()


def save_config(config: AntivirusConfig) -> None:
    """Save configuration to file."""
    config_path = get_config_path()

    with open(config_path, "w") as f:
        json.dump(_dataclass_to_dict(config), f, indent=2)


def get_config_value(key: str) -> Any:
    """Get a configuration value by dot-notation key (e.g., 'heuristics.enabled')."""
    config = load_config()
    parts = key.split(".")

    obj: Any = config
    for part in parts:
        if hasattr(obj, part):
            obj = getattr(obj, part)
        else:
            raise KeyError(f"Unknown configuration key: {key}")

    return obj


def set_config_value(key: str, value: Any) -> None:
    """Set a configuration value by dot-notation key."""
    config = load_config()
    parts = key.split(".")

    # Navigate to parent object
    obj: Any = config
    for part in parts[:-1]:
        if hasattr(obj, part):
            obj = getattr(obj, part)
        else:
            raise KeyError(f"Unknown configuration key: {key}")

    # Set the final attribute
    final_key = parts[-1]
    if not hasattr(obj, final_key):
        raise KeyError(f"Unknown configuration key: {key}")

    # Type coercion
    current_value = getattr(obj, final_key)
    if isinstance(current_value, bool):
        if isinstance(value, str):
            value = value.lower() in ("true", "1", "yes", "on")
    elif isinstance(current_value, int):
        value = int(value)
    elif isinstance(current_value, float):
        value = float(value)

    setattr(obj, final_key, value)
    save_config(config)


def reset_config() -> None:
    """Reset configuration to defaults."""
    config = AntivirusConfig()
    save_config(config)


def get_reports_dir() -> Path:
    """Get the path to the reports directory."""
    config = load_config()
    reports_dir = Path(config.reports.directory).expanduser()
    reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def get_scheduler_pid_file() -> Path:
    """Get the path to the scheduler PID file."""
    config = load_config()
    if config.scheduler.pid_file:
        return Path(config.scheduler.pid_file).expanduser()
    return get_config_dir() / "scheduler.pid"


def get_scheduler_log_file() -> Path:
    """Get the path to the scheduler log file."""
    config = load_config()
    if config.scheduler.log_file:
        return Path(config.scheduler.log_file).expanduser()
    return get_config_dir() / "scheduler.log"
