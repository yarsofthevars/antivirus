"""Minimal cross-platform antivirus with signature-based, YARA, and heuristic detection."""

__version__ = "1.3.0"

from .scanner import ScanResult, scan_file, scan_directory, scan_path
from .signatures import add_signature, check_signature, load_signatures
from .quarantine import quarantine_file, restore_file, delete_quarantined, list_quarantine
from .yara_rules import YaraMatch, add_rule, add_rules_from_dir, list_rules, remove_rule
from .monitor import FileMonitor, ThreatHandler, monitor_paths
from .config import AntivirusConfig, load_config, save_config
from .exclusions import ExclusionRule, ExclusionConfig, load_exclusions, should_exclude
from .heuristics import HeuristicResult, HeuristicMatch, analyze_file, calculate_entropy
from .reports import ScanReport, generate_report, save_report, list_reports
from .scheduler import ScheduledTask, Scheduler, load_schedule, add_scheduled_task

# App module (macOS only, requires rumps)
try:
    from .app import AntivirusApp
except ImportError:
    AntivirusApp = None  # rumps not installed or not on macOS

__all__ = [
    # Version
    "__version__",
    # Scanner
    "ScanResult",
    "scan_file",
    "scan_directory",
    "scan_path",
    # Signatures
    "add_signature",
    "check_signature",
    "load_signatures",
    # Quarantine
    "quarantine_file",
    "restore_file",
    "delete_quarantined",
    "list_quarantine",
    # YARA
    "YaraMatch",
    "add_rule",
    "add_rules_from_dir",
    "list_rules",
    "remove_rule",
    # Monitor
    "FileMonitor",
    "ThreatHandler",
    "monitor_paths",
    # Config
    "AntivirusConfig",
    "load_config",
    "save_config",
    # Exclusions
    "ExclusionRule",
    "ExclusionConfig",
    "load_exclusions",
    "should_exclude",
    # Heuristics
    "HeuristicResult",
    "HeuristicMatch",
    "analyze_file",
    "calculate_entropy",
    # Reports
    "ScanReport",
    "generate_report",
    "save_report",
    "list_reports",
    # Scheduler
    "ScheduledTask",
    "Scheduler",
    "load_schedule",
    "add_scheduled_task",
    # App (macOS menu bar)
    "AntivirusApp",
]
