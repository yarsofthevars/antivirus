"""Exclusion rules for skipping files during scans."""

import fnmatch
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional


class ExclusionType(Enum):
    """Types of exclusion rules."""
    PATH_PATTERN = "path_pattern"  # Glob patterns like *.log, **/.git/**
    EXTENSION = "extension"  # File extensions like .log, .tmp
    SIZE_MIN = "size_min"  # Skip files below this size (bytes)
    SIZE_MAX = "size_max"  # Skip files above this size (bytes)
    DIRECTORY = "directory"  # Skip entire directories


@dataclass
class ExclusionRule:
    """A single exclusion rule."""
    id: str
    type: ExclusionType
    pattern: str  # The pattern/value for matching
    description: Optional[str] = None
    enabled: bool = True
    created: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "type": self.type.value,
            "pattern": self.pattern,
            "description": self.description,
            "enabled": self.enabled,
            "created": self.created,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ExclusionRule":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            type=ExclusionType(data["type"]),
            pattern=data["pattern"],
            description=data.get("description"),
            enabled=data.get("enabled", True),
            created=data.get("created"),
        )


@dataclass
class ExclusionConfig:
    """Complete exclusion configuration."""
    rules: List[ExclusionRule] = field(default_factory=list)

    def get_enabled_rules(self) -> List[ExclusionRule]:
        """Get only enabled rules."""
        return [r for r in self.rules if r.enabled]

    def get_rules_by_type(self, rule_type: ExclusionType) -> List[ExclusionRule]:
        """Get enabled rules of a specific type."""
        return [r for r in self.rules if r.enabled and r.type == rule_type]

    def get_path_patterns(self) -> List[str]:
        """Get all enabled path patterns."""
        return [r.pattern for r in self.get_rules_by_type(ExclusionType.PATH_PATTERN)]

    def get_extensions(self) -> List[str]:
        """Get all enabled extensions."""
        return [r.pattern for r in self.get_rules_by_type(ExclusionType.EXTENSION)]

    def get_directories(self) -> List[str]:
        """Get all enabled directory exclusions."""
        return [r.pattern for r in self.get_rules_by_type(ExclusionType.DIRECTORY)]

    def get_size_min(self) -> Optional[int]:
        """Get minimum size exclusion (returns largest if multiple)."""
        rules = self.get_rules_by_type(ExclusionType.SIZE_MIN)
        if not rules:
            return None
        return max(int(r.pattern) for r in rules)

    def get_size_max(self) -> Optional[int]:
        """Get maximum size exclusion (returns smallest if multiple)."""
        rules = self.get_rules_by_type(ExclusionType.SIZE_MAX)
        if not rules:
            return None
        return min(int(r.pattern) for r in rules)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {"rules": [r.to_dict() for r in self.rules]}

    @classmethod
    def from_dict(cls, data: dict) -> "ExclusionConfig":
        """Create from dictionary."""
        rules = [ExclusionRule.from_dict(r) for r in data.get("rules", [])]
        return cls(rules=rules)


def get_exclusions_path() -> Path:
    """Get the path to the exclusions file."""
    config_dir = Path.home() / ".antivirus"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "exclusions.json"


def load_exclusions() -> ExclusionConfig:
    """Load exclusion rules from file."""
    path = get_exclusions_path()

    if not path.exists():
        config = ExclusionConfig()
        save_exclusions(config)
        return config

    try:
        with open(path, "r") as f:
            data = json.load(f)
        return ExclusionConfig.from_dict(data)
    except (json.JSONDecodeError, KeyError):
        return ExclusionConfig()


def save_exclusions(config: ExclusionConfig) -> None:
    """Save exclusion rules to file."""
    path = get_exclusions_path()

    with open(path, "w") as f:
        json.dump(config.to_dict(), f, indent=2)


def add_exclusion(
    rule_type: ExclusionType,
    pattern: str,
    description: Optional[str] = None,
) -> ExclusionRule:
    """Add a new exclusion rule."""
    config = load_exclusions()

    rule = ExclusionRule(
        id=str(uuid.uuid4())[:8],
        type=rule_type,
        pattern=pattern,
        description=description,
        enabled=True,
        created=datetime.now().isoformat(),
    )

    config.rules.append(rule)
    save_exclusions(config)
    return rule


def remove_exclusion(rule_id: str) -> bool:
    """Remove an exclusion rule by ID. Returns True if found and removed."""
    config = load_exclusions()
    original_count = len(config.rules)
    config.rules = [r for r in config.rules if r.id != rule_id]

    if len(config.rules) < original_count:
        save_exclusions(config)
        return True
    return False


def enable_exclusion(rule_id: str) -> bool:
    """Enable an exclusion rule. Returns True if found."""
    config = load_exclusions()

    for rule in config.rules:
        if rule.id == rule_id:
            rule.enabled = True
            save_exclusions(config)
            return True
    return False


def disable_exclusion(rule_id: str) -> bool:
    """Disable an exclusion rule. Returns True if found."""
    config = load_exclusions()

    for rule in config.rules:
        if rule.id == rule_id:
            rule.enabled = False
            save_exclusions(config)
            return True
    return False


def clear_exclusions() -> int:
    """Remove all exclusion rules. Returns count of rules removed."""
    config = load_exclusions()
    count = len(config.rules)
    config.rules = []
    save_exclusions(config)
    return count


def _match_glob_pattern(path: Path, pattern: str) -> bool:
    """Check if path matches a glob pattern."""
    path_str = str(path)

    # Handle ** patterns for recursive matching
    if "**" in pattern:
        # Convert ** glob to work with fnmatch
        # **/*.log matches any .log file in any subdirectory
        parts = pattern.split("**")
        if len(parts) == 2:
            prefix, suffix = parts
            prefix = prefix.rstrip("/\\")
            suffix = suffix.lstrip("/\\")

            # Check if the path contains the prefix somewhere
            if prefix:
                if prefix not in path_str:
                    return False
            # Check if the path ends with the suffix pattern
            if suffix:
                return fnmatch.fnmatch(path.name, suffix) or fnmatch.fnmatch(
                    path_str, f"*{suffix}"
                )
            return True

    # Standard glob matching
    return fnmatch.fnmatch(path_str, pattern) or fnmatch.fnmatch(path.name, pattern)


def _is_under_directory(path: Path, directory: str) -> bool:
    """Check if path is under a given directory."""
    try:
        dir_path = Path(directory).expanduser().resolve()
        file_path = path.resolve()
        return dir_path in file_path.parents or file_path == dir_path
    except (OSError, ValueError):
        return False


def should_exclude(file_path: Path, config: Optional[ExclusionConfig] = None) -> bool:
    """
    Check if a file should be excluded from scanning.

    Args:
        file_path: Path to the file to check
        config: ExclusionConfig to use. If None, loads from file.

    Returns:
        True if the file should be excluded, False otherwise.
    """
    if config is None:
        config = load_exclusions()

    # Check directory exclusions
    for directory in config.get_directories():
        if _is_under_directory(file_path, directory):
            return True

    # Check path patterns
    for pattern in config.get_path_patterns():
        if _match_glob_pattern(file_path, pattern):
            return True

    # Check extension exclusions
    extensions = config.get_extensions()
    if extensions:
        file_ext = file_path.suffix.lower()
        for ext in extensions:
            # Normalize extension (add dot if not present)
            normalized_ext = ext if ext.startswith(".") else f".{ext}"
            if file_ext == normalized_ext.lower():
                return True

    # Check size exclusions (requires file to exist)
    if file_path.exists() and file_path.is_file():
        try:
            file_size = file_path.stat().st_size

            size_min = config.get_size_min()
            if size_min is not None and file_size < size_min:
                return True

            size_max = config.get_size_max()
            if size_max is not None and file_size > size_max:
                return True
        except OSError:
            pass

    return False


def get_exclusion_reason(
    file_path: Path, config: Optional[ExclusionConfig] = None
) -> Optional[str]:
    """
    Get the reason why a file would be excluded.

    Returns None if file would not be excluded.
    """
    if config is None:
        config = load_exclusions()

    # Check directory exclusions
    for directory in config.get_directories():
        if _is_under_directory(file_path, directory):
            return f"Directory exclusion: {directory}"

    # Check path patterns
    for pattern in config.get_path_patterns():
        if _match_glob_pattern(file_path, pattern):
            return f"Path pattern: {pattern}"

    # Check extension exclusions
    extensions = config.get_extensions()
    if extensions:
        file_ext = file_path.suffix.lower()
        for ext in extensions:
            normalized_ext = ext if ext.startswith(".") else f".{ext}"
            if file_ext == normalized_ext.lower():
                return f"Extension: {ext}"

    # Check size exclusions
    if file_path.exists() and file_path.is_file():
        try:
            file_size = file_path.stat().st_size

            size_min = config.get_size_min()
            if size_min is not None and file_size < size_min:
                return f"File too small: {file_size} < {size_min} bytes"

            size_max = config.get_size_max()
            if size_max is not None and file_size > size_max:
                return f"File too large: {file_size} > {size_max} bytes"
        except OSError:
            pass

    return None
