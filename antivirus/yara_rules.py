"""YARA rules management for malware detection."""

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


@dataclass
class YaraMatch:
    """Result of a YARA rule match."""
    rule_name: str
    rule_file: str
    tags: List[str]


def get_rules_dir() -> Path:
    """Get the path to the YARA rules directory."""
    rules_dir = Path.home() / ".antivirus" / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    return rules_dir


def get_rule_files() -> List[Path]:
    """Get all YARA rule files in the rules directory."""
    rules_dir = get_rules_dir()
    files = []
    for pattern in ["*.yar", "*.yara"]:
        files.extend(rules_dir.glob(pattern))
    return sorted(files)


def load_rules() -> Optional[object]:
    """Compile and load all YARA rules. Returns compiled rules or None."""
    if not YARA_AVAILABLE:
        return None

    rule_files = get_rule_files()
    if not rule_files:
        return None

    # Build filepaths dict for yara.compile
    filepaths = {}
    for rule_file in rule_files:
        namespace = rule_file.stem
        filepaths[namespace] = str(rule_file)

    try:
        return yara.compile(filepaths=filepaths)
    except yara.Error:
        # If compilation fails, try compiling rules one by one
        valid_filepaths = {}
        for namespace, filepath in filepaths.items():
            try:
                yara.compile(filepath=filepath)
                valid_filepaths[namespace] = filepath
            except yara.Error:
                pass

        if valid_filepaths:
            return yara.compile(filepaths=valid_filepaths)
        return None


def add_rule(file_path: Path) -> bool:
    """Add a YARA rule file to the rules directory. Returns True on success."""
    file_path = Path(file_path).resolve()

    if not file_path.exists():
        return False

    if file_path.suffix.lower() not in [".yar", ".yara"]:
        return False

    # Validate the rule compiles
    if YARA_AVAILABLE:
        try:
            yara.compile(filepath=str(file_path))
        except yara.Error:
            return False

    dest = get_rules_dir() / file_path.name
    shutil.copy2(file_path, dest)
    return True


def add_rules_from_dir(dir_path: Path) -> List[str]:
    """Add all YARA rules from a directory. Returns list of added rule names."""
    dir_path = Path(dir_path).resolve()

    if not dir_path.is_dir():
        return []

    added = []
    for pattern in ["*.yar", "*.yara"]:
        for rule_file in dir_path.glob(pattern):
            if add_rule(rule_file):
                added.append(rule_file.name)

    return added


def list_rules() -> List[dict]:
    """List all YARA rule files with metadata."""
    rule_files = get_rule_files()
    rules = []

    for rule_file in rule_files:
        info = {
            "name": rule_file.name,
            "path": str(rule_file),
            "size": rule_file.stat().st_size,
        }
        rules.append(info)

    return rules


def remove_rule(rule_name: str) -> bool:
    """Remove a YARA rule file. Returns True on success."""
    rules_dir = get_rules_dir()

    # Try exact match first
    rule_path = rules_dir / rule_name
    if rule_path.exists():
        rule_path.unlink()
        return True

    # Try with extensions
    for ext in [".yar", ".yara"]:
        rule_path = rules_dir / (rule_name + ext)
        if rule_path.exists():
            rule_path.unlink()
            return True

    return False


def scan_with_yara(file_path: Path) -> List[YaraMatch]:
    """Scan a file with YARA rules. Returns list of matches."""
    if not YARA_AVAILABLE:
        return []

    rules = load_rules()
    if rules is None:
        return []

    file_path = Path(file_path).resolve()
    if not file_path.is_file():
        return []

    try:
        matches = rules.match(str(file_path))
        return [
            YaraMatch(
                rule_name=match.rule,
                rule_file=match.namespace,
                tags=list(match.tags) if match.tags else []
            )
            for match in matches
        ]
    except yara.Error:
        return []


def is_available() -> bool:
    """Check if YARA is available."""
    return YARA_AVAILABLE
