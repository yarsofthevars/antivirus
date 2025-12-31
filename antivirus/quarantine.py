"""Quarantine management for isolating infected files."""

import json
import shutil
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class QuarantineEntry:
    """Record of a quarantined file."""
    id: str
    original_path: str
    quarantine_name: str
    threat_name: str
    date: str


def get_quarantine_dir() -> Path:
    """Get the quarantine directory path."""
    quarantine_dir = Path.home() / ".antivirus" / "quarantine"
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    return quarantine_dir


def get_log_path() -> Path:
    """Get the quarantine log file path."""
    config_dir = Path.home() / ".antivirus"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "quarantine_log.json"


def load_log() -> List[Dict]:
    """Load the quarantine log."""
    log_path = get_log_path()

    if not log_path.exists():
        return []

    with open(log_path, "r") as f:
        return json.load(f)


def save_log(entries: List[Dict]) -> None:
    """Save the quarantine log."""
    log_path = get_log_path()

    with open(log_path, "w") as f:
        json.dump(entries, f, indent=2)


def quarantine_file(file_path: Path, threat_name: str) -> QuarantineEntry:
    """Move a file to quarantine."""
    quarantine_dir = get_quarantine_dir()

    entry_id = str(uuid.uuid4())[:8]
    quarantine_name = f"{entry_id}_{file_path.name}.quarantined"
    quarantine_path = quarantine_dir / quarantine_name

    shutil.move(str(file_path), str(quarantine_path))

    entry = QuarantineEntry(
        id=entry_id,
        original_path=str(file_path.absolute()),
        quarantine_name=quarantine_name,
        threat_name=threat_name,
        date=datetime.now().isoformat()
    )

    log = load_log()
    log.append(asdict(entry))
    save_log(log)

    return entry


def list_quarantine() -> List[QuarantineEntry]:
    """List all quarantined files."""
    log = load_log()
    return [QuarantineEntry(**entry) for entry in log]


def restore_file(entry_id: str) -> Optional[Path]:
    """Restore a file from quarantine. Returns the restored path or None if not found."""
    log = load_log()
    quarantine_dir = get_quarantine_dir()

    for i, entry in enumerate(log):
        if entry["id"] == entry_id:
            quarantine_path = quarantine_dir / entry["quarantine_name"]
            original_path = Path(entry["original_path"])

            if not quarantine_path.exists():
                return None

            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantine_path), str(original_path))

            log.pop(i)
            save_log(log)

            return original_path

    return None


def delete_quarantined(entry_id: str) -> bool:
    """Permanently delete a quarantined file."""
    log = load_log()
    quarantine_dir = get_quarantine_dir()

    for i, entry in enumerate(log):
        if entry["id"] == entry_id:
            quarantine_path = quarantine_dir / entry["quarantine_name"]

            if quarantine_path.exists():
                quarantine_path.unlink()

            log.pop(i)
            save_log(log)
            return True

    return False
