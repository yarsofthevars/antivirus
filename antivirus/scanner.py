"""File scanner for detecting malware using signature matching and YARA rules."""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .signatures import check_signature
from .yara_rules import scan_with_yara, YaraMatch


@dataclass
class ScanResult:
    """Result of scanning a single file."""
    path: Path
    is_threat: bool
    threat_name: Optional[str] = None
    yara_matches: List[YaraMatch] = field(default_factory=list)
    error: Optional[str] = None


def compute_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_file(file_path: Path) -> ScanResult:
    """Scan a single file for threats using hash signatures and YARA rules."""
    try:
        if not file_path.is_file():
            return ScanResult(path=file_path, is_threat=False, error="Not a file")

        # Check hash signature
        file_hash = compute_hash(file_path)
        threat_name = check_signature(file_hash)

        # Check YARA rules
        yara_matches = scan_with_yara(file_path)

        # Determine if threat (either hash match or YARA match)
        is_threat = threat_name is not None or len(yara_matches) > 0

        # Build combined threat name if needed
        if is_threat and threat_name is None and yara_matches:
            threat_name = f"YARA:{yara_matches[0].rule_name}"

        return ScanResult(
            path=file_path,
            is_threat=is_threat,
            threat_name=threat_name,
            yara_matches=yara_matches
        )
    except PermissionError:
        return ScanResult(path=file_path, is_threat=False, error="Permission denied")
    except Exception as e:
        return ScanResult(path=file_path, is_threat=False, error=str(e))


def scan_directory(dir_path: Path, recursive: bool = True) -> List[ScanResult]:
    """Scan all files in a directory."""
    results = []

    if not dir_path.is_dir():
        return [ScanResult(path=dir_path, is_threat=False, error="Not a directory")]

    pattern = "**/*" if recursive else "*"

    for file_path in dir_path.glob(pattern):
        if file_path.is_file():
            results.append(scan_file(file_path))

    return results


def scan_path(path: Path, recursive: bool = True) -> List[ScanResult]:
    """Scan a file or directory."""
    if path.is_file():
        return [scan_file(path)]
    elif path.is_dir():
        return scan_directory(path, recursive)
    else:
        return [ScanResult(path=path, is_threat=False, error="Path does not exist")]
