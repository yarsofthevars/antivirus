"""File scanner for detecting malware using signature matching, YARA rules, and heuristics."""

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

from .signatures import check_signature
from .yara_rules import scan_with_yara, YaraMatch

if TYPE_CHECKING:
    from .heuristics import HeuristicResult
    from .exclusions import ExclusionConfig


@dataclass
class ScanResult:
    """Result of scanning a single file."""
    path: Path
    is_threat: bool
    threat_name: Optional[str] = None
    yara_matches: List[YaraMatch] = field(default_factory=list)
    heuristic_result: Optional["HeuristicResult"] = None
    scan_time: Optional[float] = None  # Duration in seconds
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "path": str(self.path),
            "is_threat": self.is_threat,
            "threat_name": self.threat_name,
            "yara_matches": [
                {"rule_name": m.rule_name, "rule_file": m.rule_file, "tags": m.tags}
                for m in self.yara_matches
            ],
            "heuristic_result": self.heuristic_result.to_dict() if self.heuristic_result else None,
            "scan_time": self.scan_time,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "error": self.error,
        }


def compute_hash(file_path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def scan_file(
    file_path: Path,
    use_heuristics: bool = False,
    heuristics_only: bool = False,
    entropy_threshold: Optional[float] = None,
    exclusion_config: Optional["ExclusionConfig"] = None,
) -> ScanResult:
    """
    Scan a single file for threats.

    Args:
        file_path: Path to the file to scan
        use_heuristics: Enable heuristic analysis in addition to signatures
        heuristics_only: Only perform heuristic analysis (skip signatures/YARA)
        entropy_threshold: Override default entropy threshold for heuristics
        exclusion_config: Exclusion rules to apply

    Returns:
        ScanResult with threat information
    """
    start_time = time.time()

    try:
        if not file_path.is_file():
            return ScanResult(path=file_path, is_threat=False, error="Not a file")

        # Check exclusions first (fast path)
        if exclusion_config is not None:
            from .exclusions import should_exclude, get_exclusion_reason
            if should_exclude(file_path, exclusion_config):
                reason = get_exclusion_reason(file_path, exclusion_config)
                return ScanResult(
                    path=file_path,
                    is_threat=False,
                    error=f"Excluded: {reason}",
                    scan_time=time.time() - start_time,
                )

        # Get file metadata
        try:
            file_size = file_path.stat().st_size
        except OSError:
            file_size = None

        threat_name: Optional[str] = None
        yara_matches: List[YaraMatch] = []
        file_hash: Optional[str] = None
        heuristic_result: Optional["HeuristicResult"] = None

        if not heuristics_only:
            # Check hash signature
            file_hash = compute_hash(file_path)
            threat_name = check_signature(file_hash)

            # Check YARA rules
            yara_matches = scan_with_yara(file_path)

        # Perform heuristic analysis if requested
        if use_heuristics or heuristics_only:
            from .heuristics import analyze_file
            heuristic_result = analyze_file(file_path, entropy_threshold=entropy_threshold)

        # Determine if threat
        is_threat = threat_name is not None or len(yara_matches) > 0

        # Check heuristics for threat status
        if heuristic_result and heuristic_result.is_suspicious:
            is_threat = True
            if threat_name is None:
                # Use heuristic finding as threat name
                if heuristic_result.matches:
                    threat_name = f"Heuristic:{heuristic_result.matches[0].name}"
                else:
                    threat_name = f"Heuristic:HighRisk(score={heuristic_result.risk_score:.0f})"

        # Build combined threat name if only YARA matched
        if is_threat and threat_name is None and yara_matches:
            threat_name = f"YARA:{yara_matches[0].rule_name}"

        scan_time = time.time() - start_time

        return ScanResult(
            path=file_path,
            is_threat=is_threat,
            threat_name=threat_name,
            yara_matches=yara_matches,
            heuristic_result=heuristic_result,
            scan_time=scan_time,
            file_size=file_size,
            file_hash=file_hash,
        )

    except PermissionError:
        return ScanResult(
            path=file_path,
            is_threat=False,
            error="Permission denied",
            scan_time=time.time() - start_time,
        )
    except Exception as e:
        return ScanResult(
            path=file_path,
            is_threat=False,
            error=str(e),
            scan_time=time.time() - start_time,
        )


def scan_directory(
    dir_path: Path,
    recursive: bool = True,
    use_heuristics: bool = False,
    heuristics_only: bool = False,
    entropy_threshold: Optional[float] = None,
    exclusion_config: Optional["ExclusionConfig"] = None,
) -> List[ScanResult]:
    """
    Scan all files in a directory.

    Args:
        dir_path: Directory to scan
        recursive: Scan subdirectories
        use_heuristics: Enable heuristic analysis
        heuristics_only: Only perform heuristic analysis
        entropy_threshold: Override default entropy threshold
        exclusion_config: Exclusion rules to apply

    Returns:
        List of ScanResult for each file
    """
    results = []

    if not dir_path.is_dir():
        return [ScanResult(path=dir_path, is_threat=False, error="Not a directory")]

    # Check if entire directory is excluded
    if exclusion_config is not None:
        from .exclusions import should_exclude
        if should_exclude(dir_path, exclusion_config):
            return []

    pattern = "**/*" if recursive else "*"

    for file_path in dir_path.glob(pattern):
        if file_path.is_file():
            results.append(scan_file(
                file_path,
                use_heuristics=use_heuristics,
                heuristics_only=heuristics_only,
                entropy_threshold=entropy_threshold,
                exclusion_config=exclusion_config,
            ))

    return results


def scan_path(
    path: Path,
    recursive: bool = True,
    use_heuristics: bool = False,
    heuristics_only: bool = False,
    entropy_threshold: Optional[float] = None,
    exclusion_config: Optional["ExclusionConfig"] = None,
) -> List[ScanResult]:
    """
    Scan a file or directory.

    Args:
        path: File or directory to scan
        recursive: For directories, scan subdirectories
        use_heuristics: Enable heuristic analysis
        heuristics_only: Only perform heuristic analysis
        entropy_threshold: Override default entropy threshold
        exclusion_config: Exclusion rules to apply

    Returns:
        List of ScanResult
    """
    if path.is_file():
        return [scan_file(
            path,
            use_heuristics=use_heuristics,
            heuristics_only=heuristics_only,
            entropy_threshold=entropy_threshold,
            exclusion_config=exclusion_config,
        )]
    elif path.is_dir():
        return scan_directory(
            path,
            recursive=recursive,
            use_heuristics=use_heuristics,
            heuristics_only=heuristics_only,
            entropy_threshold=entropy_threshold,
            exclusion_config=exclusion_config,
        )
    else:
        return [ScanResult(path=path, is_threat=False, error="Path does not exist")]
