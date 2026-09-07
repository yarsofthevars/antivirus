"""Heuristic detection for suspicious files."""

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import load_config


class HeuristicType(Enum):
    """Types of heuristic detections."""
    ENTROPY = "entropy"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    FILE_ANOMALY = "file_anomaly"
    EMBEDDED_EXECUTABLE = "embedded_executable"
    EXTENSION_MISMATCH = "extension_mismatch"


class Severity(Enum):
    """Severity levels for heuristic matches."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        """Get numeric weight for severity."""
        weights = {"low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0}
        return weights[self.value]


@dataclass
class HeuristicMatch:
    """Result of a single heuristic check."""
    type: HeuristicType
    name: str
    description: str
    severity: Severity
    confidence: float  # 0.0 to 1.0
    details: Optional[Dict] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "type": self.type.value,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "details": self.details,
        }


@dataclass
class HeuristicResult:
    """Aggregated heuristics result for a file."""
    path: Path
    entropy: float
    is_suspicious: bool
    risk_score: float  # 0.0 to 100.0
    matches: List[HeuristicMatch] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "path": str(self.path),
            "entropy": self.entropy,
            "is_suspicious": self.is_suspicious,
            "risk_score": self.risk_score,
            "matches": [m.to_dict() for m in self.matches],
            "error": self.error,
        }


# File magic signatures for detecting file types
FILE_SIGNATURES: Dict[bytes, Tuple[str, str]] = {
    b"MZ": ("PE", "Windows executable"),
    b"\x7fELF": ("ELF", "Linux executable"),
    b"\xca\xfe\xba\xbe": ("Mach-O", "macOS universal binary"),
    b"\xfe\xed\xfa\xce": ("Mach-O", "macOS 32-bit executable"),
    b"\xfe\xed\xfa\xcf": ("Mach-O", "macOS 64-bit executable"),
    b"\xcf\xfa\xed\xfe": ("Mach-O", "macOS 64-bit executable (little-endian)"),
    b"PK\x03\x04": ("ZIP", "ZIP archive"),
    b"PK\x05\x06": ("ZIP", "ZIP archive (empty)"),
    b"\x1f\x8b": ("GZIP", "GZIP compressed"),
    b"Rar!\x1a\x07": ("RAR", "RAR archive"),
    b"\x50\x4b\x03\x04": ("ZIP", "ZIP archive"),
    b"%PDF": ("PDF", "PDF document"),
    b"\xd0\xcf\x11\xe0": ("OLE", "Microsoft Office document"),
}

# Extensions that should match specific file types
EXTENSION_TYPE_MAP: Dict[str, List[str]] = {
    ".exe": ["PE"],
    ".dll": ["PE"],
    ".sys": ["PE"],
    ".elf": ["ELF"],
    ".so": ["ELF"],
    ".dylib": ["Mach-O"],
    ".app": ["Mach-O"],
    ".zip": ["ZIP"],
    ".jar": ["ZIP"],
    ".apk": ["ZIP"],
    ".gz": ["GZIP"],
    ".tgz": ["GZIP"],
    ".rar": ["RAR"],
    ".pdf": ["PDF"],
    ".doc": ["OLE"],
    ".xls": ["OLE"],
    ".ppt": ["OLE"],
}

# Suspicious patterns to detect
SUSPICIOUS_PATTERNS: Dict[str, List[Tuple[bytes, str, Severity]]] = {
    "shell_commands": [
        (rb"(?:system|exec|shell_exec|passthru|popen)\s*\(", "Shell execution function", Severity.HIGH),
        (rb"subprocess\.(call|run|Popen|check_output)", "Python subprocess call", Severity.MEDIUM),
        (rb"os\.system\s*\(", "Python os.system call", Severity.HIGH),
        (rb"os\.popen\s*\(", "Python os.popen call", Severity.HIGH),
        (rb"commands\.getoutput", "Python commands module", Severity.MEDIUM),
        (rb"\$\([^)]+\)", "Shell command substitution", Severity.LOW),
        (rb"`[^`]+`", "Shell backtick execution", Severity.MEDIUM),
    ],
    "base64_encoded": [
        (rb"base64[._]?(decode|b64decode)", "Base64 decode function", Severity.MEDIUM),
        (rb"atob\s*\(", "JavaScript atob decode", Severity.MEDIUM),
        (rb"btoa\s*\(", "JavaScript btoa encode", Severity.LOW),
        (rb"[A-Za-z0-9+/]{100,}={0,2}", "Long base64 string", Severity.MEDIUM),
    ],
    "network_indicators": [
        (rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
         "IP address", Severity.LOW),
        (rb"https?://[^\s\"'<>\]]+", "HTTP/HTTPS URL", Severity.LOW),
        (rb"ftp://[^\s\"'<>\]]+", "FTP URL", Severity.MEDIUM),
        (rb"socket\.(socket|connect|bind|listen)", "Socket operations", Severity.MEDIUM),
        (rb"requests\.(get|post|put|delete|patch)", "HTTP requests library", Severity.LOW),
        (rb"urllib\.(request|urlopen)", "Python urllib", Severity.LOW),
    ],
    "obfuscation": [
        (rb"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){10,}", "Hex escape sequence", Severity.HIGH),
        (rb"eval\s*\(", "Eval function", Severity.HIGH),
        (rb"exec\s*\(", "Exec function", Severity.HIGH),
        (rb"compile\s*\(", "Compile function", Severity.MEDIUM),
        (rb"__import__\s*\(", "Dynamic import", Severity.MEDIUM),
        (rb"getattr\s*\([^,]+,\s*['\"][^'\"]+['\"]\s*\)\s*\(", "Dynamic method call", Severity.MEDIUM),
        (rb"chr\s*\(\s*\d+\s*\)\s*(?:\+\s*chr\s*\(\s*\d+\s*\)){5,}", "Character concatenation", Severity.HIGH),
        (rb"String\.fromCharCode\s*\([^)]+\)", "JavaScript char code", Severity.MEDIUM),
    ],
    "crypto_mining": [
        (rb"stratum\+tcp://", "Mining pool connection", Severity.CRITICAL),
        (rb"coinhive", "CoinHive miner", Severity.CRITICAL),
        (rb"cryptonight", "CryptoNight algorithm", Severity.HIGH),
        (rb"monero|xmr", "Monero references", Severity.MEDIUM),
    ],
    "privilege_escalation": [
        (rb"sudo\s+", "Sudo command", Severity.MEDIUM),
        (rb"chmod\s+[0-7]*[4-7][0-7]{2}", "Setuid/setgid chmod", Severity.HIGH),
        (rb"setuid|setgid|seteuid|setegid", "Set UID/GID functions", Severity.HIGH),
        (rb"root:|:0:", "Root user reference in passwd format", Severity.MEDIUM),
    ],
    "data_exfiltration": [
        (rb"multipart/form-data", "Multipart form upload", Severity.LOW),
        (rb"POST.*password|password.*POST", "Password in POST", Severity.HIGH),
        (rb"(api[_-]?key|apikey|secret[_-]?key)", "API key reference", Severity.MEDIUM),
        (rb"credentials|passwd|shadow", "Credential file reference", Severity.MEDIUM),
    ],
}


def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.

    Args:
        data: Binary data to analyze

    Returns:
        Entropy value between 0.0 (uniform) and 8.0 (maximum randomness)
    """
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counter.values():
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)

    return entropy


def detect_file_type(data: bytes) -> Optional[Tuple[str, str]]:
    """
    Detect file type from magic bytes.

    Args:
        data: First few bytes of file

    Returns:
        Tuple of (type_code, description) or None if unknown
    """
    for signature, type_info in FILE_SIGNATURES.items():
        if data.startswith(signature):
            return type_info
    return None


def check_extension_mismatch(path: Path, detected_type: Optional[str]) -> Optional[HeuristicMatch]:
    """
    Check if file extension matches detected type.

    Args:
        path: File path
        detected_type: Detected file type code (e.g., "PE", "ELF")

    Returns:
        HeuristicMatch if mismatch detected, None otherwise
    """
    if detected_type is None:
        return None

    ext = path.suffix.lower()
    if not ext:
        return None

    expected_types = EXTENSION_TYPE_MAP.get(ext, [])

    # If extension has expected types and detected type doesn't match
    if expected_types and detected_type not in expected_types:
        # Check for suspicious mismatches (e.g., .txt file that's actually executable)
        if ext in [".txt", ".log", ".cfg", ".ini", ".csv", ".md", ".json", ".xml", ".html"]:
            if detected_type in ["PE", "ELF", "Mach-O"]:
                return HeuristicMatch(
                    type=HeuristicType.EXTENSION_MISMATCH,
                    name="ExecutableDisguisedAsText",
                    description=f"File with {ext} extension contains {detected_type} executable",
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    details={"extension": ext, "detected_type": detected_type},
                )

    # Check for executables with wrong extensions
    if detected_type in ["PE", "ELF", "Mach-O"]:
        if ext not in [".exe", ".dll", ".sys", ".elf", ".so", ".dylib", ".app", ".bin", ""]:
            return HeuristicMatch(
                type=HeuristicType.EXTENSION_MISMATCH,
                name="MismatchedExecutableExtension",
                description=f"Executable file ({detected_type}) has unexpected extension {ext}",
                severity=Severity.HIGH,
                confidence=0.85,
                details={"extension": ext, "detected_type": detected_type},
            )

    return None


def find_embedded_executables(data: bytes) -> List[HeuristicMatch]:
    """
    Find executable signatures embedded within file data.

    Args:
        data: File content

    Returns:
        List of HeuristicMatch for each embedded executable found
    """
    matches = []

    # Skip first 16 bytes to avoid matching the file's own header
    search_data = data[16:] if len(data) > 16 else b""

    for signature, (type_code, description) in FILE_SIGNATURES.items():
        if type_code in ["PE", "ELF", "Mach-O"]:
            offset = search_data.find(signature)
            if offset != -1:
                matches.append(HeuristicMatch(
                    type=HeuristicType.EMBEDDED_EXECUTABLE,
                    name=f"Embedded{type_code}",
                    description=f"Embedded {description} found at offset {offset + 16}",
                    severity=Severity.HIGH,
                    confidence=0.9,
                    details={"type": type_code, "offset": offset + 16},
                ))

    return matches


def detect_suspicious_patterns(data: bytes, config_enabled: Optional[Dict[str, bool]] = None) -> List[HeuristicMatch]:
    """
    Detect suspicious patterns in file content.

    Args:
        data: File content
        config_enabled: Dict of pattern categories to enable/disable

    Returns:
        List of HeuristicMatch for detected patterns
    """
    matches = []

    # Default to all enabled
    if config_enabled is None:
        config_enabled = {
            "shell_commands": True,
            "base64_encoded": True,
            "network_indicators": True,
            "obfuscation": True,
            "crypto_mining": True,
            "privilege_escalation": True,
            "data_exfiltration": True,
        }

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        if not config_enabled.get(category, True):
            continue

        for pattern, description, severity in patterns:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                found = regex.findall(data)
                if found:
                    # Limit matches to avoid huge results
                    match_count = min(len(found), 10)
                    sample = found[0][:50] if found else b""

                    matches.append(HeuristicMatch(
                        type=HeuristicType.SUSPICIOUS_PATTERN,
                        name=f"{category}:{description.replace(' ', '_')}",
                        description=f"{description} ({match_count} occurrence(s))",
                        severity=severity,
                        confidence=min(0.5 + (match_count * 0.1), 0.95),
                        details={
                            "category": category,
                            "count": match_count,
                            "sample": sample.decode("utf-8", errors="replace")[:50],
                        },
                    ))
            except re.error:
                continue

    return matches


def calculate_risk_score(entropy: float, matches: List[HeuristicMatch], entropy_threshold: float = 7.5) -> float:
    """
    Calculate overall risk score from entropy and matches.

    Args:
        entropy: File entropy
        matches: List of heuristic matches
        entropy_threshold: Threshold for high entropy

    Returns:
        Risk score from 0.0 to 100.0
    """
    score = 0.0

    # Entropy contribution (max 30 points)
    if entropy > entropy_threshold:
        entropy_excess = entropy - entropy_threshold
        score += min(entropy_excess * 60, 30)  # Up to 30 points for high entropy

    # Match contributions
    for match in matches:
        weight = match.severity.weight
        confidence = match.confidence
        contribution = weight * confidence * 10  # Up to 40 points per critical match
        score += contribution

    return min(score, 100.0)


def analyze_file(
    file_path: Path,
    entropy_threshold: Optional[float] = None,
    severity_threshold: Optional[str] = None,
) -> HeuristicResult:
    """
    Perform full heuristic analysis on a file.

    Args:
        file_path: Path to file to analyze
        entropy_threshold: Override config entropy threshold
        severity_threshold: Minimum severity to report (low, medium, high, critical)

    Returns:
        HeuristicResult with all findings
    """
    # Load config for defaults
    config = load_config()
    if entropy_threshold is None:
        entropy_threshold = config.heuristics.entropy_threshold
    if severity_threshold is None:
        severity_threshold = config.heuristics.severity_threshold

    # Map severity threshold to enum
    severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_severity_level = severity_levels.get(severity_threshold, 1)

    try:
        if not file_path.is_file():
            return HeuristicResult(
                path=file_path,
                entropy=0.0,
                is_suspicious=False,
                risk_score=0.0,
                error="Not a file",
            )

        # Read file content (limit to 10MB for analysis)
        max_size = 10 * 1024 * 1024
        file_size = file_path.stat().st_size

        with open(file_path, "rb") as f:
            data = f.read(max_size)

        # Calculate entropy
        entropy = calculate_entropy(data)

        # Collect all matches
        all_matches: List[HeuristicMatch] = []

        # Check for high entropy
        if entropy > entropy_threshold:
            all_matches.append(HeuristicMatch(
                type=HeuristicType.ENTROPY,
                name="HighEntropy",
                description=f"File has high entropy ({entropy:.2f}/8.0), possibly packed or encrypted",
                severity=Severity.MEDIUM if entropy < 7.8 else Severity.HIGH,
                confidence=min((entropy - entropy_threshold) / 0.5, 1.0),
                details={"entropy": entropy, "threshold": entropy_threshold},
            ))

        # Detect file type and check for extension mismatch
        detected_type = detect_file_type(data)
        if detected_type:
            mismatch = check_extension_mismatch(file_path, detected_type[0])
            if mismatch:
                all_matches.append(mismatch)

        # Find embedded executables
        embedded = find_embedded_executables(data)
        all_matches.extend(embedded)

        # Detect suspicious patterns
        pattern_config = {
            "shell_commands": config.heuristics.detect_shell_commands,
            "base64_encoded": config.heuristics.detect_base64,
            "network_indicators": config.heuristics.detect_network_indicators,
            "obfuscation": config.heuristics.detect_obfuscation,
        }
        patterns = detect_suspicious_patterns(data, pattern_config)
        all_matches.extend(patterns)

        # Filter by severity threshold
        filtered_matches = [
            m for m in all_matches
            if severity_levels.get(m.severity.value, 0) >= min_severity_level
        ]

        # Calculate risk score
        risk_score = calculate_risk_score(entropy, filtered_matches, entropy_threshold)

        # Determine if suspicious
        is_suspicious = risk_score >= 25.0 or any(
            m.severity in [Severity.HIGH, Severity.CRITICAL] for m in filtered_matches
        )

        return HeuristicResult(
            path=file_path,
            entropy=entropy,
            is_suspicious=is_suspicious,
            risk_score=risk_score,
            matches=filtered_matches,
        )

    except PermissionError:
        return HeuristicResult(
            path=file_path,
            entropy=0.0,
            is_suspicious=False,
            risk_score=0.0,
            error="Permission denied",
        )
    except Exception as e:
        return HeuristicResult(
            path=file_path,
            entropy=0.0,
            is_suspicious=False,
            risk_score=0.0,
            error=str(e),
        )
