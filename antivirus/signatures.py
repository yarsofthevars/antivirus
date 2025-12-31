"""Signature database for malware detection using SHA-256 hashes."""

import json
from pathlib import Path
from typing import Dict, Optional

DEFAULT_SIGNATURES = {
    # EICAR test file - standard antivirus test pattern
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}


def get_db_path() -> Path:
    """Get the path to the signature database file."""
    config_dir = Path.home() / ".antivirus"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "signatures.json"


def load_signatures() -> Dict[str, str]:
    """Load signatures from the database file."""
    db_path = get_db_path()

    if not db_path.exists():
        save_signatures(DEFAULT_SIGNATURES)
        return DEFAULT_SIGNATURES.copy()

    with open(db_path, "r") as f:
        return json.load(f)


def save_signatures(signatures: Dict[str, str]) -> None:
    """Save signatures to the database file."""
    db_path = get_db_path()

    with open(db_path, "w") as f:
        json.dump(signatures, f, indent=2)


def add_signature(hash_value: str, threat_name: str) -> None:
    """Add a new signature to the database."""
    signatures = load_signatures()
    signatures[hash_value.lower()] = threat_name
    save_signatures(signatures)


def check_signature(hash_value: str) -> Optional[str]:
    """Check if a hash matches a known threat. Returns threat name or None."""
    signatures = load_signatures()
    return signatures.get(hash_value.lower())
