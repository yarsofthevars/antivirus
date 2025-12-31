"""Shared test fixtures for antivirus tests."""

import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_yara_rule(temp_dir):
    """Create a sample YARA rule file."""
    rule_content = '''rule TestRule : test
{
    meta:
        description = "Test rule for unit tests"

    strings:
        $test = "MALWARE_TEST_STRING"

    condition:
        $test
}
'''
    rule_path = temp_dir / "test_rule.yar"
    rule_path.write_text(rule_content)
    return rule_path


@pytest.fixture
def sample_yara_rules_dir(temp_dir):
    """Create a directory with multiple YARA rule files."""
    rules_dir = temp_dir / "rules"
    rules_dir.mkdir()

    rule1 = '''rule Rule1 : tag1
{
    strings:
        $a = "PATTERN_ONE"
    condition:
        $a
}
'''
    rule2 = '''rule Rule2 : tag2
{
    strings:
        $b = "PATTERN_TWO"
    condition:
        $b
}
'''
    (rules_dir / "rule1.yar").write_text(rule1)
    (rules_dir / "rule2.yara").write_text(rule2)

    return rules_dir


@pytest.fixture
def malicious_file(temp_dir):
    """Create a file that matches the test YARA rule."""
    file_path = temp_dir / "malicious.txt"
    file_path.write_text("This file contains MALWARE_TEST_STRING for testing.")
    return file_path


@pytest.fixture
def clean_file(temp_dir):
    """Create a file that doesn't match any rules."""
    file_path = temp_dir / "clean.txt"
    file_path.write_text("This is a clean file with no malicious patterns.")
    return file_path


@pytest.fixture
def invalid_yara_rule(temp_dir):
    """Create an invalid YARA rule file."""
    rule_path = temp_dir / "invalid.yar"
    rule_path.write_text("this is not valid yara syntax {{{")
    return rule_path


@pytest.fixture
def mock_rules_dir(temp_dir, monkeypatch):
    """Mock the YARA rules directory to use a temp directory."""
    rules_dir = temp_dir / "mock_rules"
    rules_dir.mkdir()

    def mock_get_rules_dir():
        return rules_dir

    from antivirus import yara_rules
    monkeypatch.setattr(yara_rules, "get_rules_dir", mock_get_rules_dir)

    return rules_dir
