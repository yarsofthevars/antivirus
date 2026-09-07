"""Tests for the heuristics module."""

import pytest
from pathlib import Path

from antivirus.heuristics import (
    calculate_entropy,
    detect_file_type,
    check_extension_mismatch,
    find_embedded_executables,
    detect_suspicious_patterns,
    analyze_file,
    HeuristicType,
    Severity,
)


class TestCalculateEntropy:
    """Tests for entropy calculation."""

    def test_empty_data(self):
        """Empty data should have zero entropy."""
        assert calculate_entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        """Repeated single byte should have zero entropy."""
        assert calculate_entropy(b"AAAAAAAAAA") == 0.0

    def test_all_bytes(self):
        """All 256 byte values should have maximum entropy (8.0)."""
        data = bytes(range(256))
        entropy = calculate_entropy(data)
        assert 7.9 < entropy <= 8.0

    def test_text_file(self):
        """Normal text should have moderate entropy."""
        data = b"Hello, this is a normal text file with some content."
        entropy = calculate_entropy(data)
        assert 3.0 < entropy < 6.0

    def test_random_bytes(self, high_entropy_file):
        """Random bytes should have high entropy."""
        data = high_entropy_file.read_bytes()
        entropy = calculate_entropy(data)
        assert entropy > 7.0


class TestDetectFileType:
    """Tests for file type detection."""

    def test_pe_executable(self):
        """Should detect PE executable."""
        result = detect_file_type(b"MZ\x90\x00")
        assert result is not None
        assert result[0] == "PE"

    def test_elf_executable(self):
        """Should detect ELF executable."""
        result = detect_file_type(b"\x7fELF\x02\x01")
        assert result is not None
        assert result[0] == "ELF"

    def test_zip_archive(self):
        """Should detect ZIP archive."""
        result = detect_file_type(b"PK\x03\x04")
        assert result is not None
        assert result[0] == "ZIP"

    def test_pdf_document(self):
        """Should detect PDF document."""
        result = detect_file_type(b"%PDF-1.4")
        assert result is not None
        assert result[0] == "PDF"

    def test_unknown_type(self):
        """Unknown file type should return None."""
        result = detect_file_type(b"random data here")
        assert result is None


class TestCheckExtensionMismatch:
    """Tests for extension mismatch detection."""

    def test_txt_with_pe_content(self, temp_dir):
        """Should detect .txt file containing PE executable."""
        path = temp_dir / "document.txt"
        result = check_extension_mismatch(path, "PE")
        assert result is not None
        assert result.type == HeuristicType.EXTENSION_MISMATCH
        assert result.severity in [Severity.HIGH, Severity.CRITICAL]

    def test_exe_with_pe_content(self, temp_dir):
        """Should not flag .exe with PE content."""
        path = temp_dir / "program.exe"
        result = check_extension_mismatch(path, "PE")
        assert result is None

    def test_no_extension(self, temp_dir):
        """File without extension should not be flagged."""
        path = temp_dir / "noextension"
        result = check_extension_mismatch(path, "PE")
        assert result is None


class TestFindEmbeddedExecutables:
    """Tests for embedded executable detection."""

    def test_no_embedded(self):
        """Normal text should not have embedded executables."""
        data = b"This is just normal text content."
        matches = find_embedded_executables(data)
        assert len(matches) == 0

    def test_embedded_pe(self):
        """Should detect embedded PE executable."""
        data = b"Some header data" + b"\x00" * 100 + b"MZ\x90\x00" + b"\x00" * 50
        matches = find_embedded_executables(data)
        assert len(matches) == 1
        assert matches[0].type == HeuristicType.EMBEDDED_EXECUTABLE
        assert "PE" in matches[0].name

    def test_embedded_elf(self):
        """Should detect embedded ELF executable."""
        data = b"Some header data" + b"\x00" * 100 + b"\x7fELF" + b"\x00" * 50
        matches = find_embedded_executables(data)
        assert len(matches) == 1
        assert "ELF" in matches[0].name


class TestDetectSuspiciousPatterns:
    """Tests for suspicious pattern detection."""

    def test_shell_execution(self):
        """Should detect shell execution patterns."""
        data = b"os.system('rm -rf /')"
        matches = detect_suspicious_patterns(data)
        shell_matches = [m for m in matches if "shell" in m.name.lower()]
        assert len(shell_matches) > 0

    def test_base64_patterns(self):
        """Should detect base64 patterns."""
        data = b"import base64; base64.b64decode(data)"
        matches = detect_suspicious_patterns(data)
        b64_matches = [m for m in matches if "base64" in m.name.lower()]
        assert len(b64_matches) > 0

    def test_eval_function(self):
        """Should detect eval patterns."""
        data = b"eval(compile(code, '<string>', 'exec'))"
        matches = detect_suspicious_patterns(data)
        eval_matches = [m for m in matches if "eval" in m.name.lower() or "obfuscation" in m.name.lower()]
        assert len(eval_matches) > 0

    def test_ip_address(self):
        """Should detect IP addresses."""
        data = b"connect to 192.168.1.1:8080"
        matches = detect_suspicious_patterns(data)
        ip_matches = [m for m in matches if "ip" in m.name.lower() or "network" in m.name.lower()]
        assert len(ip_matches) > 0

    def test_clean_file(self):
        """Clean file should have no suspicious patterns."""
        data = b"def hello():\n    print('Hello, World!')\n"
        matches = detect_suspicious_patterns(data)
        # May have some low-confidence matches, but nothing critical
        critical = [m for m in matches if m.severity == Severity.CRITICAL]
        assert len(critical) == 0


class TestAnalyzeFile:
    """Tests for full file analysis."""

    def test_clean_file(self, sample_file):
        """Clean file should not be suspicious."""
        result = analyze_file(sample_file)
        assert result.is_suspicious is False
        assert result.risk_score < 25

    def test_malicious_file(self, malicious_file):
        """File with malicious patterns should be suspicious."""
        result = analyze_file(malicious_file)
        assert result.is_suspicious is True
        assert len(result.matches) > 0

    def test_high_entropy_file(self, high_entropy_file):
        """High entropy file should trigger alert."""
        result = analyze_file(high_entropy_file)
        assert result.entropy > 7.0
        entropy_matches = [m for m in result.matches if m.type == HeuristicType.ENTROPY]
        assert len(entropy_matches) > 0

    def test_nonexistent_file(self, temp_dir):
        """Nonexistent file should return error."""
        result = analyze_file(temp_dir / "nonexistent.txt")
        assert result.error is not None

    def test_custom_threshold(self, high_entropy_file):
        """Custom entropy threshold should be respected."""
        # With very high threshold, random file shouldn't trigger
        result = analyze_file(high_entropy_file, entropy_threshold=8.5)
        entropy_matches = [m for m in result.matches if m.type == HeuristicType.ENTROPY]
        assert len(entropy_matches) == 0
