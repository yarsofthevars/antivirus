# Antivirus

A minimal cross-platform antivirus scanner with signature-based and YARA pattern detection.

## Features

- **SHA-256 Signature Detection** - Detect known malware by file hash
- **YARA Rules Support** - Pattern matching with custom YARA rules
- **Real-time Monitoring** - Watch directories for new threats
- **Quarantine Management** - Isolate, restore, or delete infected files
- **Cross-platform** - Works on Windows, macOS, and Linux

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd antivirus

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

### Requirements

- Python 3.7+
- watchdog >= 3.0.0
- yara-python >= 4.3.0

## Usage

### Scan Files

```bash
# Scan a file or directory
python -m antivirus scan /path/to/scan

# Scan with auto-quarantine
python -m antivirus scan /path/to/scan --quarantine

# Verbose output (show all files)
python -m antivirus scan /path/to/scan --verbose

# Non-recursive scan
python -m antivirus scan /path/to/scan --no-recursive
```

### Manage Signatures

```bash
# List all signatures
python -m antivirus list-signatures

# Add a new signature
python -m antivirus add-signature <sha256-hash> "Threat Name"
```

### Manage YARA Rules

```bash
# List loaded rules
python -m antivirus list-rules

# Add a YARA rule file
python -m antivirus add-rule /path/to/rule.yar

# Add all rules from a directory
python -m antivirus add-rules /path/to/rules/

# Remove a rule
python -m antivirus remove-rule rule.yar
```

### Quarantine Management

```bash
# List quarantined files
python -m antivirus list-quarantine

# Manually quarantine a file
python -m antivirus quarantine /path/to/file --threat "Threat Name"

# Restore a file from quarantine
python -m antivirus restore <quarantine-id>

# Permanently delete a quarantined file
python -m antivirus delete <quarantine-id>
```

### Real-time Monitoring

```bash
# Monitor directories for threats
python -m antivirus monitor /path/to/watch

# Monitor with auto-quarantine
python -m antivirus monitor /path/to/watch --quarantine

# Verbose monitoring
python -m antivirus monitor /path/to/watch --verbose

# Monitor multiple paths
python -m antivirus monitor /path1 /path2 /path3
```

## Configuration

All data is stored in `~/.antivirus/`:

```
~/.antivirus/
├── signatures.json      # SHA-256 signature database
├── quarantine_log.json  # Quarantine records
├── quarantine/          # Quarantined files
└── rules/               # YARA rule files
```

## Writing YARA Rules

Create `.yar` or `.yara` files with standard YARA syntax:

```yara
rule ExampleMalware : malware
{
    meta:
        description = "Detects example malware"
        author = "Your Name"

    strings:
        $suspicious = "malicious_pattern"
        $another = { 4D 5A 90 00 }

    condition:
        any of them
}
```

Add rules to the scanner:

```bash
python -m antivirus add-rule example.yar
```

## Development

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=antivirus --cov-report=term-missing

# Run specific test file
python -m pytest tests/test_scanner.py -v
```

### Project Structure

```
antivirus/
├── __init__.py      # Package initialization
├── __main__.py      # Entry point
├── cli.py           # Command-line interface
├── scanner.py       # Core scanning engine
├── signatures.py    # Hash signature management
├── yara_rules.py    # YARA rules management
├── quarantine.py    # Quarantine operations
└── monitor.py       # Real-time monitoring
```

## License

MIT License
