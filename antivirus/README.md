# Antivirus

A minimal cross-platform antivirus scanner with signature-based detection, YARA pattern matching, and heuristic analysis.

## Features

- **SHA-256 Signature Detection** - Detect known malware by file hash
- **YARA Rules Support** - Pattern matching with custom YARA rules
- **Heuristic Detection** - Entropy analysis, suspicious patterns, file anomalies
- **Real-time Monitoring** - Watch directories for new threats
- **Quarantine Management** - Isolate, restore, or delete infected files
- **Scheduled Scans** - Built-in daemon scheduler with hourly/daily/weekly intervals
- **Exclusion Rules** - Skip paths, extensions, sizes, or directories
- **Reports** - Generate JSON and HTML scan reports
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

# Scan with heuristics enabled
python -m antivirus scan /path/to/scan --heuristics

# Heuristics-only scan (skip signatures/YARA)
python -m antivirus scan /path/to/scan --heuristics-only

# Custom entropy threshold (default 7.5)
python -m antivirus scan /path/to/scan --heuristics --entropy-threshold 7.0

# Generate report after scan
python -m antivirus scan /path/to/scan --report json
python -m antivirus scan /path/to/scan --report html

# Save report to specific file
python -m antivirus scan /path/to/scan --report json --report-file ./report.json

# Quiet mode (for cron jobs)
python -m antivirus scan /path/to/scan --quiet

# Write output to file
python -m antivirus scan /path/to/scan --output ./scan.log
```

### Heuristic Detection

Heuristics detect suspicious files through:

- **Entropy Analysis** - High entropy (>7.5) indicates packed/encrypted content
- **Suspicious Patterns** - Shell commands, base64, network indicators, obfuscation
- **File Anomalies** - Extension mismatches, embedded executables

### Exclusion Rules

```bash
# Add path pattern exclusion (glob syntax)
python -m antivirus exclude add --path "**/.git/**"
python -m antivirus exclude add --path "**/node_modules/**"

# Add extension exclusion
python -m antivirus exclude add --extension .log
python -m antivirus exclude add --extension .tmp

# Add size-based exclusions
python -m antivirus exclude add --size-max 104857600  # Skip files > 100MB
python -m antivirus exclude add --size-min 0          # Skip empty files

# Add directory exclusion
python -m antivirus exclude add --directory /path/to/skip

# List all exclusion rules
python -m antivirus exclude list

# Remove an exclusion rule
python -m antivirus exclude remove <rule-id>

# Enable/disable rules
python -m antivirus exclude enable <rule-id>
python -m antivirus exclude disable <rule-id>

# Clear all exclusion rules
python -m antivirus exclude clear
```

### Report Management

```bash
# List saved reports
python -m antivirus report list

# View a report
python -m antivirus report view <report-id>

# Delete a report
python -m antivirus report delete <report-id>
```

### Scheduled Scans

```bash
# Add a scheduled task
python -m antivirus schedule add --name "Daily Home Scan" --path /home --interval daily
python -m antivirus schedule add --name "Weekly Full Scan" --path / --interval weekly
python -m antivirus schedule add --name "Hourly Downloads" --path ~/Downloads --interval hourly

# Add with options
python -m antivirus schedule add --name "Safe Scan" --path /data \
    --interval daily --recursive --quarantine

# List scheduled tasks
python -m antivirus schedule list

# Remove a scheduled task
python -m antivirus schedule remove <task-id>

# Enable/disable tasks
python -m antivirus schedule enable <task-id>
python -m antivirus schedule disable <task-id>
```

### Daemon Management

```bash
# Start the scheduler daemon
python -m antivirus daemon start

# Check daemon status
python -m antivirus daemon status

# Stop the daemon
python -m antivirus daemon stop
```

### Configuration

```bash
# Show current configuration
python -m antivirus config show

# Set configuration values
python -m antivirus config set heuristics.enabled true
python -m antivirus config set heuristics.entropy_threshold 7.0
python -m antivirus config set reports.default_format html

# Reset to defaults
python -m antivirus config reset
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

# Monitor with heuristics
python -m antivirus monitor /path/to/watch --heuristics

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
├── config.json          # Configuration settings
├── signatures.json      # SHA-256 signature database
├── exclusions.json      # Exclusion rules
├── schedule.json        # Scheduled tasks
├── quarantine_log.json  # Quarantine records
├── quarantine/          # Quarantined files
├── reports/             # Saved scan reports
└── rules/               # YARA rule files
```

### Configuration Options

```json
{
  "version": "1.0",
  "heuristics": {
    "enabled": true,
    "entropy_threshold": 7.5,
    "severity_threshold": "medium",
    "detect_shell_commands": true,
    "detect_base64": true,
    "detect_network_indicators": true,
    "detect_obfuscation": true
  },
  "scheduler": {
    "enabled": false,
    "log_file": null,
    "pid_file": null
  },
  "reports": {
    "directory": "~/.antivirus/reports",
    "auto_generate": false,
    "default_format": "json",
    "retention_days": 30
  },
  "scan": {
    "default_recursive": true,
    "default_auto_quarantine": false,
    "default_heuristics": false,
    "verbose": false
  }
}
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
python -m pytest tests/test_heuristics.py -v
```

### Project Structure

```
antivirus/
├── __init__.py      # Package initialization (v1.2.0)
├── __main__.py      # Entry point
├── cli.py           # Command-line interface
├── scanner.py       # Core scanning engine
├── signatures.py    # Hash signature management
├── yara_rules.py    # YARA rules management
├── quarantine.py    # Quarantine operations
├── monitor.py       # Real-time monitoring
├── config.py        # Configuration management
├── exclusions.py    # Exclusion rule matching
├── heuristics.py    # Heuristic detection engine
├── reports.py       # JSON/HTML report generation
└── scheduler.py     # Background daemon scheduler
```

## License

MIT License
