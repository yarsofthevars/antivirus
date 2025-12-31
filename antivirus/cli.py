"""Command-line interface for the antivirus."""

import argparse
import sys
from pathlib import Path

from .scanner import scan_path
from .signatures import add_signature, load_signatures
from .quarantine import quarantine_file, list_quarantine, restore_file, delete_quarantined
from .monitor import monitor_paths
from .yara_rules import (
    add_rule as yara_add_rule,
    add_rules_from_dir,
    list_rules as yara_list_rules,
    remove_rule as yara_remove_rule,
    is_available as yara_is_available,
)


def cmd_scan(args):
    """Handle the scan command."""
    path = Path(args.path).resolve()
    print(f"Scanning: {path}")

    if not yara_is_available():
        print("  Note: YARA not installed. Install with: pip install yara-python\n")

    results = scan_path(path, recursive=not args.no_recursive)

    threats_found = 0
    files_scanned = 0

    for result in results:
        if result.error:
            if args.verbose:
                print(f"  [SKIP] {result.path}: {result.error}")
            continue

        files_scanned += 1

        if result.is_threat:
            threats_found += 1
            print(f"  [THREAT] {result.path}: {result.threat_name}")

            # Show YARA match details
            if result.yara_matches:
                for match in result.yara_matches:
                    tags = f" [{', '.join(match.tags)}]" if match.tags else ""
                    print(f"    YARA: {match.rule_name} ({match.rule_file}){tags}")

            if args.quarantine:
                entry = quarantine_file(result.path, result.threat_name)
                print(f"    -> Quarantined (ID: {entry.id})")
        elif args.verbose:
            print(f"  [OK] {result.path}")

    print(f"\nScan complete: {files_scanned} files scanned, {threats_found} threats found")

    return 1 if threats_found > 0 else 0


def cmd_quarantine(args):
    """Handle the quarantine command."""
    path = Path(args.path).resolve()

    if not path.exists():
        print(f"Error: File not found: {path}")
        return 1

    entry = quarantine_file(path, args.threat or "Manual-Quarantine")
    print(f"Quarantined: {path}")
    print(f"  ID: {entry.id}")
    print(f"  Threat: {entry.threat_name}")
    return 0


def cmd_list_quarantine(args):
    """Handle the list-quarantine command."""
    entries = list_quarantine()

    if not entries:
        print("Quarantine is empty")
        return 0

    print(f"Quarantined files ({len(entries)}):\n")

    for entry in entries:
        print(f"  ID: {entry.id}")
        print(f"  Original: {entry.original_path}")
        print(f"  Threat: {entry.threat_name}")
        print(f"  Date: {entry.date}")
        print()

    return 0


def cmd_restore(args):
    """Handle the restore command."""
    restored_path = restore_file(args.id)

    if restored_path:
        print(f"Restored: {restored_path}")
        return 0
    else:
        print(f"Error: Could not restore file with ID: {args.id}")
        return 1


def cmd_delete(args):
    """Handle the delete command."""
    if delete_quarantined(args.id):
        print(f"Deleted quarantined file: {args.id}")
        return 0
    else:
        print(f"Error: Could not find file with ID: {args.id}")
        return 1


def cmd_add_signature(args):
    """Handle the add-signature command."""
    add_signature(args.hash, args.name)
    print(f"Added signature: {args.name} ({args.hash})")
    return 0


def cmd_list_signatures(args):
    """Handle the list-signatures command."""
    signatures = load_signatures()

    print(f"Signatures ({len(signatures)}):\n")

    for hash_val, name in signatures.items():
        print(f"  {name}")
        print(f"    {hash_val}")
        print()

    return 0


def cmd_add_rule(args):
    """Handle the add-rule command."""
    path = Path(args.path).resolve()

    if not path.exists():
        print(f"Error: File not found: {path}")
        return 1

    if not yara_is_available():
        print("Error: YARA not installed. Install with: pip install yara-python")
        return 1

    if yara_add_rule(path):
        print(f"Added YARA rule: {path.name}")
        return 0
    else:
        print(f"Error: Failed to add rule. Check that it's a valid .yar/.yara file.")
        return 1


def cmd_add_rules(args):
    """Handle the add-rules command."""
    path = Path(args.path).resolve()

    if not path.exists():
        print(f"Error: Directory not found: {path}")
        return 1

    if not path.is_dir():
        print(f"Error: Not a directory: {path}")
        return 1

    if not yara_is_available():
        print("Error: YARA not installed. Install with: pip install yara-python")
        return 1

    added = add_rules_from_dir(path)

    if added:
        print(f"Added {len(added)} YARA rule(s):")
        for name in added:
            print(f"  {name}")
        return 0
    else:
        print("No valid YARA rules found in directory.")
        return 1


def cmd_list_rules(args):
    """Handle the list-rules command."""
    rules = yara_list_rules()

    if not rules:
        print("No YARA rules loaded.")
        if not yara_is_available():
            print("Note: YARA not installed. Install with: pip install yara-python")
        return 0

    print(f"YARA rules ({len(rules)}):\n")

    for rule in rules:
        print(f"  {rule['name']}")
        print(f"    Size: {rule['size']} bytes")
        print()

    return 0


def cmd_remove_rule(args):
    """Handle the remove-rule command."""
    if yara_remove_rule(args.name):
        print(f"Removed YARA rule: {args.name}")
        return 0
    else:
        print(f"Error: Rule not found: {args.name}")
        return 1


def cmd_monitor(args):
    """Handle the monitor command."""
    paths = [Path(p).resolve() for p in args.paths]

    for path in paths:
        if not path.exists():
            print(f"Error: Path not found: {path}")
            return 1

    monitor_paths(
        paths=paths,
        recursive=not args.no_recursive,
        auto_quarantine=args.quarantine,
        verbose=args.verbose,
    )
    return 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="antivirus",
        description="Minimal cross-platform antivirus"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan file or directory")
    scan_parser.add_argument("path", help="Path to scan")
    scan_parser.add_argument("-q", "--quarantine", action="store_true",
                            help="Automatically quarantine threats")
    scan_parser.add_argument("-v", "--verbose", action="store_true",
                            help="Show all scanned files")
    scan_parser.add_argument("--no-recursive", action="store_true",
                            help="Don't scan subdirectories")
    scan_parser.set_defaults(func=cmd_scan)

    # quarantine command
    quarantine_parser = subparsers.add_parser("quarantine", help="Quarantine a file")
    quarantine_parser.add_argument("path", help="Path to quarantine")
    quarantine_parser.add_argument("-t", "--threat", help="Threat name")
    quarantine_parser.set_defaults(func=cmd_quarantine)

    # list-quarantine command
    list_q_parser = subparsers.add_parser("list-quarantine", help="List quarantined files")
    list_q_parser.set_defaults(func=cmd_list_quarantine)

    # restore command
    restore_parser = subparsers.add_parser("restore", help="Restore file from quarantine")
    restore_parser.add_argument("id", help="Quarantine entry ID")
    restore_parser.set_defaults(func=cmd_restore)

    # delete command
    delete_parser = subparsers.add_parser("delete", help="Delete quarantined file")
    delete_parser.add_argument("id", help="Quarantine entry ID")
    delete_parser.set_defaults(func=cmd_delete)

    # add-signature command
    add_sig_parser = subparsers.add_parser("add-signature", help="Add malware signature")
    add_sig_parser.add_argument("hash", help="SHA-256 hash")
    add_sig_parser.add_argument("name", help="Threat name")
    add_sig_parser.set_defaults(func=cmd_add_signature)

    # list-signatures command
    list_sig_parser = subparsers.add_parser("list-signatures", help="List all signatures")
    list_sig_parser.set_defaults(func=cmd_list_signatures)

    # add-rule command
    add_rule_parser = subparsers.add_parser("add-rule", help="Add a YARA rule file")
    add_rule_parser.add_argument("path", help="Path to .yar/.yara file")
    add_rule_parser.set_defaults(func=cmd_add_rule)

    # add-rules command
    add_rules_parser = subparsers.add_parser("add-rules", help="Add YARA rules from directory")
    add_rules_parser.add_argument("path", help="Directory containing .yar/.yara files")
    add_rules_parser.set_defaults(func=cmd_add_rules)

    # list-rules command
    list_rules_parser = subparsers.add_parser("list-rules", help="List all YARA rules")
    list_rules_parser.set_defaults(func=cmd_list_rules)

    # remove-rule command
    remove_rule_parser = subparsers.add_parser("remove-rule", help="Remove a YARA rule")
    remove_rule_parser.add_argument("name", help="Rule file name")
    remove_rule_parser.set_defaults(func=cmd_remove_rule)

    # monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Real-time file monitoring")
    monitor_parser.add_argument("paths", nargs="+", help="Paths to monitor")
    monitor_parser.add_argument("-q", "--quarantine", action="store_true",
                               help="Automatically quarantine threats")
    monitor_parser.add_argument("-v", "--verbose", action="store_true",
                               help="Show all scanned files")
    monitor_parser.add_argument("--no-recursive", action="store_true",
                               help="Don't monitor subdirectories")
    monitor_parser.set_defaults(func=cmd_monitor)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
