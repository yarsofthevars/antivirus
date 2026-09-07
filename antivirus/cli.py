"""Command-line interface for the antivirus."""

import argparse
import sys
from datetime import datetime
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
    from .exclusions import load_exclusions
    from .reports import generate_report, save_report

    path = Path(args.path).resolve()

    # Handle quiet mode
    quiet = getattr(args, 'quiet', False)
    output_file = getattr(args, 'output', None)

    if not quiet:
        print(f"Scanning: {path}")

        if not yara_is_available():
            print("  Note: YARA not installed. Install with: pip install yara-python\n")

    # Load exclusions
    exclusion_config = load_exclusions()

    # Determine heuristics settings
    use_heuristics = getattr(args, 'heuristics', False) or getattr(args, 'heuristics_only', False)
    heuristics_only = getattr(args, 'heuristics_only', False)
    entropy_threshold = getattr(args, 'entropy_threshold', None)

    start_time = datetime.now()

    results = scan_path(
        path,
        recursive=not args.no_recursive,
        use_heuristics=use_heuristics,
        heuristics_only=heuristics_only,
        entropy_threshold=entropy_threshold,
        exclusion_config=exclusion_config,
    )

    threats_found = 0
    files_scanned = 0
    heuristic_alerts = 0
    quarantined_count = 0
    output_lines = []

    for result in results:
        if result.error:
            if args.verbose and not quiet:
                msg = f"  [SKIP] {result.path}: {result.error}"
                print(msg)
                output_lines.append(msg)
            continue

        files_scanned += 1

        # Track heuristic alerts
        if result.heuristic_result and result.heuristic_result.matches:
            heuristic_alerts += 1

        if result.is_threat:
            threats_found += 1
            msg = f"  [THREAT] {result.path}: {result.threat_name}"
            if not quiet:
                print(msg)
            output_lines.append(msg)

            # Show YARA match details
            if result.yara_matches:
                for match in result.yara_matches:
                    tags = f" [{', '.join(match.tags)}]" if match.tags else ""
                    detail = f"    YARA: {match.rule_name} ({match.rule_file}){tags}"
                    if not quiet:
                        print(detail)
                    output_lines.append(detail)

            # Show heuristic match details
            if result.heuristic_result and result.heuristic_result.matches:
                for match in result.heuristic_result.matches[:3]:
                    detail = f"    Heuristic: [{match.severity.value.upper()}] {match.name}"
                    if not quiet:
                        print(detail)
                    output_lines.append(detail)

            if args.quarantine:
                try:
                    entry = quarantine_file(result.path, result.threat_name)
                    quarantined_count += 1
                    q_msg = f"    -> Quarantined (ID: {entry.id})"
                    if not quiet:
                        print(q_msg)
                    output_lines.append(q_msg)
                except Exception as e:
                    if not quiet:
                        print(f"    -> Failed to quarantine: {e}")

        elif args.verbose and not quiet:
            print(f"  [OK] {result.path}")

    summary = f"\nScan complete: {files_scanned} files scanned, {threats_found} threats found"
    if heuristic_alerts > 0:
        summary += f", {heuristic_alerts} heuristic alerts"
    if quarantined_count > 0:
        summary += f", {quarantined_count} quarantined"

    if not quiet:
        print(summary)
    output_lines.append(summary)

    # Generate report if requested
    report_format = getattr(args, 'report', None)
    report_file = getattr(args, 'report_file', None)

    if report_format:
        report = generate_report(
            results=results,
            paths_scanned=[str(path)],
            scan_type="manual",
            start_time=start_time,
            exclusions_applied=[r.pattern for r in exclusion_config.get_enabled_rules()],
            quarantined_count=quarantined_count,
        )

        if report_file:
            report_path = save_report(report, format=report_format, output_path=Path(report_file))
        else:
            report_path = save_report(report, format=report_format)

        if not quiet:
            print(f"Report saved: {report_path}")

    # Write to output file if specified
    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(output_lines))

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

    use_heuristics = getattr(args, 'heuristics', False)
    entropy_threshold = getattr(args, 'entropy_threshold', None)

    monitor_paths(
        paths=paths,
        recursive=not args.no_recursive,
        auto_quarantine=args.quarantine,
        use_heuristics=use_heuristics,
        entropy_threshold=entropy_threshold,
        verbose=args.verbose,
    )
    return 0


# Exclusion commands

def cmd_exclude_add(args):
    """Handle the exclude add command."""
    from .exclusions import add_exclusion, ExclusionType

    if args.path_pattern:
        rule = add_exclusion(ExclusionType.PATH_PATTERN, args.path_pattern, args.description)
        print(f"Added path pattern exclusion: {args.path_pattern} (ID: {rule.id})")
    elif args.extension:
        ext = args.extension if args.extension.startswith('.') else f".{args.extension}"
        rule = add_exclusion(ExclusionType.EXTENSION, ext, args.description)
        print(f"Added extension exclusion: {ext} (ID: {rule.id})")
    elif args.size_max:
        rule = add_exclusion(ExclusionType.SIZE_MAX, str(args.size_max), args.description)
        print(f"Added size-max exclusion: {args.size_max} bytes (ID: {rule.id})")
    elif args.size_min:
        rule = add_exclusion(ExclusionType.SIZE_MIN, str(args.size_min), args.description)
        print(f"Added size-min exclusion: {args.size_min} bytes (ID: {rule.id})")
    elif args.directory:
        rule = add_exclusion(ExclusionType.DIRECTORY, args.directory, args.description)
        print(f"Added directory exclusion: {args.directory} (ID: {rule.id})")
    else:
        print("Error: Must specify one of --path, --extension, --size-max, --size-min, or --directory")
        return 1

    return 0


def cmd_exclude_list(args):
    """Handle the exclude list command."""
    from .exclusions import load_exclusions

    config = load_exclusions()

    if not config.rules:
        print("No exclusion rules defined")
        return 0

    print(f"Exclusion rules ({len(config.rules)}):\n")

    for rule in config.rules:
        status = "enabled" if rule.enabled else "disabled"
        desc = f" - {rule.description}" if rule.description else ""
        print(f"  [{rule.id}] {rule.type.value}: {rule.pattern} ({status}){desc}")

    return 0


def cmd_exclude_remove(args):
    """Handle the exclude remove command."""
    from .exclusions import remove_exclusion

    if remove_exclusion(args.id):
        print(f"Removed exclusion rule: {args.id}")
        return 0
    else:
        print(f"Error: Rule not found: {args.id}")
        return 1


def cmd_exclude_enable(args):
    """Handle the exclude enable command."""
    from .exclusions import enable_exclusion

    if enable_exclusion(args.id):
        print(f"Enabled exclusion rule: {args.id}")
        return 0
    else:
        print(f"Error: Rule not found: {args.id}")
        return 1


def cmd_exclude_disable(args):
    """Handle the exclude disable command."""
    from .exclusions import disable_exclusion

    if disable_exclusion(args.id):
        print(f"Disabled exclusion rule: {args.id}")
        return 0
    else:
        print(f"Error: Rule not found: {args.id}")
        return 1


def cmd_exclude_clear(args):
    """Handle the exclude clear command."""
    from .exclusions import clear_exclusions

    count = clear_exclusions()
    print(f"Cleared {count} exclusion rule(s)")
    return 0


# Report commands

def cmd_report_list(args):
    """Handle the report list command."""
    from .reports import list_reports

    reports = list_reports()

    if not reports:
        print("No reports found")
        return 0

    print(f"Reports ({len(reports)}):\n")

    for report in reports:
        threats = f"{report['threats']} threats" if report['threats'] >= 0 else "unknown"
        print(f"  [{report['id']}] {report['scan_type']} scan - {threats}")
        print(f"    Generated: {report['generated']}")
        print(f"    Format: {report['format']}")
        print()

    return 0


def cmd_report_view(args):
    """Handle the report view command."""
    from .reports import load_report, get_report_path

    report = load_report(args.id)

    if report:
        print(f"Report: {report.id}")
        print(f"Type: {report.scan_type}")
        print(f"Generated: {report.report_generated}")
        print(f"\nStatistics:")
        print(f"  Files scanned: {report.statistics.files_scanned}")
        print(f"  Threats found: {report.statistics.threats_found}")
        print(f"  Heuristic alerts: {report.statistics.heuristic_alerts}")
        print(f"  Duration: {report.statistics.scan_duration:.2f}s")

        if report.threats:
            print(f"\nThreats ({len(report.threats)}):")
            for threat in report.threats[:10]:  # Limit display
                print(f"  {threat['path']}: {threat['threat_name']}")

        return 0
    else:
        # Try to find HTML report
        html_path = get_report_path(args.id, "html")
        if html_path:
            print(f"HTML report found: {html_path}")
            print("Open in browser to view.")
            return 0

        print(f"Error: Report not found: {args.id}")
        return 1


def cmd_report_delete(args):
    """Handle the report delete command."""
    from .reports import delete_report

    if delete_report(args.id):
        print(f"Deleted report: {args.id}")
        return 0
    else:
        print(f"Error: Report not found: {args.id}")
        return 1


# Schedule commands

def cmd_schedule_add(args):
    """Handle the schedule add command."""
    from .scheduler import add_scheduled_task, ScheduleInterval

    interval_map = {
        'hourly': ScheduleInterval.HOURLY,
        'daily': ScheduleInterval.DAILY,
        'weekly': ScheduleInterval.WEEKLY,
        'custom': ScheduleInterval.CUSTOM,
    }

    interval = interval_map.get(args.interval, ScheduleInterval.DAILY)
    cron_expr = args.cron if args.interval == 'custom' else None

    task = add_scheduled_task(
        name=args.name,
        paths=args.paths,
        interval=interval,
        cron_expression=cron_expr,
        recursive=not getattr(args, 'no_recursive', False),
        auto_quarantine=getattr(args, 'quarantine', False),
        use_heuristics=getattr(args, 'heuristics', False),
    )

    print(f"Added scheduled task: {task.name} (ID: {task.id})")
    print(f"  Interval: {task.interval.value}")
    print(f"  Next run: {task.next_run}")
    return 0


def cmd_schedule_list(args):
    """Handle the schedule list command."""
    from .scheduler import load_schedule

    tasks = load_schedule()

    if not tasks:
        print("No scheduled tasks")
        return 0

    print(f"Scheduled tasks ({len(tasks)}):\n")

    for task in tasks:
        status = "enabled" if task.enabled else "disabled"
        print(f"  [{task.id}] {task.name} ({status})")
        print(f"    Paths: {', '.join(task.paths)}")
        print(f"    Interval: {task.interval.value}")
        print(f"    Next run: {task.next_run or 'N/A'}")
        print(f"    Last run: {task.last_run or 'Never'}")
        print()

    return 0


def cmd_schedule_remove(args):
    """Handle the schedule remove command."""
    from .scheduler import remove_scheduled_task

    if remove_scheduled_task(args.id):
        print(f"Removed scheduled task: {args.id}")
        return 0
    else:
        print(f"Error: Task not found: {args.id}")
        return 1


def cmd_schedule_enable(args):
    """Handle the schedule enable command."""
    from .scheduler import enable_scheduled_task

    if enable_scheduled_task(args.id):
        print(f"Enabled scheduled task: {args.id}")
        return 0
    else:
        print(f"Error: Task not found: {args.id}")
        return 1


def cmd_schedule_disable(args):
    """Handle the schedule disable command."""
    from .scheduler import disable_scheduled_task

    if disable_scheduled_task(args.id):
        print(f"Disabled scheduled task: {args.id}")
        return 0
    else:
        print(f"Error: Task not found: {args.id}")
        return 1


# Daemon commands

def cmd_daemon_start(args):
    """Handle the daemon start command."""
    from .scheduler import start_daemon, get_daemon_status

    status = get_daemon_status()
    if status["running"]:
        print(f"Daemon already running (PID: {status['pid']})")
        return 0

    if getattr(args, 'foreground', False):
        from .scheduler import run_daemon_foreground
        run_daemon_foreground()
    else:
        if start_daemon():
            print("Scheduler daemon started")
            return 0
        else:
            print("Error: Failed to start daemon")
            return 1

    return 0


def cmd_daemon_stop(args):
    """Handle the daemon stop command."""
    from .scheduler import stop_daemon

    if stop_daemon():
        print("Scheduler daemon stopped")
        return 0
    else:
        print("Daemon not running")
        return 0


def cmd_daemon_status(args):
    """Handle the daemon status command."""
    from .scheduler import get_daemon_status

    status = get_daemon_status()

    if status["running"]:
        print(f"Daemon: running (PID: {status['pid']})")
    else:
        print("Daemon: stopped")

    print(f"Tasks: {status['enabled_tasks']} enabled / {status['tasks_count']} total")
    print(f"PID file: {status['pid_file']}")
    print(f"Log file: {status['log_file']}")

    return 0


# Config commands

def cmd_config_show(args):
    """Handle the config show command."""
    from .config import load_config
    import json

    config = load_config()

    # Convert to dict and print
    from dataclasses import asdict
    print(json.dumps(asdict(config), indent=2))
    return 0


def cmd_config_set(args):
    """Handle the config set command."""
    from .config import set_config_value

    try:
        set_config_value(args.key, args.value)
        print(f"Set {args.key} = {args.value}")
        return 0
    except KeyError as e:
        print(f"Error: {e}")
        return 1


def cmd_config_reset(args):
    """Handle the config reset command."""
    from .config import reset_config

    reset_config()
    print("Configuration reset to defaults")
    return 0


def cmd_app(args):
    """Handle the app command (launch menu bar app)."""
    import sys
    if sys.platform != "darwin":
        print("Error: Menu bar app is only available on macOS")
        return 1

    try:
        from .app import main as app_main
        app_main()
        return 0
    except ImportError as e:
        print(f"Error: Could not import app module: {e}")
        print("Make sure rumps is installed: pip install rumps")
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="antivirus",
        description="Minimal cross-platform antivirus with heuristic detection"
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
    scan_parser.add_argument("--heuristics", action="store_true",
                            help="Enable heuristic detection")
    scan_parser.add_argument("--heuristics-only", action="store_true",
                            help="Only perform heuristic analysis (skip signatures)")
    scan_parser.add_argument("--entropy-threshold", type=float,
                            help="Entropy threshold for heuristics (default: 7.5)")
    scan_parser.add_argument("--report", choices=["json", "html"],
                            help="Generate report in specified format")
    scan_parser.add_argument("--report-file", help="Output path for report")
    scan_parser.add_argument("-Q", "--quiet", action="store_true",
                            help="Suppress output (for cron)")
    scan_parser.add_argument("--output", help="Write results to file")
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
    monitor_parser.add_argument("--heuristics", action="store_true",
                               help="Enable heuristic detection")
    monitor_parser.add_argument("--entropy-threshold", type=float,
                               help="Entropy threshold for heuristics")
    monitor_parser.set_defaults(func=cmd_monitor)

    # exclude command (with subcommands)
    exclude_parser = subparsers.add_parser("exclude", help="Manage exclusion rules")
    exclude_subparsers = exclude_parser.add_subparsers(dest="exclude_command", required=True)

    # exclude add
    exclude_add_parser = exclude_subparsers.add_parser("add", help="Add exclusion rule")
    exclude_add_group = exclude_add_parser.add_mutually_exclusive_group(required=True)
    exclude_add_group.add_argument("--path", dest="path_pattern", help="Path glob pattern")
    exclude_add_group.add_argument("--extension", help="File extension")
    exclude_add_group.add_argument("--size-max", type=int, help="Max file size (bytes)")
    exclude_add_group.add_argument("--size-min", type=int, help="Min file size (bytes)")
    exclude_add_group.add_argument("--directory", help="Directory to exclude")
    exclude_add_parser.add_argument("-d", "--description", help="Rule description")
    exclude_add_parser.set_defaults(func=cmd_exclude_add)

    # exclude list
    exclude_list_parser = exclude_subparsers.add_parser("list", help="List exclusion rules")
    exclude_list_parser.set_defaults(func=cmd_exclude_list)

    # exclude remove
    exclude_remove_parser = exclude_subparsers.add_parser("remove", help="Remove exclusion rule")
    exclude_remove_parser.add_argument("id", help="Rule ID")
    exclude_remove_parser.set_defaults(func=cmd_exclude_remove)

    # exclude enable
    exclude_enable_parser = exclude_subparsers.add_parser("enable", help="Enable exclusion rule")
    exclude_enable_parser.add_argument("id", help="Rule ID")
    exclude_enable_parser.set_defaults(func=cmd_exclude_enable)

    # exclude disable
    exclude_disable_parser = exclude_subparsers.add_parser("disable", help="Disable exclusion rule")
    exclude_disable_parser.add_argument("id", help="Rule ID")
    exclude_disable_parser.set_defaults(func=cmd_exclude_disable)

    # exclude clear
    exclude_clear_parser = exclude_subparsers.add_parser("clear", help="Clear all exclusion rules")
    exclude_clear_parser.set_defaults(func=cmd_exclude_clear)

    # report command (with subcommands)
    report_parser = subparsers.add_parser("report", help="Manage scan reports")
    report_subparsers = report_parser.add_subparsers(dest="report_command", required=True)

    # report list
    report_list_parser = report_subparsers.add_parser("list", help="List saved reports")
    report_list_parser.set_defaults(func=cmd_report_list)

    # report view
    report_view_parser = report_subparsers.add_parser("view", help="View a report")
    report_view_parser.add_argument("id", help="Report ID")
    report_view_parser.set_defaults(func=cmd_report_view)

    # report delete
    report_delete_parser = report_subparsers.add_parser("delete", help="Delete a report")
    report_delete_parser.add_argument("id", help="Report ID")
    report_delete_parser.set_defaults(func=cmd_report_delete)

    # schedule command (with subcommands)
    schedule_parser = subparsers.add_parser("schedule", help="Manage scheduled scans")
    schedule_subparsers = schedule_parser.add_subparsers(dest="schedule_command", required=True)

    # schedule add
    schedule_add_parser = schedule_subparsers.add_parser("add", help="Add scheduled scan")
    schedule_add_parser.add_argument("--name", required=True, help="Task name")
    schedule_add_parser.add_argument("--paths", nargs="+", required=True, help="Paths to scan")
    schedule_add_parser.add_argument("--interval", choices=["hourly", "daily", "weekly", "custom"],
                                    default="daily", help="Scan interval")
    schedule_add_parser.add_argument("--cron", help="Custom interval (HH:MM or seconds)")
    schedule_add_parser.add_argument("--no-recursive", action="store_true")
    schedule_add_parser.add_argument("-q", "--quarantine", action="store_true")
    schedule_add_parser.add_argument("--heuristics", action="store_true")
    schedule_add_parser.set_defaults(func=cmd_schedule_add)

    # schedule list
    schedule_list_parser = schedule_subparsers.add_parser("list", help="List scheduled tasks")
    schedule_list_parser.set_defaults(func=cmd_schedule_list)

    # schedule remove
    schedule_remove_parser = schedule_subparsers.add_parser("remove", help="Remove scheduled task")
    schedule_remove_parser.add_argument("id", help="Task ID")
    schedule_remove_parser.set_defaults(func=cmd_schedule_remove)

    # schedule enable
    schedule_enable_parser = schedule_subparsers.add_parser("enable", help="Enable scheduled task")
    schedule_enable_parser.add_argument("id", help="Task ID")
    schedule_enable_parser.set_defaults(func=cmd_schedule_enable)

    # schedule disable
    schedule_disable_parser = schedule_subparsers.add_parser("disable", help="Disable scheduled task")
    schedule_disable_parser.add_argument("id", help="Task ID")
    schedule_disable_parser.set_defaults(func=cmd_schedule_disable)

    # daemon command (with subcommands)
    daemon_parser = subparsers.add_parser("daemon", help="Manage scheduler daemon")
    daemon_subparsers = daemon_parser.add_subparsers(dest="daemon_command", required=True)

    # daemon start
    daemon_start_parser = daemon_subparsers.add_parser("start", help="Start scheduler daemon")
    daemon_start_parser.add_argument("--foreground", action="store_true",
                                    help="Run in foreground (blocking)")
    daemon_start_parser.set_defaults(func=cmd_daemon_start)

    # daemon stop
    daemon_stop_parser = daemon_subparsers.add_parser("stop", help="Stop scheduler daemon")
    daemon_stop_parser.set_defaults(func=cmd_daemon_stop)

    # daemon status
    daemon_status_parser = daemon_subparsers.add_parser("status", help="Check daemon status")
    daemon_status_parser.set_defaults(func=cmd_daemon_status)

    # config command (with subcommands)
    config_parser = subparsers.add_parser("config", help="Manage configuration")
    config_subparsers = config_parser.add_subparsers(dest="config_command", required=True)

    # config show
    config_show_parser = config_subparsers.add_parser("show", help="Show current configuration")
    config_show_parser.set_defaults(func=cmd_config_show)

    # config set
    config_set_parser = config_subparsers.add_parser("set", help="Set configuration value")
    config_set_parser.add_argument("key", help="Config key (e.g., heuristics.enabled)")
    config_set_parser.add_argument("value", help="Value to set")
    config_set_parser.set_defaults(func=cmd_config_set)

    # config reset
    config_reset_parser = config_subparsers.add_parser("reset", help="Reset configuration")
    config_reset_parser.set_defaults(func=cmd_config_reset)

    # app command (launch menu bar app)
    app_parser = subparsers.add_parser("app", help="Launch menu bar application (macOS)")
    app_parser.set_defaults(func=cmd_app)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
