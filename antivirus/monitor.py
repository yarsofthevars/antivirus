"""Real-time file system monitoring for threat detection."""

import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from .scanner import scan_file, ScanResult
from .quarantine import quarantine_file

if TYPE_CHECKING:
    from .exclusions import ExclusionConfig


class ThreatHandler(FileSystemEventHandler):
    """Handler for file system events that scans files for threats."""

    def __init__(
        self,
        auto_quarantine: bool = False,
        use_heuristics: bool = False,
        entropy_threshold: Optional[float] = None,
        exclusion_config: Optional["ExclusionConfig"] = None,
        on_threat: Optional[Callable[[Path, str, Optional[ScanResult]], None]] = None,
        on_scan: Optional[Callable[[Path], None]] = None,
        on_skip: Optional[Callable[[Path, str], None]] = None,
    ):
        self.auto_quarantine = auto_quarantine
        self.use_heuristics = use_heuristics
        self.entropy_threshold = entropy_threshold
        self.exclusion_config = exclusion_config
        self.on_threat = on_threat
        self.on_scan = on_scan
        self.on_skip = on_skip

    def _scan_file(self, path: Path) -> None:
        """Scan a file and handle threats."""
        if not path.is_file():
            return

        # Check exclusions before scanning
        if self.exclusion_config is not None:
            from .exclusions import should_exclude, get_exclusion_reason
            if should_exclude(path, self.exclusion_config):
                if self.on_skip:
                    reason = get_exclusion_reason(path, self.exclusion_config)
                    self.on_skip(path, reason or "Excluded")
                return

        if self.on_scan:
            self.on_scan(path)

        result = scan_file(
            path,
            use_heuristics=self.use_heuristics,
            entropy_threshold=self.entropy_threshold,
            exclusion_config=self.exclusion_config,
        )

        if result.is_threat and result.threat_name:
            if self.on_threat:
                self.on_threat(path, result.threat_name, result)

            if self.auto_quarantine:
                try:
                    quarantine_file(path, result.threat_name)
                except Exception:
                    pass

    def on_created(self, event: FileSystemEvent) -> None:
        """Handle file creation events."""
        if not event.is_directory:
            self._scan_file(Path(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events."""
        if not event.is_directory:
            self._scan_file(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        """Handle file move events."""
        if not event.is_directory and hasattr(event, 'dest_path'):
            self._scan_file(Path(event.dest_path))


class FileMonitor:
    """Real-time file system monitor."""

    def __init__(
        self,
        paths: list,
        recursive: bool = True,
        auto_quarantine: bool = False,
        use_heuristics: bool = False,
        entropy_threshold: Optional[float] = None,
        exclusion_config: Optional["ExclusionConfig"] = None,
        on_threat: Optional[Callable[[Path, str, Optional[ScanResult]], None]] = None,
        on_scan: Optional[Callable[[Path], None]] = None,
        on_skip: Optional[Callable[[Path, str], None]] = None,
    ):
        self.paths = [Path(p).resolve() for p in paths]
        self.recursive = recursive
        self.observer = Observer()
        self.handler = ThreatHandler(
            auto_quarantine=auto_quarantine,
            use_heuristics=use_heuristics,
            entropy_threshold=entropy_threshold,
            exclusion_config=exclusion_config,
            on_threat=on_threat,
            on_scan=on_scan,
            on_skip=on_skip,
        )

    def start(self) -> None:
        """Start monitoring."""
        for path in self.paths:
            if path.exists():
                self.observer.schedule(
                    self.handler,
                    str(path),
                    recursive=self.recursive
                )

        self.observer.start()

    def stop(self) -> None:
        """Stop monitoring."""
        self.observer.stop()
        self.observer.join()

    def is_running(self) -> bool:
        """Check if monitor is running."""
        return self.observer.is_alive()


def monitor_paths(
    paths: list,
    recursive: bool = True,
    auto_quarantine: bool = False,
    use_heuristics: bool = False,
    entropy_threshold: Optional[float] = None,
    use_exclusions: bool = True,
    verbose: bool = False,
) -> None:
    """
    Monitor paths for threats. Blocks until interrupted.

    Args:
        paths: List of paths to monitor
        recursive: Monitor subdirectories
        auto_quarantine: Automatically quarantine threats
        use_heuristics: Enable heuristic detection
        entropy_threshold: Custom entropy threshold for heuristics
        use_exclusions: Apply exclusion rules
        verbose: Show all scan events
    """
    from datetime import datetime

    # Load exclusions if enabled
    exclusion_config = None
    if use_exclusions:
        from .exclusions import load_exclusions
        exclusion_config = load_exclusions()

    def on_threat(path: Path, threat_name: str, result: Optional[ScanResult]) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        action = "Quarantined" if auto_quarantine else "Detected"
        print(f"[{timestamp}] [THREAT] {path}: {threat_name} ({action})")

        # Show heuristic details if available
        if result and result.heuristic_result and result.heuristic_result.matches:
            for match in result.heuristic_result.matches[:3]:  # Limit to 3
                print(f"           [{match.severity.value.upper()}] {match.name}: {match.description}")

    def on_scan(path: Path) -> None:
        if verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [SCAN] {path}")

    def on_skip(path: Path, reason: str) -> None:
        if verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [SKIP] {path}: {reason}")

    monitor = FileMonitor(
        paths=paths,
        recursive=recursive,
        auto_quarantine=auto_quarantine,
        use_heuristics=use_heuristics,
        entropy_threshold=entropy_threshold,
        exclusion_config=exclusion_config,
        on_threat=on_threat,
        on_scan=on_scan,
        on_skip=on_skip if verbose else None,
    )

    mode_info = []
    if use_heuristics:
        mode_info.append("heuristics enabled")
    if auto_quarantine:
        mode_info.append("auto-quarantine")
    if exclusion_config and exclusion_config.rules:
        mode_info.append(f"{len(exclusion_config.get_enabled_rules())} exclusion rules")

    mode_str = f" ({', '.join(mode_info)})" if mode_info else ""

    print(f"Monitoring {len(paths)} path(s) for threats{mode_str}...")
    print("Press Ctrl+C to stop.\n")

    monitor.start()

    try:
        while monitor.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
        print("Monitor stopped.")
