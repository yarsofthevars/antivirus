"""Real-time file system monitoring for threat detection."""

import time
from pathlib import Path
from typing import Callable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from .scanner import scan_file
from .quarantine import quarantine_file


class ThreatHandler(FileSystemEventHandler):
    """Handler for file system events that scans files for threats."""

    def __init__(
        self,
        auto_quarantine: bool = False,
        on_threat: Optional[Callable[[Path, str], None]] = None,
        on_scan: Optional[Callable[[Path], None]] = None,
    ):
        self.auto_quarantine = auto_quarantine
        self.on_threat = on_threat
        self.on_scan = on_scan

    def _scan_file(self, path: Path) -> None:
        """Scan a file and handle threats."""
        if not path.is_file():
            return

        if self.on_scan:
            self.on_scan(path)

        result = scan_file(path)

        if result.is_threat and result.threat_name:
            if self.on_threat:
                self.on_threat(path, result.threat_name)

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
        on_threat: Optional[Callable[[Path, str], None]] = None,
        on_scan: Optional[Callable[[Path], None]] = None,
    ):
        self.paths = [Path(p).resolve() for p in paths]
        self.recursive = recursive
        self.observer = Observer()
        self.handler = ThreatHandler(
            auto_quarantine=auto_quarantine,
            on_threat=on_threat,
            on_scan=on_scan,
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
    verbose: bool = False,
) -> None:
    """Monitor paths for threats. Blocks until interrupted."""
    from datetime import datetime

    def on_threat(path: Path, threat_name: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        action = "Quarantined" if auto_quarantine else "Detected"
        print(f"[{timestamp}] [THREAT] {path}: {threat_name} ({action})")

    def on_scan(path: Path) -> None:
        if verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [SCAN] {path}")

    monitor = FileMonitor(
        paths=paths,
        recursive=recursive,
        auto_quarantine=auto_quarantine,
        on_threat=on_threat,
        on_scan=on_scan,
    )

    print(f"Monitoring {len(paths)} path(s) for threats...")
    print("Press Ctrl+C to stop.\n")

    monitor.start()

    try:
        while monitor.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()
        print("Monitor stopped.")
