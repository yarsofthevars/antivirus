"""macOS Menu Bar Application for Box of Kingles: The AntiVirus!"""

import os
import subprocess
import threading
from pathlib import Path
from typing import Optional, List
from datetime import datetime

import rumps

from .scanner import scan_file, scan_directory, ScanResult
from .monitor import FileMonitor
from .quarantine import list_quarantine, restore_file, delete_quarantined, quarantine_file
from .config import load_config, save_config, get_config_dir
from .exclusions import load_exclusions
from .scheduler import load_schedule, get_daemon_status
from .reports import list_reports, generate_report, save_report, get_reports_dir


# Status icons (emoji-based for simplicity)
ICON_PROTECTED = "🛡️"
ICON_SCANNING = "🔍"
ICON_THREAT = "⚠️"
ICON_DISABLED = "⏸️"


class AntivirusApp(rumps.App):
    """Box of Kingles Menu Bar Application."""

    def __init__(self):
        super().__init__(
            name="Box of Kingles",
            title=ICON_DISABLED,
            quit_button=None,  # We'll add our own
        )

        self.monitor: Optional[FileMonitor] = None
        self.recent_threats: List[dict] = []
        self.scanning = False
        self.config = load_config()

        # Build the menu
        self.build_menu()

        # Timer for periodic updates
        self.timer = rumps.Timer(self.update_menu, 30)
        self.timer.start()

    def build_menu(self):
        """Build the application menu."""
        self.menu.clear()

        # Protection toggle
        protection_status = "ON" if self.monitor and self.monitor.is_running() else "OFF"
        self.protection_item = rumps.MenuItem(
            f"Protection: {protection_status}",
            callback=self.toggle_protection
        )
        self.menu.add(self.protection_item)

        self.menu.add(rumps.separator)

        # Quick Scan submenu
        quick_scan = rumps.MenuItem("Quick Scan")
        quick_scan.add(rumps.MenuItem("Scan File...", callback=self.scan_file_dialog))
        quick_scan.add(rumps.MenuItem("Scan Folder...", callback=self.scan_folder_dialog))
        quick_scan.add(rumps.separator)
        quick_scan.add(rumps.MenuItem("Scan Downloads", callback=self.scan_downloads))
        quick_scan.add(rumps.MenuItem("Scan Home", callback=self.scan_home))
        self.menu.add(quick_scan)

        self.menu.add(rumps.separator)

        # Quarantine submenu
        self.build_quarantine_menu()

        # Recent Threats submenu
        self.build_recent_threats_menu()

        self.menu.add(rumps.separator)

        # Scheduled Scans submenu
        self.build_scheduled_menu()

        self.menu.add(rumps.separator)

        # Settings and other items
        self.menu.add(rumps.MenuItem("Settings...", callback=self.open_settings))
        self.menu.add(rumps.MenuItem("View Reports...", callback=self.open_reports))
        self.menu.add(rumps.MenuItem("About Box of Kingles", callback=self.show_about))

        self.menu.add(rumps.separator)
        self.menu.add(rumps.MenuItem("Quit", callback=self.quit_app))

    def build_quarantine_menu(self):
        """Build the quarantine submenu."""
        entries = list_quarantine()
        count = len(entries)

        quarantine_menu = rumps.MenuItem(f"Quarantine ({count} items)")

        if entries:
            for entry in entries[:5]:  # Show first 5
                name = Path(entry.original_path).name
                item_text = f"{name} - {entry.threat_name}"
                item = rumps.MenuItem(item_text)
                item.add(rumps.MenuItem("Restore", callback=lambda _, e=entry: self.restore_quarantine(e)))
                item.add(rumps.MenuItem("Delete", callback=lambda _, e=entry: self.delete_quarantine(e)))
                quarantine_menu.add(item)

            if count > 5:
                quarantine_menu.add(rumps.separator)
                quarantine_menu.add(rumps.MenuItem(f"... and {count - 5} more"))
        else:
            quarantine_menu.add(rumps.MenuItem("(Empty)"))

        quarantine_menu.add(rumps.separator)
        quarantine_menu.add(rumps.MenuItem("Open Quarantine Folder", callback=self.open_quarantine_folder))

        self.menu.add(quarantine_menu)

    def build_recent_threats_menu(self):
        """Build the recent threats submenu."""
        count = len(self.recent_threats)
        threats_menu = rumps.MenuItem(f"Recent Threats ({count})")

        if self.recent_threats:
            for threat in self.recent_threats[-5:]:
                path = threat.get("path", "Unknown")
                name = threat.get("name", "Unknown Threat")
                threats_menu.add(rumps.MenuItem(f"{Path(path).name} - {name}"))

            threats_menu.add(rumps.separator)
            threats_menu.add(rumps.MenuItem("Clear History", callback=self.clear_threats))
        else:
            threats_menu.add(rumps.MenuItem("(No recent threats)"))

        self.menu.add(threats_menu)

    def build_scheduled_menu(self):
        """Build the scheduled scans submenu."""
        tasks = load_schedule()
        scheduled_menu = rumps.MenuItem("Scheduled Scans")

        if tasks:
            for task in tasks[:5]:
                status = "✓" if task.enabled else "✗"
                next_run = task.next_run[:10] if task.next_run else "Not scheduled"
                item_text = f"{status} {task.name} ({next_run})"
                scheduled_menu.add(rumps.MenuItem(item_text))
        else:
            scheduled_menu.add(rumps.MenuItem("(No scheduled scans)"))

        # Daemon status
        daemon = get_daemon_status()
        daemon_status = "Running" if daemon.get("running") else "Stopped"
        scheduled_menu.add(rumps.separator)
        scheduled_menu.add(rumps.MenuItem(f"Daemon: {daemon_status}"))

        self.menu.add(scheduled_menu)

    def update_menu(self, _=None):
        """Periodic menu update."""
        self.build_menu()
        self.update_icon()

    def update_icon(self):
        """Update the menu bar icon based on status."""
        if self.scanning:
            self.title = ICON_SCANNING
        elif self.recent_threats:
            self.title = ICON_THREAT
        elif self.monitor and self.monitor.is_running():
            self.title = ICON_PROTECTED
        else:
            self.title = ICON_DISABLED

    def toggle_protection(self, _):
        """Toggle real-time protection."""
        if self.monitor and self.monitor.is_running():
            self.monitor.stop()
            self.monitor = None
            rumps.notification(
                title="Box of Kingles",
                subtitle="Protection Disabled",
                message="Real-time protection has been turned off.",
            )
        else:
            # Monitor common paths
            paths = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
            ]
            paths = [p for p in paths if os.path.exists(p)]

            exclusions = load_exclusions()
            self.monitor = FileMonitor(
                paths=paths,
                recursive=True,
                auto_quarantine=self.config.scan.default_auto_quarantine,
                use_heuristics=self.config.heuristics.enabled,
                exclusion_config=exclusions,
                on_threat=self.on_threat_detected,
            )
            self.monitor.start()
            rumps.notification(
                title="Box of Kingles",
                subtitle="Protection Enabled",
                message=f"Monitoring: {', '.join(Path(p).name for p in paths)}",
            )

        self.update_menu()

    def on_threat_detected(self, path: Path, threat_name: str, result: Optional[ScanResult]):
        """Handle threat detection."""
        self.recent_threats.append({
            "path": str(path),
            "name": threat_name,
            "time": datetime.now().isoformat(),
        })
        # Keep only last 20
        self.recent_threats = self.recent_threats[-20:]

        rumps.notification(
            title="Threat Detected!",
            subtitle=threat_name,
            message=str(path),
            sound=True,
        )
        self.update_icon()

    def run_scan(self, path: Path, is_directory: bool = False):
        """Run a scan in background thread."""
        def scan_thread():
            self.scanning = True
            self.update_icon()

            try:
                if is_directory:
                    results = scan_directory(
                        path,
                        recursive=True,
                        use_heuristics=self.config.heuristics.enabled,
                        exclusion_config=load_exclusions(),
                    )
                else:
                    results = [scan_file(
                        path,
                        use_heuristics=self.config.heuristics.enabled,
                    )]

                threats = [r for r in results if r.is_threat]

                for threat in threats:
                    self.recent_threats.append({
                        "path": str(threat.path),
                        "name": threat.threat_name or "Unknown",
                        "time": datetime.now().isoformat(),
                    })

                # Show notification
                if threats:
                    rumps.notification(
                        title="Scan Complete",
                        subtitle=f"{len(threats)} threat(s) found!",
                        message=f"Scanned {len(results)} files",
                        sound=True,
                    )
                else:
                    rumps.notification(
                        title="Scan Complete",
                        subtitle="No threats found",
                        message=f"Scanned {len(results)} files",
                    )

            except Exception as e:
                rumps.notification(
                    title="Scan Error",
                    subtitle="An error occurred",
                    message=str(e),
                )
            finally:
                self.scanning = False
                self.update_icon()

        thread = threading.Thread(target=scan_thread, daemon=True)
        thread.start()

    def scan_file_dialog(self, _):
        """Open file picker and scan selected file."""
        script = '''
        tell application "System Events"
            activate
            set theFile to choose file with prompt "Select a file to scan"
            return POSIX path of theFile
        end tell
        '''
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                path = Path(result.stdout.strip())
                self.run_scan(path, is_directory=False)
        except Exception:
            pass

    def scan_folder_dialog(self, _):
        """Open folder picker and scan selected folder."""
        script = '''
        tell application "System Events"
            activate
            set theFolder to choose folder with prompt "Select a folder to scan"
            return POSIX path of theFolder
        end tell
        '''
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                path = Path(result.stdout.strip())
                self.run_scan(path, is_directory=True)
        except Exception:
            pass

    def scan_downloads(self, _):
        """Scan Downloads folder."""
        path = Path.home() / "Downloads"
        if path.exists():
            self.run_scan(path, is_directory=True)

    def scan_home(self, _):
        """Scan Home folder."""
        path = Path.home()
        self.run_scan(path, is_directory=True)

    def restore_quarantine(self, entry):
        """Restore a quarantined file."""
        if restore_file(entry.id):
            rumps.notification(
                title="File Restored",
                subtitle=entry.threat_name,
                message=f"Restored to: {entry.original_path}",
            )
            self.update_menu()

    def delete_quarantine(self, entry):
        """Delete a quarantined file."""
        if delete_quarantined(entry.id):
            rumps.notification(
                title="File Deleted",
                subtitle=entry.threat_name,
                message="Permanently removed from quarantine",
            )
            self.update_menu()

    def clear_threats(self, _):
        """Clear recent threats history."""
        self.recent_threats = []
        self.update_icon()
        self.update_menu()

    def open_quarantine_folder(self, _):
        """Open quarantine folder in Finder."""
        quarantine_dir = get_config_dir() / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["open", str(quarantine_dir)])

    def open_reports(self, _):
        """Open reports folder in Finder."""
        reports_dir = get_reports_dir()
        reports_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(["open", str(reports_dir)])

    def open_settings(self, _):
        """Open settings dialog."""
        # Simple settings via alert
        config = load_config()

        message = f"""Current Settings:

Heuristics: {"Enabled" if config.heuristics.enabled else "Disabled"}
Entropy Threshold: {config.heuristics.entropy_threshold}
Auto-Quarantine: {"Enabled" if config.scan.default_auto_quarantine else "Disabled"}

To change settings, use the CLI:
python -m antivirus config set <key> <value>"""

        rumps.alert(
            title="Box of Kingles Settings",
            message=message,
            ok="OK",
        )

    def show_about(self, _):
        """Show about dialog."""
        rumps.alert(
            title="Box of Kingles: The AntiVirus!",
            message="""Version 1.2.0

A minimal cross-platform antivirus scanner with:
- SHA-256 signature detection
- YARA pattern matching
- Heuristic analysis
- Real-time protection
- Scheduled scans

Stay safe out there!""",
            ok="OK",
        )

    def quit_app(self, _):
        """Quit the application."""
        if self.monitor and self.monitor.is_running():
            self.monitor.stop()
        rumps.quit_application()


def main():
    """Launch the menu bar application."""
    app = AntivirusApp()
    app.run()


if __name__ == "__main__":
    main()
