"""Scheduler for automated scans with daemon support."""

import json
import os
import signal
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .config import get_config_dir, get_scheduler_pid_file, get_scheduler_log_file


class ScheduleInterval(Enum):
    """Predefined schedule intervals."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    CUSTOM = "custom"

    @property
    def seconds(self) -> int:
        """Get interval in seconds."""
        intervals = {
            "hourly": 3600,
            "daily": 86400,
            "weekly": 604800,
            "custom": 0,
        }
        return intervals[self.value]


@dataclass
class ScheduledTask:
    """A scheduled scan task."""
    id: str
    name: str
    paths: List[str]
    interval: ScheduleInterval
    cron_expression: Optional[str] = None  # For custom intervals
    enabled: bool = True
    recursive: bool = True
    auto_quarantine: bool = False
    use_heuristics: bool = False
    last_run: Optional[str] = None  # ISO timestamp
    next_run: Optional[str] = None  # ISO timestamp
    created: str = ""  # ISO timestamp

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "paths": self.paths,
            "interval": self.interval.value,
            "cron_expression": self.cron_expression,
            "enabled": self.enabled,
            "recursive": self.recursive,
            "auto_quarantine": self.auto_quarantine,
            "use_heuristics": self.use_heuristics,
            "last_run": self.last_run,
            "next_run": self.next_run,
            "created": self.created,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScheduledTask":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            paths=data.get("paths", []),
            interval=ScheduleInterval(data.get("interval", "daily")),
            cron_expression=data.get("cron_expression"),
            enabled=data.get("enabled", True),
            recursive=data.get("recursive", True),
            auto_quarantine=data.get("auto_quarantine", False),
            use_heuristics=data.get("use_heuristics", False),
            last_run=data.get("last_run"),
            next_run=data.get("next_run"),
            created=data.get("created", ""),
        )

    def calculate_next_run(self) -> datetime:
        """Calculate when this task should next run."""
        now = datetime.now()

        if self.interval == ScheduleInterval.CUSTOM and self.cron_expression:
            # For custom intervals, parse simple format: "HH:MM" for daily at specific time
            # or number of seconds for custom interval
            try:
                if ":" in self.cron_expression:
                    # Parse as time of day (HH:MM)
                    hour, minute = map(int, self.cron_expression.split(":"))
                    next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
                    if next_run <= now:
                        next_run += timedelta(days=1)
                    return next_run
                else:
                    # Parse as seconds interval
                    interval_secs = int(self.cron_expression)
                    return now + timedelta(seconds=interval_secs)
            except (ValueError, TypeError):
                # Fall back to daily
                return now + timedelta(days=1)
        else:
            return now + timedelta(seconds=self.interval.seconds)


def get_schedule_path() -> Path:
    """Get the path to the schedule file."""
    return get_config_dir() / "schedule.json"


def load_schedule() -> List[ScheduledTask]:
    """Load scheduled tasks from file."""
    path = get_schedule_path()

    if not path.exists():
        return []

    try:
        with open(path, "r") as f:
            data = json.load(f)
        return [ScheduledTask.from_dict(task) for task in data.get("tasks", [])]
    except (json.JSONDecodeError, KeyError):
        return []


def save_schedule(tasks: List[ScheduledTask]) -> None:
    """Save scheduled tasks to file."""
    path = get_schedule_path()

    with open(path, "w") as f:
        json.dump({"tasks": [task.to_dict() for task in tasks]}, f, indent=2)


def add_scheduled_task(
    name: str,
    paths: List[str],
    interval: ScheduleInterval = ScheduleInterval.DAILY,
    cron_expression: Optional[str] = None,
    recursive: bool = True,
    auto_quarantine: bool = False,
    use_heuristics: bool = False,
) -> ScheduledTask:
    """Add a new scheduled task."""
    tasks = load_schedule()

    now = datetime.now()
    task = ScheduledTask(
        id=str(uuid.uuid4())[:8],
        name=name,
        paths=paths,
        interval=interval,
        cron_expression=cron_expression,
        enabled=True,
        recursive=recursive,
        auto_quarantine=auto_quarantine,
        use_heuristics=use_heuristics,
        last_run=None,
        next_run=None,
        created=now.isoformat(),
    )

    # Calculate next run
    task.next_run = task.calculate_next_run().isoformat()

    tasks.append(task)
    save_schedule(tasks)
    return task


def remove_scheduled_task(task_id: str) -> bool:
    """Remove a scheduled task. Returns True if found and removed."""
    tasks = load_schedule()
    original_count = len(tasks)
    tasks = [t for t in tasks if t.id != task_id]

    if len(tasks) < original_count:
        save_schedule(tasks)
        return True
    return False


def enable_scheduled_task(task_id: str) -> bool:
    """Enable a scheduled task. Returns True if found."""
    tasks = load_schedule()

    for task in tasks:
        if task.id == task_id:
            task.enabled = True
            task.next_run = task.calculate_next_run().isoformat()
            save_schedule(tasks)
            return True
    return False


def disable_scheduled_task(task_id: str) -> bool:
    """Disable a scheduled task. Returns True if found."""
    tasks = load_schedule()

    for task in tasks:
        if task.id == task_id:
            task.enabled = False
            save_schedule(tasks)
            return True
    return False


def get_scheduled_task(task_id: str) -> Optional[ScheduledTask]:
    """Get a scheduled task by ID."""
    tasks = load_schedule()
    for task in tasks:
        if task.id == task_id:
            return task
    return None


def update_task_last_run(task_id: str) -> None:
    """Update task's last run time and calculate next run."""
    tasks = load_schedule()

    for task in tasks:
        if task.id == task_id:
            now = datetime.now()
            task.last_run = now.isoformat()
            task.next_run = task.calculate_next_run().isoformat()
            save_schedule(tasks)
            return


class Scheduler:
    """Background scheduler daemon for running scheduled scans."""

    def __init__(
        self,
        on_task_start: Optional[Callable[[ScheduledTask], None]] = None,
        on_task_complete: Optional[Callable[[ScheduledTask, int, int], None]] = None,
        on_error: Optional[Callable[[ScheduledTask, Exception], None]] = None,
    ):
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pid_file = get_scheduler_pid_file()
        self._log_file = get_scheduler_log_file()
        self.on_task_start = on_task_start
        self.on_task_complete = on_task_complete
        self.on_error = on_error

    def _log(self, message: str) -> None:
        """Write to log file."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {message}\n"

        with open(self._log_file, "a") as f:
            f.write(log_line)

    def _write_pid(self) -> None:
        """Write current process ID to PID file."""
        self._pid_file.write_text(str(os.getpid()))

    def _remove_pid(self) -> None:
        """Remove PID file."""
        if self._pid_file.exists():
            self._pid_file.unlink()

    def _run_task(self, task: ScheduledTask) -> None:
        """Execute a scheduled task."""
        from .scanner import scan_path
        from .quarantine import quarantine_file
        from .exclusions import load_exclusions
        from .reports import generate_report, save_report

        try:
            if self.on_task_start:
                self.on_task_start(task)

            self._log(f"Starting task '{task.name}' (ID: {task.id})")

            # Load exclusions
            exclusion_config = load_exclusions()

            # Run scan for each path
            all_results = []
            for path_str in task.paths:
                path = Path(path_str).expanduser().resolve()
                if path.exists():
                    results = scan_path(
                        path,
                        recursive=task.recursive,
                        use_heuristics=task.use_heuristics,
                        exclusion_config=exclusion_config,
                    )
                    all_results.extend(results)

            # Count threats and quarantine if enabled
            threats_found = 0
            quarantined = 0
            for result in all_results:
                if result.is_threat:
                    threats_found += 1
                    if task.auto_quarantine and result.threat_name:
                        try:
                            quarantine_file(result.path, result.threat_name)
                            quarantined += 1
                        except Exception:
                            pass

            # Generate report
            report = generate_report(
                results=all_results,
                paths_scanned=task.paths,
                scan_type="scheduled",
                quarantined_count=quarantined,
            )
            save_report(report, format="json")

            # Update task
            update_task_last_run(task.id)

            self._log(
                f"Completed task '{task.name}': "
                f"{len(all_results)} files scanned, {threats_found} threats, {quarantined} quarantined"
            )

            if self.on_task_complete:
                self.on_task_complete(task, len(all_results), threats_found)

        except Exception as e:
            self._log(f"Error in task '{task.name}': {e}")
            if self.on_error:
                self.on_error(task, e)

    def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        self._log("Scheduler started")
        self._write_pid()

        while not self._stop_event.is_set():
            try:
                now = datetime.now()
                tasks = load_schedule()

                for task in tasks:
                    if not task.enabled:
                        continue

                    if task.next_run is None:
                        continue

                    try:
                        next_run = datetime.fromisoformat(task.next_run)
                    except (ValueError, TypeError):
                        continue

                    if now >= next_run:
                        # Run in separate thread to not block scheduler
                        task_thread = threading.Thread(
                            target=self._run_task,
                            args=(task,),
                            daemon=True,
                        )
                        task_thread.start()

            except Exception as e:
                self._log(f"Scheduler error: {e}")

            # Check every 30 seconds
            self._stop_event.wait(30)

        self._log("Scheduler stopped")
        self._remove_pid()

    def start(self, background: bool = True) -> None:
        """
        Start the scheduler.

        Args:
            background: Run in background thread (True) or foreground (False)
        """
        if self._thread is not None and self._thread.is_alive():
            return  # Already running

        self._stop_event.clear()

        if background:
            self._thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self._thread.start()
        else:
            # Run in foreground (blocking)
            self._scheduler_loop()

    def stop(self) -> None:
        """Stop the scheduler."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def is_running(self) -> bool:
        """Check if scheduler is running."""
        return self._thread is not None and self._thread.is_alive()


def get_daemon_status() -> Dict:
    """
    Get daemon status information.

    Returns:
        Dict with status information
    """
    pid_file = get_scheduler_pid_file()
    log_file = get_scheduler_log_file()

    status = {
        "running": False,
        "pid": None,
        "pid_file": str(pid_file),
        "log_file": str(log_file),
        "tasks_count": len(load_schedule()),
        "enabled_tasks": len([t for t in load_schedule() if t.enabled]),
    }

    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
            # Check if process is actually running
            try:
                os.kill(pid, 0)  # Doesn't actually kill, just checks
                status["running"] = True
                status["pid"] = pid
            except OSError:
                # Process not running, stale PID file
                pass
        except (ValueError, IOError):
            pass

    return status


def start_daemon() -> bool:
    """
    Start the scheduler daemon.

    Returns:
        True if daemon was started, False if already running
    """
    status = get_daemon_status()
    if status["running"]:
        return False

    # Create scheduler and start
    scheduler = Scheduler()
    scheduler.start(background=True)

    # Give it a moment to start
    time.sleep(0.5)

    return scheduler.is_running()


def stop_daemon() -> bool:
    """
    Stop the scheduler daemon.

    Returns:
        True if daemon was stopped, False if not running
    """
    pid_file = get_scheduler_pid_file()

    if not pid_file.exists():
        return False

    try:
        pid = int(pid_file.read_text().strip())

        # Send SIGTERM
        try:
            os.kill(pid, signal.SIGTERM)
            # Wait for process to terminate
            for _ in range(10):
                time.sleep(0.5)
                try:
                    os.kill(pid, 0)
                except OSError:
                    break  # Process terminated
        except OSError:
            pass  # Process already terminated

        # Clean up PID file
        if pid_file.exists():
            pid_file.unlink()

        return True

    except (ValueError, IOError):
        return False


def run_daemon_foreground() -> None:
    """
    Run the scheduler daemon in foreground (blocking).
    Useful for running as a system service.
    """
    scheduler = Scheduler(
        on_task_start=lambda t: print(f"Starting task: {t.name}"),
        on_task_complete=lambda t, files, threats: print(
            f"Completed task: {t.name} ({files} files, {threats} threats)"
        ),
        on_error=lambda t, e: print(f"Error in task {t.name}: {e}"),
    )

    def signal_handler(signum, frame):
        print("\nShutting down scheduler...")
        scheduler.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("Starting scheduler daemon (foreground mode)")
    print("Press Ctrl+C to stop")

    scheduler.start(background=False)
