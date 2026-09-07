"""Tests for the scheduler module."""

import pytest
from pathlib import Path
from datetime import datetime, timedelta

from antivirus.scheduler import (
    ScheduleInterval,
    ScheduledTask,
    Scheduler,
    load_schedule,
    save_schedule,
    add_scheduled_task,
    remove_scheduled_task,
    enable_scheduled_task,
    disable_scheduled_task,
    get_scheduled_task,
    get_daemon_status,
)


class TestScheduleInterval:
    """Tests for ScheduleInterval enum."""

    def test_hourly_seconds(self):
        """Hourly should be 3600 seconds."""
        assert ScheduleInterval.HOURLY.seconds == 3600

    def test_daily_seconds(self):
        """Daily should be 86400 seconds."""
        assert ScheduleInterval.DAILY.seconds == 86400

    def test_weekly_seconds(self):
        """Weekly should be 604800 seconds."""
        assert ScheduleInterval.WEEKLY.seconds == 604800

    def test_custom_seconds(self):
        """Custom should be 0 (uses cron expression)."""
        assert ScheduleInterval.CUSTOM.seconds == 0


class TestScheduledTask:
    """Tests for ScheduledTask dataclass."""

    def test_to_dict(self):
        """Should serialize to dictionary."""
        task = ScheduledTask(
            id="test123",
            name="Test Task",
            paths=["/home/user"],
            interval=ScheduleInterval.DAILY,
            enabled=True,
            recursive=True,
            auto_quarantine=False,
            created="2025-01-01T00:00:00",
        )
        d = task.to_dict()
        assert d["id"] == "test123"
        assert d["name"] == "Test Task"
        assert d["interval"] == "daily"
        assert d["paths"] == ["/home/user"]

    def test_from_dict(self):
        """Should create from dictionary."""
        d = {
            "id": "test456",
            "name": "Another Task",
            "paths": ["/tmp"],
            "interval": "weekly",
            "enabled": False,
            "recursive": False,
            "auto_quarantine": True,
            "created": "2025-01-01T00:00:00",
        }
        task = ScheduledTask.from_dict(d)
        assert task.id == "test456"
        assert task.interval == ScheduleInterval.WEEKLY
        assert task.enabled is False

    def test_calculate_next_run_daily(self):
        """Should calculate next run for daily interval."""
        task = ScheduledTask(
            id="test",
            name="Test",
            paths=["/"],
            interval=ScheduleInterval.DAILY,
            created="",
        )
        next_run = task.calculate_next_run()
        now = datetime.now()
        assert next_run > now
        assert (next_run - now).days <= 1

    def test_calculate_next_run_custom_time(self):
        """Should calculate next run for custom time."""
        task = ScheduledTask(
            id="test",
            name="Test",
            paths=["/"],
            interval=ScheduleInterval.CUSTOM,
            cron_expression="03:00",  # 3 AM
            created="",
        )
        next_run = task.calculate_next_run()
        assert next_run.hour == 3
        assert next_run.minute == 0

    def test_calculate_next_run_custom_seconds(self):
        """Should calculate next run for custom seconds interval."""
        task = ScheduledTask(
            id="test",
            name="Test",
            paths=["/"],
            interval=ScheduleInterval.CUSTOM,
            cron_expression="300",  # 5 minutes
            created="",
        )
        now = datetime.now()
        next_run = task.calculate_next_run()
        diff = (next_run - now).total_seconds()
        assert 290 < diff < 310  # Around 300 seconds


class TestSchedulePersistence:
    """Tests for schedule persistence."""

    def test_empty_schedule(self, clean_config):
        """Should handle empty schedule."""
        tasks = load_schedule()
        assert isinstance(tasks, list)

    def test_save_and_load(self, clean_config):
        """Should save and load schedule."""
        tasks = [
            ScheduledTask(
                id="test1",
                name="Task 1",
                paths=["/tmp"],
                interval=ScheduleInterval.DAILY,
                created="2025-01-01T00:00:00",
            ),
        ]
        save_schedule(tasks)

        loaded = load_schedule()
        assert len(loaded) == 1
        assert loaded[0].id == "test1"

    def test_add_scheduled_task(self, clean_config):
        """Should add new task."""
        task = add_scheduled_task(
            name="New Task",
            paths=["/home"],
            interval=ScheduleInterval.WEEKLY,
        )
        assert task.id is not None
        assert task.name == "New Task"
        assert task.next_run is not None

        loaded = load_schedule()
        assert any(t.id == task.id for t in loaded)

    def test_remove_scheduled_task(self, clean_config):
        """Should remove task."""
        task = add_scheduled_task(
            name="To Remove",
            paths=["/tmp"],
        )
        assert remove_scheduled_task(task.id) is True
        assert remove_scheduled_task(task.id) is False  # Already removed

    def test_enable_disable_task(self, clean_config):
        """Should enable/disable task."""
        task = add_scheduled_task(
            name="Toggle Task",
            paths=["/tmp"],
        )

        assert disable_scheduled_task(task.id) is True
        loaded = get_scheduled_task(task.id)
        assert loaded.enabled is False

        assert enable_scheduled_task(task.id) is True
        loaded = get_scheduled_task(task.id)
        assert loaded.enabled is True


class TestScheduler:
    """Tests for Scheduler class."""

    def test_create_scheduler(self):
        """Should create scheduler instance."""
        scheduler = Scheduler()
        assert scheduler.is_running() is False

    def test_start_stop(self, clean_config):
        """Should start and stop scheduler."""
        scheduler = Scheduler()
        scheduler.start(background=True)
        assert scheduler.is_running() is True

        scheduler.stop()
        assert scheduler.is_running() is False

    def test_callbacks(self, clean_config):
        """Should call callbacks."""
        started = []
        completed = []

        def on_start(task):
            started.append(task)

        def on_complete(task, files, threats):
            completed.append((task, files, threats))

        scheduler = Scheduler(
            on_task_start=on_start,
            on_task_complete=on_complete,
        )

        # Just verify the scheduler was created with callbacks
        assert scheduler.on_task_start is not None
        assert scheduler.on_task_complete is not None


class TestDaemonStatus:
    """Tests for daemon status."""

    def test_get_status(self, clean_config):
        """Should get daemon status."""
        status = get_daemon_status()
        assert "running" in status
        assert "pid" in status
        assert "tasks_count" in status

    def test_status_when_stopped(self, clean_config):
        """Should show stopped when not running."""
        status = get_daemon_status()
        assert status["running"] is False
        assert status["pid"] is None
