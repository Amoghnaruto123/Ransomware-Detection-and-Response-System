"""Tests for the file monitor, process monitor, logger and config loader."""

import os
import time

import pytest
from loguru import logger
from pydantic import ValidationError
from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirModifiedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
)

import app.core.logger as logger_module
from app.core.config import load_config
from app.core.logger import get_logger, setup_logging
from app.detectors.file_monitor import FileMonitor, RDRSEventHandler
from app.detectors.process_monitor import take_snapshot


def wait_for(condition, timeout=5.0):
    """Poll until condition() is true or the timeout passes."""
    end = time.time() + timeout
    while time.time() < end:
        if condition():
            return True
        time.sleep(0.05)
    return False


# ---------- event handler ----------


def test_handler_converts_and_counts_all_four_event_types():
    seen = []
    handler = RDRSEventHandler(callback=seen.append)
    handler.on_created(FileCreatedEvent("C:/x/a.TXT"))
    handler.on_modified(FileModifiedEvent("C:/x/a.TXT"))
    handler.on_moved(FileMovedEvent("C:/x/a.TXT", "C:/x/a.locked"))
    handler.on_deleted(FileDeletedEvent("C:/x/a.locked"))
    kinds = [e.event_type.value for e in seen]
    assert kinds == ["created", "modified", "moved", "deleted"]
    assert handler.total == 4
    assert handler.summary == {"created": 1, "modified": 1, "moved": 1, "deleted": 1}
    assert seen[0].extension == ".txt"  # lower-cased
    assert seen[2].dest_extension == ".locked"
    assert seen[2].extension_changed is True


def test_handler_ignores_directory_events():
    seen = []
    handler = RDRSEventHandler(callback=seen.append)
    handler.on_created(DirCreatedEvent("C:/x/folder"))
    handler.on_modified(DirModifiedEvent("C:/x/folder"))
    handler.on_deleted(DirDeletedEvent("C:/x/folder"))
    handler.on_moved(DirMovedEvent("C:/x/a", "C:/x/b"))
    assert handler.total == 0
    assert seen == []


def test_handler_works_without_a_callback():
    handler = RDRSEventHandler()
    handler.on_created(FileCreatedEvent("a.txt"))
    assert handler.total == 1


# ---------- live file monitor ----------


def test_monitor_sees_real_file_changes(tmp_path):
    watched = tmp_path / "watched"  # does not exist yet: start() must create it
    seen = []
    monitor = FileMonitor([str(watched)], callback=seen.append)
    monitor.start()
    try:
        assert watched.is_dir()
        time.sleep(0.5)
        target = watched / "a.txt"
        target.write_text("hello")
        assert wait_for(lambda: monitor.total >= 1)
        target.rename(watched / "a.locked")
        assert wait_for(lambda: monitor.summary["moved"] >= 1)
    finally:
        monitor.stop()
    assert any(e.event_type.value == "created" for e in seen)
    assert any(e.extension_changed for e in seen)


# ---------- process monitor ----------


def test_snapshot_lists_this_process_and_skips_idle():
    snaps = take_snapshot(interval=0.05)
    assert len(snaps) > 5
    pids = {s.pid for s in snaps}
    assert os.getpid() in pids
    assert 0 not in pids  # System Idle Process is ignored
    mine = next(s for s in snaps if s.pid == os.getpid())
    assert mine.name
    assert mine.memory_mb > 0
    assert 0 <= mine.cpu_percent <= 100


# ---------- logger ----------


@pytest.fixture
def fresh_logging(monkeypatch):
    """Reset the logger so each test can set it up from scratch."""
    monkeypatch.setattr(logger_module, "_configured", False)
    yield
    logger.remove()  # close all log files so Windows can delete the temp folder
    monkeypatch.setattr(logger_module, "_configured", False)


def test_setup_logging_creates_one_file_per_channel(tmp_path, fresh_logging):
    logs = tmp_path / "logs"
    setup_logging(str(logs))
    get_logger("alerts").warning("an alert")
    get_logger("audit").info("an audit line")
    get_logger("events").info("an event")
    get_logger("system").info("started")
    get_logger("system").error("something broke")
    logger.complete()

    assert "an alert" in (logs / "alerts.log").read_text(encoding="utf-8")
    assert "an audit line" in (logs / "audit.log").read_text(encoding="utf-8")
    assert "an event" in (logs / "events.log").read_text(encoding="utf-8")
    assert "alert" not in (logs / "system.log").read_text(encoding="utf-8")
    errors = (logs / "errors.log").read_text(encoding="utf-8")
    assert "something broke" in errors
    assert "started" not in errors


def test_setup_logging_is_safe_to_call_twice(tmp_path, fresh_logging):
    logs = tmp_path / "logs"
    setup_logging(str(logs))
    setup_logging(str(logs))  # second call must not add duplicate handlers
    get_logger("alerts").warning("only once")
    logger.complete()
    text = (logs / "alerts.log").read_text(encoding="utf-8")
    assert text.count("only once") == 1


# ---------- config loader ----------


def test_load_config_reads_yaml_values(tmp_path):
    path = tmp_path / "c.yaml"
    path.write_text(
        "app:\n  simulation_mode: false\nthresholds:\n  avg_entropy: 6.5\n",
        encoding="utf-8",
    )
    settings = load_config(str(path))
    assert settings.app.simulation_mode is False
    assert settings.thresholds.avg_entropy == 6.5
    assert settings.weights.rapid_encryption == 40  # default for a missing section


def test_load_config_empty_file_uses_defaults(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    settings = load_config(str(path))
    assert settings.app.simulation_mode is True
    assert settings.levels.critical == 70


def test_load_config_rejects_bad_types(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("monitor:\n  window_seconds: banana\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(str(path))


def test_load_config_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "nope.yaml"))
