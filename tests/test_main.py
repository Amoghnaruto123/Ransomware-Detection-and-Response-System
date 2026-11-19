"""Tests for the program entry point (app/main.py)."""

import os
import sys
import threading
import types
from datetime import datetime

import pytest
from loguru import logger

import app.core.logger as logger_module
import app.main as rdrs_main
from app.core.models import EventType, FileEvent
from app.database.models import ProcessSnapshot


@pytest.fixture
def fresh_logging(monkeypatch):
    """Reset the logger so main() can set it up inside a test."""
    monkeypatch.setattr(logger_module, "_configured", False)
    yield
    logger.remove()
    monkeypatch.setattr(logger_module, "_configured", False)


class RecordingDB:
    """Stands in for Database and remembers what it was asked to save."""

    def __init__(self):
        self.events = []
        self.process_batches = []

    def save_event(self, event, entropy=None):
        self.events.append((event, entropy))

    def save_processes(self, snapshots):
        self.process_batches.append(list(snapshots))


class RecordingPipeline:
    """Stands in for Pipeline and remembers what it was given."""

    def __init__(self, fail=False):
        self.fail = fail
        self.events = []
        self.process_updates = []

    def process_event(self, event, entropy=None):
        if self.fail:
            raise RuntimeError("pipeline exploded")
        self.events.append((event, entropy))

    def update_processes(self, snapshots):
        self.process_updates.append(list(snapshots))


def make_snapshot(pid, name, cpu):
    return ProcessSnapshot(
        pid=pid, name=name, cpu_percent=cpu, memory_mb=1.0, disk_write_mb=0.0,
        exe_path="C:\\Windows\\x.exe", timestamp=datetime.now(),
    )


def test_parse_args_defaults_and_overrides(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["rdrs"])
    args = rdrs_main.parse_args()
    assert args.watch is None
    assert args.config == "config.yaml"

    argv = ["rdrs", "--watch", "a", "b", "--config", "x.yaml"]
    monkeypatch.setattr(sys, "argv", argv)
    args = rdrs_main.parse_args()
    assert args.watch == ["a", "b"]
    assert args.config == "x.yaml"


def test_measure_entropy_reads_files_and_gives_up_on_empty_ones(tmp_path):
    random_file = tmp_path / "r.bin"
    random_file.write_bytes(os.urandom(5000))
    empty_file = tmp_path / "e.bin"
    empty_file.write_bytes(b"")
    assert rdrs_main.measure_entropy(str(random_file)) > 7.9
    assert rdrs_main.measure_entropy(str(empty_file), retries=2, delay=0) is None
    missing = str(tmp_path / "gone.bin")
    assert rdrs_main.measure_entropy(missing, retries=2, delay=0) is None


def test_event_handler_measures_entropy_and_forwards_events(tmp_path):
    db, pipeline = RecordingDB(), RecordingPipeline()
    handle = rdrs_main.make_event_handler(db, pipeline)
    original = tmp_path / "a.txt"
    original.write_bytes(os.urandom(5000))
    locked = tmp_path / "a.locked"
    locked.write_bytes(os.urandom(5000))

    handle(FileEvent(event_type=EventType.CREATED, path=str(original),
                     extension=".txt"))
    handle(FileEvent(event_type=EventType.MOVED, path=str(original),
                     extension=".txt", dest_path=str(locked),
                     dest_extension=".locked"))
    handle(FileEvent(event_type=EventType.DELETED, path=str(locked),
                     extension=".locked"))

    assert len(db.events) == 3
    assert len(pipeline.events) == 3
    assert db.events[0][1] > 7.9  # created: measured
    assert db.events[1][1] > 7.9  # moved: measured at the new name
    assert db.events[2][1] is None  # deleted: nothing to measure


def test_event_handler_survives_a_failing_pipeline():
    db, pipeline = RecordingDB(), RecordingPipeline(fail=True)
    handle = rdrs_main.make_event_handler(db, pipeline)
    event = FileEvent(event_type=EventType.DELETED, path="x.txt", extension=".txt")
    handle(event)  # must not raise
    assert len(db.events) == 1  # saved before the pipeline failed


def test_plain_copy_duplicates_every_field():
    original = ProcessSnapshot(
        pid=5, name="a.exe", cpu_percent=1.5, memory_mb=2.5, disk_write_mb=3.5,
        exe_path="C:\\a.exe", parent_pid=1, parent_name="p.exe",
        timestamp=datetime.now(),
    )
    copy = rdrs_main.plain_copy(original)
    assert copy is not original
    fields = ("pid", "name", "cpu_percent", "memory_mb", "disk_write_mb",
              "exe_path", "parent_pid", "parent_name", "timestamp")
    for field in fields:
        assert getattr(copy, field) == getattr(original, field)


def test_process_loop_sorts_by_cpu_and_feeds_pipeline_and_database(monkeypatch):
    stop = threading.Event()

    def fake_snapshot():
        stop.set()  # so the loop runs exactly one round
        return [make_snapshot(1, "idle.exe", 0.5), make_snapshot(2, "busy.exe", 9.0)]

    monkeypatch.setattr(rdrs_main, "take_snapshot", fake_snapshot)
    db, pipeline = RecordingDB(), RecordingPipeline()
    rdrs_main.process_loop(db, pipeline, stop, interval=0)

    assert [p.name for p in db.process_batches[0]] == ["busy.exe", "idle.exe"]
    assert [p.name for p in pipeline.process_updates[0]] == ["busy.exe", "idle.exe"]
    assert pipeline.process_updates[0][0] is not db.process_batches[0][0]


def test_process_loop_survives_a_failing_snapshot(monkeypatch):
    stop = threading.Event()

    def broken():
        stop.set()
        raise RuntimeError("psutil exploded")

    monkeypatch.setattr(rdrs_main, "take_snapshot", broken)
    db, pipeline = RecordingDB(), RecordingPipeline()
    rdrs_main.process_loop(db, pipeline, stop, interval=0)  # must return normally
    assert db.process_batches == []


def test_main_starts_everything_and_stops_cleanly_on_ctrl_c(
    tmp_path, monkeypatch, capsys, fresh_logging
):
    config = tmp_path / "config.yaml"
    config.write_text(
        "paths:\n"
        f"  database: '{(tmp_path / 'main.db').as_posix()}'\n"
        f"  logs_dir: '{(tmp_path / 'logs').as_posix()}'\n",
        encoding="utf-8",
    )
    watched = tmp_path / "watched"
    argv = ["rdrs", "--config", str(config), "--watch", str(watched)]
    monkeypatch.setattr(sys, "argv", argv)

    def interrupt(_seconds):
        raise KeyboardInterrupt  # simulates the user pressing Ctrl+C

    monkeypatch.setattr(rdrs_main, "time", types.SimpleNamespace(sleep=interrupt))
    monkeypatch.setattr(rdrs_main, "take_snapshot", lambda: [])

    databases = []
    real_database = rdrs_main.Database

    def tracking_database(path):
        database = real_database(path)
        databases.append(database)
        return database

    monkeypatch.setattr(rdrs_main, "Database", tracking_database)

    rdrs_main.main()

    out = capsys.readouterr().out
    assert "Watching:" in out
    assert "Events: 0" in out
    assert "Stopped. Final count: 0" in out
    assert watched.is_dir()  # the monitor created the folder it was told to watch
    for database in databases:
        database._engine.dispose()
