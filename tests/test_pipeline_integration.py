"""Integration test: a burst of fake events must produce a Critical incident."""

import json
import os
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.core.models import EventType, FileEvent
from app.database.db import Database
from app.database.models import AlertRecord, IncidentRecord, ProcessSnapshot
from app.detectors.pipeline import Pipeline
from app.detectors.scoring import CRITICAL, NORMAL


@pytest.fixture
def system(tmp_path):
    """A complete RDRS pipeline wired to a temporary database and folders."""
    settings = Settings()
    settings.paths.database = str(tmp_path / "test.db")
    settings.response.quarantine_dir = str(tmp_path / "quarantine")
    db = Database(settings.paths.database)
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    return Pipeline(db, settings), db, sandbox


def feed_attack(pipeline: Pipeline, sandbox: Path, count: int = 25) -> None:
    """Create `count` fake-encrypted files and feed their events to the pipeline."""
    for i in range(count):
        original = sandbox / f"doc{i}.txt"
        locked = sandbox / f"doc{i}.locked"
        locked.write_bytes(os.urandom(2000))  # the file as it exists after the "attack"
        pipeline.process_event(
            FileEvent(event_type=EventType.MODIFIED, path=str(original), extension=".txt"),
            7.99,
        )
        pipeline.process_event(
            FileEvent(
                event_type=EventType.MOVED,
                path=str(original),
                extension=".txt",
                dest_path=str(locked),
                dest_extension=".locked",
            ),
            7.99,
        )


def test_burst_produces_critical_incident_with_evidence(system):
    pipeline, db, sandbox = system
    feed_attack(pipeline, sandbox)

    assert pipeline.latest.level == CRITICAL
    assert pipeline.latest.score >= 70

    with db.session() as s:
        incidents = list(s.scalars(select(IncidentRecord)))
        alerts = list(s.scalars(select(AlertRecord)))
    assert len(incidents) == 1  # the cooldown stops duplicates
    assert incidents[0].level == CRITICAL
    assert len(alerts) >= 2  # at least a Warning and a Critical

    evidence = Path(incidents[0].evidence_dir)
    assert (evidence / "manifest.json").is_file()
    copies = [p for p in evidence.iterdir() if p.name != "manifest.json"]
    assert len(copies) > 0


def test_original_files_are_left_untouched(system):
    pipeline, db, sandbox = system
    feed_attack(pipeline, sandbox)
    before = {p.name: p.read_bytes() for p in sandbox.iterdir()}

    with db.session() as s:
        evidence = Path(s.scalars(select(IncidentRecord)).first().evidence_dir)
    assert evidence.is_dir()

    after = {p.name: p.read_bytes() for p in sandbox.iterdir()}
    assert before == after  # nothing moved, changed or deleted


def test_normal_activity_creates_no_incident(system):
    pipeline, db, sandbox = system
    for i in range(3):
        path = sandbox / f"note{i}.txt"
        path.write_text("hello")
        pipeline.process_event(
            FileEvent(event_type=EventType.MODIFIED, path=str(path), extension=".txt"),
            3.4,
        )
    assert pipeline.latest.level == NORMAL
    assert db.count(IncidentRecord) == 0


def test_suspect_process_is_recorded(system):
    pipeline, db, sandbox = system
    pipeline.update_processes(
        [
            ProcessSnapshot(pid=1, name="calm.exe", cpu_percent=1.0, memory_mb=10,
                            disk_write_mb=1, exe_path="C:\\Windows\\calm.exe"),
            ProcessSnapshot(pid=2, name="evil.exe", cpu_percent=95.0, memory_mb=50,
                            disk_write_mb=900, exe_path="C:\\Users\\Temp\\evil.exe"),
        ]
    )
    feed_attack(pipeline, sandbox)

    with db.session() as s:
        incident = s.scalars(select(IncidentRecord)).first()
        files = json.loads(incident.affected_files)
    assert incident.suspect_process == "evil.exe"
    assert {"cpu_spike", "unknown_program"} <= set(pipeline.latest.signals)
    assert len(files) > 0