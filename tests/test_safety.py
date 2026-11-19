"""Tests for the safety rules: simulation mode and copy-only evidence."""

import os
from datetime import datetime

import pytest
from loguru import logger
from sqlalchemy import select

from app.core.config import Settings
from app.database.db import Database
from app.database.models import IncidentRecord
from app.detectors.detection_engine import WindowStats
from app.detectors.pipeline import is_trusted
from app.detectors.response import IncidentResponder
from app.detectors.scoring import calculate_score


@pytest.fixture
def setup(tmp_path):
    settings = Settings()
    settings.response.quarantine_dir = str(tmp_path / "quarantine")
    db = Database(str(tmp_path / "t.db"))
    yield settings, db, tmp_path
    db._engine.dispose()


def critical_case(settings, files):
    stats = WindowStats(window_seconds=60, rapid_encryption=True, mass_rename=True,
                        affected_files=[str(f) for f in files])
    return calculate_score(stats, settings.weights, settings.levels), stats


def capture_audit_messages():
    messages = []
    logger.add(lambda m: messages.append(m.record["message"]), level="INFO")
    return messages


def test_simulation_mode_only_logs_and_keeps_files(setup):
    settings, db, tmp_path = setup
    settings.response.terminate_process = True
    settings.app.simulation_mode = True
    f = tmp_path / "a.locked"
    f.write_bytes(os.urandom(100))
    original = f.read_bytes()
    assessment, stats = critical_case(settings, [f])

    messages = capture_audit_messages()
    IncidentResponder(db, settings).respond(assessment, stats, "evil.exe")

    assert any("SIMULATION: would terminate" in m for m in messages)
    assert f.read_bytes() == original


def test_live_mode_still_never_terminates(setup):
    settings, db, tmp_path = setup
    settings.response.terminate_process = True
    settings.app.simulation_mode = False
    f = tmp_path / "a.locked"
    f.write_bytes(b"data")
    assessment, stats = critical_case(settings, [f])

    messages = capture_audit_messages()
    IncidentResponder(db, settings).respond(assessment, stats, "evil.exe")

    assert any("nothing was killed" in m for m in messages)


def test_evidence_skips_missing_files_but_still_creates_incident(setup):
    settings, db, tmp_path = setup
    real = tmp_path / "real.locked"
    real.write_bytes(b"data")
    ghost = tmp_path / "ghost.locked"  # never created
    assessment, stats = critical_case(settings, [real, ghost])

    responder = IncidentResponder(db, settings)
    incident_id = responder.respond(assessment, stats, None)

    with db.session() as s:
        incident = s.scalars(select(IncidentRecord)).first()
    assert incident.id == incident_id
    copies = [p for p in os.listdir(incident.evidence_dir) if p != "manifest.json"]
    assert len(copies) == 1


def test_responder_cooldown_prevents_duplicate_incidents(setup):
    settings, db, tmp_path = setup
    f = tmp_path / "a.locked"
    f.write_bytes(b"data")
    assessment, stats = critical_case(settings, [f])
    responder = IncidentResponder(db, settings)
    assert responder.respond(assessment, stats, None) is not None
    assert responder.respond(assessment, stats, None) is None
    assert db.count(IncidentRecord) == 1


def test_is_trusted_rules():
    assert is_trusted("C:\\Windows\\System32\\svchost.exe")
    assert is_trusted("c:\\program files\\app\\a.exe")
    assert not is_trusted("D:\\Projects\\rdrs\\.venv\\Scripts\\python.exe")
    assert not is_trusted("C:\\Users\\Bob\\AppData\\Local\\Temp\\evil.exe")
    assert not is_trusted(None)
    assert not is_trusted("")
