"""Tests for the report generator and the database layer."""

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.core.models import EventType, FileEvent
from app.database.db import Database
from app.database.models import EventRecord, IncidentRecord, ProcessSnapshot
from app.reports.generator import build_report, generate_reports


@pytest.fixture
def db(tmp_path):
    """A fresh temporary database, closed properly after each test."""
    database = Database(str(tmp_path / "test.db"))
    yield database
    database._engine.dispose()


@pytest.fixture
def incident_id(db, tmp_path):
    """One Critical incident with an evidence manifest and nearby events."""
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    manifest = {
        "signals": {"rapid_encryption": 40, "mass_rename": 30},
        "files_copied": ["a.locked"],
    }
    (evidence / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    now = datetime.now()
    with db.session() as s:
        s.add(EventRecord(event_type="modified", path="a.txt", extension=".txt",
                          entropy=7.9, timestamp=now - timedelta(seconds=5)))
        s.add(EventRecord(event_type="moved", path="a.txt", dest_path="a.locked",
                          extension=".txt", dest_extension=".locked",
                          timestamp=now - timedelta(seconds=4)))
        s.add(EventRecord(event_type="modified", path="old.txt", extension=".txt",
                          timestamp=now - timedelta(hours=1)))
        incident = IncidentRecord(
            score=70, level="Critical", suspect_process="evil.exe",
            affected_files=json.dumps(["a.locked"]), evidence_dir=str(evidence),
            status="open", timestamp=now,
        )
        s.add(incident)
        s.commit()
        return incident.id


# ---------- report generator ----------


def test_build_report_contents(db, incident_id):
    report = build_report(db, incident_id)
    assert report["incident_id"] == incident_id
    assert report["threat_score"] == 70
    assert report["threat_level"] == "Critical"
    assert report["suspect_process"] == "evil.exe"
    assert report["signals"] == {"rapid_encryption": 40, "mass_rename": 30}
    assert report["affected_files"] == ["a.locked"]
    assert report["files_copied"] == ["a.locked"]
    assert any("evil.exe" in r for r in report["recommendations"])


def test_timeline_excludes_events_outside_the_window(db, incident_id):
    timeline = build_report(db, incident_id)["timeline"]
    assert len(timeline) == 2  # the 1-hour-old event is left out
    assert timeline[0]["entropy"] == 7.9
    assert timeline[1]["entropy"] is None


def test_missing_incident_returns_none(db, tmp_path):
    assert build_report(db, 999) is None
    assert generate_reports(db, 999, str(tmp_path / "reports")) is None


def test_report_survives_missing_or_broken_manifest(db, tmp_path):
    broken = tmp_path / "broken"
    broken.mkdir()
    (broken / "manifest.json").write_text("not json", encoding="utf-8")
    with db.session() as s:
        a = IncidentRecord(score=40, level="Warning", affected_files="[]",
                           evidence_dir=None, timestamp=datetime.now())
        b = IncidentRecord(score=40, level="Warning", affected_files="[]",
                           evidence_dir=str(broken), timestamp=datetime.now())
        s.add_all([a, b])
        s.commit()
        ids = [a.id, b.id]
    for incident in ids:
        report = build_report(db, incident)
        assert report["signals"] == {}
        assert report["suspect_process"] is None
        assert report["recommendations"]  # the general advice is still there


def test_generate_reports_writes_json_and_csv(db, incident_id, tmp_path):
    paths = generate_reports(db, incident_id, str(tmp_path / "reports"))
    assert Path(paths["json"]).is_file()
    assert Path(paths["csv"]).is_file()
    saved = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert saved["incident_id"] == incident_id
    assert saved["threat_score"] == 70


def test_csv_contains_every_section(db, incident_id, tmp_path):
    paths = generate_reports(db, incident_id, str(tmp_path / "reports"))
    with open(paths["csv"], encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    sections = {r["section"] for r in rows}
    assert {"summary", "signal", "affected_file", "timeline", "recommendation"} <= sections
    timeline = [r for r in rows if r["section"] == "timeline"]
    assert any("->" in r["item"] for r in timeline)  # the rename row
    assert any("entropy=7.9" in r["detail"] for r in timeline)


# ---------- database layer ----------


def test_save_event_stores_entropy(db):
    event = FileEvent(event_type=EventType.CREATED, path="x.txt", extension=".txt")
    db.save_event(event, entropy=7.5)
    assert db.count(EventRecord) == 1
    assert db.recent_events(1)[0].entropy == 7.5


def test_recent_events_are_newest_first(db):
    for name in ("first.txt", "second.txt", "third.txt"):
        db.save_event(FileEvent(event_type=EventType.MODIFIED, path=name, extension=".txt"))
    newest = db.recent_events(2)
    assert [e.path for e in newest] == ["third.txt", "second.txt"]


def test_save_processes_stores_rows(db):
    now = datetime.now()
    db.save_processes([
        ProcessSnapshot(pid=1, name="a.exe", timestamp=now),
        ProcessSnapshot(pid=2, name="b.exe", timestamp=now),
    ])
    assert db.count(ProcessSnapshot) == 2
