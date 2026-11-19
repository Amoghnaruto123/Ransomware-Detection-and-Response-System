"""Tests for the REST API and dashboard routes, using FastAPI's TestClient."""

import json
from datetime import datetime, timedelta

import pytest
import yaml
from fastapi.testclient import TestClient

import app.api.dashboard_routes as dash
import app.api.main as api
from app.core.config import Settings
from app.database.db import Database
from app.database.models import (
    AlertRecord,
    EventRecord,
    IncidentRecord,
    ProcessSnapshot,
    ScoreRecord,
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """The API wired to a temporary database, config file and reports folder."""
    db = Database(str(tmp_path / "api.db"))

    config = tmp_path / "config.yaml"
    config.write_text(
        yaml.safe_dump({"app": {"simulation_mode": True},
                        "thresholds": {"files_modified_per_minute": 20}}),
        encoding="utf-8",
    )

    monkeypatch.setattr(api, "db", db)
    monkeypatch.setattr(api, "settings", Settings())
    monkeypatch.setattr(api, "CONFIG_PATH", str(config))
    monkeypatch.setattr(api, "REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setattr(dash, "_db", db)

    yield TestClient(api.app)
    db._engine.dispose()


def add_incident(db: Database, tmp_path) -> int:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "manifest.json").write_text(
        json.dumps({"signals": {"rapid_encryption": 40}, "files_copied": []}),
        encoding="utf-8",
    )
    with db.session() as s:
        incident = IncidentRecord(
            score=80, level="Critical", suspect_process="x.exe",
            affected_files="[]", evidence_dir=str(evidence),
            timestamp=datetime.now(),
        )
        s.add(incident)
        s.commit()
        return incident.id


# ---------- basic endpoints ----------


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_status_is_normal_when_database_is_empty(client):
    body = client.get("/status").json()
    assert body["threat_level"] == "Normal"
    assert body["threat_score"] == 0
    assert body["simulation_mode"] is True
    assert body["totals"] == {"events": 0, "alerts": 0, "incidents": 0}
    assert body["last_event_time"] is None


def test_status_reports_a_recent_critical_score(client):
    with api.db.session() as s:
        s.add(ScoreRecord(score=95, level="Critical", signals="[]", timestamp=datetime.now()))
        s.add(EventRecord(event_type="modified", path="a.txt", timestamp=datetime.now()))
        s.commit()
    body = client.get("/status").json()
    assert body["threat_level"] == "Critical"
    assert body["threat_score"] == 95
    assert body["totals"]["events"] == 1
    assert body["last_event_time"] is not None


def test_status_ignores_an_old_score(client):
    old = datetime.now() - timedelta(hours=5)
    with api.db.session() as s:
        s.add(ScoreRecord(score=95, level="Critical", signals="[]", timestamp=old))
        s.commit()
    assert client.get("/status").json()["threat_level"] == "Normal"


def test_alerts_newest_first_and_limit(client):
    with api.db.session() as s:
        for n in range(5):
            s.add(AlertRecord(level="Warning", score=40 + n, message=f"m{n}",
                              timestamp=datetime.now()))
        s.commit()
    rows = client.get("/alerts?limit=3").json()
    assert len(rows) == 3
    assert rows[0]["message"] == "m4"


def test_events_endpoint(client):
    with api.db.session() as s:
        s.add(EventRecord(event_type="created", path="a.txt", extension=".txt",
                          entropy=7.456, timestamp=datetime.now()))
        s.commit()
    rows = client.get("/events").json()
    assert rows[0]["event_type"] == "created"
    assert rows[0]["entropy"] == 7.46


def test_limit_validation_rejects_bad_values(client):
    assert client.get("/alerts?limit=0").status_code == 422
    assert client.get("/events?limit=100000").status_code == 422


# ---------- reports ----------


def test_reports_list_and_generation(client, tmp_path):
    incident_id = add_incident(api.db, tmp_path)

    listed = client.get("/reports").json()
    assert listed[0]["incident_id"] == incident_id
    assert listed[0]["report_ready"] is False

    r = client.get(f"/reports/{incident_id}")
    assert r.status_code == 200
    assert r.json()["report"]["threat_score"] == 80
    assert r.json()["files"]["json"].endswith(f"incident_{incident_id}.json")

    assert client.get("/reports").json()[0]["report_ready"] is True


def test_missing_report_is_404(client):
    assert client.get("/reports/999").status_code == 404


# ---------- scan ----------


def test_scan_flags_high_entropy_files(client, tmp_path, monkeypatch):
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "plain.txt").write_text("hello world " * 100)
    import os
    (watched / "random.bin").write_bytes(os.urandom(20000))
    monkeypatch.setattr(api.settings.monitor, "watch_paths", [str(watched)])

    body = client.post("/scan").json()
    assert body["scanned_files"] == 2
    assert body["high_entropy_files"] == 1
    assert body["top_files"][0]["path"].endswith("random.bin")


def test_scan_of_missing_folder_is_empty(client, tmp_path, monkeypatch):
    monkeypatch.setattr(api.settings.monitor, "watch_paths", [str(tmp_path / "nope")])
    body = client.post("/scan").json()
    assert body["scanned_files"] == 0
    assert body["high_entropy_ratio"] == 0.0


# ---------- settings ----------


def test_get_settings(client):
    body = client.get("/settings").json()
    assert body["simulation_mode"] is True
    assert {"thresholds", "weights", "levels"} <= set(body)


def test_update_settings_saves_to_file(client, tmp_path):
    r = client.post("/settings", json={"thresholds": {"avg_entropy": 6.5}})
    assert r.status_code == 200
    assert r.json()["changed"] == {"avg_entropy": 6.5}
    text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    saved = yaml.safe_load(text)
    assert saved["thresholds"]["avg_entropy"] == 6.5
    assert saved["thresholds"]["files_modified_per_minute"] == 20
    assert client.get("/settings").json()["thresholds"]["avg_entropy"] == 6.5


def test_update_settings_rejects_invalid_values(client):
    body = {"thresholds": {"avg_entropy": 99}}
    assert client.post("/settings", json=body).status_code == 422


def test_update_settings_with_nothing_is_400(client):
    assert client.post("/settings", json={"thresholds": {}}).status_code == 400


def test_simulation_mode_cannot_be_changed_through_the_api(client, tmp_path):
    body = {"simulation_mode": False, "thresholds": {"cpu_percent": 70}}
    client.post("/settings", json=body)
    text = (tmp_path / "config.yaml").read_text(encoding="utf-8")
    saved = yaml.safe_load(text)
    assert saved["app"]["simulation_mode"] is True


def test_processes_endpoint(client):
    with api.db.session() as s:
        s.add(ProcessSnapshot(pid=7, name="a.exe", cpu_percent=5.0,
                              timestamp=datetime.now()))
        s.commit()
    rows = client.get("/processes?limit=5").json()
    assert rows[0]["pid"] == 7
    assert rows[0]["name"] == "a.exe"


def test_dashboard_page_is_served(client):
    r = client.get("/dashboard")
    assert r.status_code == 200
    assert "RDRS" in r.text
    assert "text/html" in r.headers["content-type"]


def test_dashboard_404_when_page_missing(client, tmp_path, monkeypatch):
    monkeypatch.setattr(dash, "_PAGE", tmp_path / "missing.html")
    assert client.get("/dashboard").status_code == 404
