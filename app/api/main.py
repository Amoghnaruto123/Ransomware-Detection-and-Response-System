"""REST API for RDRS: JSON views of what the monitor has stored."""

from datetime import datetime, timedelta
from itertools import islice
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.core.config import Settings, load_config
from app.core.entropy import file_entropy
from app.database.db import Database
from app.database.models import (
    AlertRecord,
    EventRecord,
    IncidentRecord,
    ScoreRecord,
)
from app.reports.generator import build_report, generate_reports

CONFIG_PATH = "config.yaml"
REPORTS_DIR = "./data/reports"
MAX_SCAN_FILES = 2000  # safety cap so a scan can never run away

settings = load_config(CONFIG_PATH)
db = Database(settings.paths.database)

app = FastAPI(
    title="RDRS API",
    description="Ransomware Detection and Response System (defensive tool)",
    version="1.0",
)


def alert_to_dict(a: AlertRecord) -> dict:
    """Convert an alert row into a JSON-friendly dictionary."""
    return {
        "id": a.id,
        "level": a.level,
        "score": a.score,
        "message": a.message,
        "timestamp": a.timestamp.isoformat(),
    }


def event_to_dict(e: EventRecord) -> dict:
    """Convert a file event row into a JSON-friendly dictionary."""
    return {
        "id": e.id,
        "event_type": e.event_type,
        "path": e.path,
        "dest_path": e.dest_path,
        "extension": e.extension,
        "dest_extension": e.dest_extension,
        "entropy": round(e.entropy, 2) if e.entropy is not None else None,
        "timestamp": e.timestamp.isoformat(),
    }


@app.get("/health")
def health() -> dict:
    """Liveness check: if this answers, the API is running."""
    return {"status": "ok", "time": datetime.now().isoformat()}


@app.get("/status")
def status() -> dict:
    """Current threat level plus headline numbers."""
    fresh_for = timedelta(seconds=settings.monitor.window_seconds * 2)
    with db.session() as s:
        latest = s.scalars(
            select(ScoreRecord).order_by(ScoreRecord.id.desc()).limit(1)
        ).first()
        last_event = s.scalars(
            select(EventRecord).order_by(EventRecord.id.desc()).limit(1)
        ).first()

    is_recent = latest is not None and datetime.now() - latest.timestamp <= fresh_for
    return {
        "threat_level": latest.level if is_recent else "Normal",
        "threat_score": latest.score if is_recent else 0,
        "simulation_mode": settings.app.simulation_mode,
        "watching": settings.monitor.watch_paths,
        "totals": {
            "events": db.count(EventRecord),
            "alerts": db.count(AlertRecord),
            "incidents": db.count(IncidentRecord),
        },
        "last_event_time": last_event.timestamp.isoformat() if last_event else None,
    }


@app.get("/alerts")
def alerts(limit: int = Query(20, ge=1, le=200)) -> list[dict]:
    """Newest alerts first."""
    with db.session() as s:
        stmt = select(AlertRecord).order_by(AlertRecord.id.desc()).limit(limit)
        return [alert_to_dict(a) for a in s.scalars(stmt)]


@app.get("/events")
def events(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
    """Newest file events first."""
    return [event_to_dict(e) for e in db.recent_events(limit)]


@app.get("/reports")
def list_reports(limit: int = Query(20, ge=1, le=200)) -> list[dict]:
    """Newest incidents first, with whether a report file already exists."""
    folder = Path(REPORTS_DIR).resolve()
    with db.session() as s:
        stmt = select(IncidentRecord).order_by(IncidentRecord.id.desc()).limit(limit)
        return [
            {
                "incident_id": i.id,
                "level": i.level,
                "score": i.score,
                "suspect_process": i.suspect_process,
                "status": i.status,
                "timestamp": i.timestamp.isoformat(),
                "report_ready": (folder / f"incident_{i.id}.json").exists(),
            }
            for i in s.scalars(stmt)
        ]


@app.get("/reports/{incident_id}")
def get_report(incident_id: int) -> dict:
    """Build the report for one incident, save JSON + CSV files, return it."""
    report = build_report(db, incident_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    files = generate_reports(db, incident_id, REPORTS_DIR)
    return {"files": files, "report": report}


def _iter_files(roots: list[str]):
    """Yield every file under the watched folders."""
    for p in roots:
        root = Path(p).resolve()
        if root.is_dir():
            for f in root.rglob("*"):
                if f.is_file():
                    yield f


@app.post("/scan")
def scan() -> dict:
    """Read-only scan: measure entropy of files in the watched folders."""
    limit = settings.thresholds.avg_entropy
    readings: list[tuple[float, str]] = []
    for f in islice(_iter_files(settings.monitor.watch_paths), MAX_SCAN_FILES):
        readings.append((file_entropy(f), str(f)))

    high = sorted((r for r in readings if r[0] >= limit), reverse=True)
    return {
        "scanned_files": len(readings),
        "entropy_threshold": limit,
        "high_entropy_files": len(high),
        "high_entropy_ratio": round(len(high) / len(readings), 2) if readings else 0.0,
        "top_files": [{"path": p, "entropy": round(e, 2)} for e, p in high[:10]],
        "note": "Read-only scan. Compressed files (zip, jpg) also score high.",
    }


class ThresholdsUpdate(BaseModel):
    """Thresholds that may be changed; omit a field to leave it as it is."""

    files_modified_per_minute: int | None = Field(None, ge=1, le=10000)
    renames_per_minute: int | None = Field(None, ge=1, le=10000)
    extension_changes_per_minute: int | None = Field(None, ge=1, le=10000)
    avg_entropy: float | None = Field(None, ge=0, le=8)
    cpu_percent: float | None = Field(None, ge=1, le=100)


class SettingsUpdate(BaseModel):
    """Body of POST /settings."""

    thresholds: ThresholdsUpdate


@app.get("/settings")
def get_settings() -> dict:
    """Show the current thresholds, weights and levels."""
    return {
        "simulation_mode": settings.app.simulation_mode,
        "thresholds": settings.thresholds.model_dump(),
        "weights": settings.weights.model_dump(),
        "levels": settings.levels.model_dump(),
    }


@app.post("/settings")
def update_settings(update: SettingsUpdate) -> dict:
    """Change detection thresholds and save them to config.yaml.

    Safety: simulation mode and process termination can NOT be changed here.
    """
    changes = update.thresholds.model_dump(exclude_none=True)
    if not changes:
        raise HTTPException(status_code=400, detail="No thresholds supplied")

    data = yaml.safe_load(Path(CONFIG_PATH).read_text(encoding="utf-8")) or {}
    data.setdefault("thresholds", {}).update(changes)
    checked = Settings(**data)  # raises if the result would be invalid

    Path(CONFIG_PATH).write_text(
        yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
    )
    settings.thresholds = checked.thresholds
    return {
        "saved": True,
        "changed": changes,
        "note": "Restart the monitor (python -m app.main) to apply the new values.",
    }

from app.api.dashboard_routes import router as dashboard_router  # noqa: E402
app.include_router(dashboard_router)
