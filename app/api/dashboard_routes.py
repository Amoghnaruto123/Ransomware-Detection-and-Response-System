"""Dashboard routes: serves the dashboard page and process data."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select

from app.core.config import load_config
from app.database.db import Database
from app.database.models import ProcessSnapshot

router = APIRouter()
_settings = load_config()
_db = Database(_settings.paths.database)
_PAGE = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"


@router.get("/processes")
def processes(limit: int = Query(30, ge=1, le=200)) -> list[dict]:
    """Most recent process snapshots, newest first."""
    with _db.session() as s:
        stmt = select(ProcessSnapshot).order_by(ProcessSnapshot.id.desc()).limit(limit)
        return [
            {
                "pid": p.pid,
                "name": p.name,
                "cpu_percent": p.cpu_percent,
                "memory_mb": p.memory_mb,
                "disk_write_mb": p.disk_write_mb,
                "exe_path": p.exe_path,
                "timestamp": p.timestamp.isoformat(),
            }
            for p in s.scalars(stmt)
        ]


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard() -> str:
    """Serve the dashboard web page."""
    if not _PAGE.is_file():
        raise HTTPException(status_code=404, detail="Dashboard page not built yet")
    return _PAGE.read_text(encoding="utf-8")