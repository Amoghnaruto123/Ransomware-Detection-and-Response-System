"""Incident response: alerts, incident records and evidence copies.

Safety: this module never terminates a process and never modifies or
deletes the original files. Evidence is copied only.
"""

import json
import shutil
import time
from datetime import datetime
from pathlib import Path

from app.core.config import Settings
from app.core.logger import get_logger
from app.database.db import Database
from app.database.models import AlertRecord, IncidentRecord, ScoreRecord
from app.detectors.detection_engine import WindowStats
from app.detectors.scoring import CRITICAL, NORMAL, ThreatAssessment

MAX_EVIDENCE_FILES = 200  # cap how many files one incident copies
COOLDOWN_SECONDS = 60  # don't raise the same level again within this time

alert_log = get_logger("alerts")
audit_log = get_logger("audit")


class IncidentResponder:
    """Turns a threat assessment into alerts, incidents and saved evidence."""

    def __init__(
        self, db: Database, settings: Settings, cooldown: int = COOLDOWN_SECONDS
    ) -> None:
        self._db = db
        self._settings = settings
        self._cooldown = cooldown
        self._last_response: dict[str, float] = {}

    def _in_cooldown(self, level: str) -> bool:
        last = self._last_response.get(level)
        return last is not None and time.monotonic() - last < self._cooldown

    def respond(
        self,
        assessment: ThreatAssessment,
        stats: WindowStats,
        suspect_process: str | None = None,
    ) -> int | None:
        """Handle one assessment. Returns the incident id if one was created."""
        level = assessment.level
        if level == NORMAL or self._in_cooldown(level):
            return None
        self._last_response[level] = time.monotonic()
        now = datetime.now()

        message = (
            f"{level} | score={assessment.score} | "
            f"signals={', '.join(assessment.signals)}"
        )
        with self._db.session() as s:
            s.add(
                ScoreRecord(
                    score=assessment.score,
                    level=level,
                    signals=json.dumps(assessment.signals),
                    timestamp=now,
                )
            )
            s.add(
                AlertRecord(
                    level=level, score=assessment.score, message=message, timestamp=now
                )
            )
            s.commit()

        if level == CRITICAL:
            alert_log.critical(message)
        else:
            alert_log.warning(message)
        audit_log.info(f"Alert raised: {message}")

        if level != CRITICAL:
            return None
        return self._handle_critical(assessment, stats, suspect_process, now)

    def _handle_critical(
        self,
        assessment: ThreatAssessment,
        stats: WindowStats,
        suspect: str | None,
        now: datetime,
    ) -> int:
        """Create the incident record and copy the evidence."""
        with self._db.session() as s:
            incident = IncidentRecord(
                score=assessment.score,
                level=assessment.level,
                suspect_process=suspect,
                affected_files=json.dumps(stats.affected_files),
                status="open",
                timestamp=now,
            )
            s.add(incident)
            s.flush()  # assigns incident.id without finishing the transaction
            incident_id = incident.id
            evidence = self._copy_evidence(incident_id, assessment, stats, suspect, now)
            incident.evidence_dir = str(evidence)
            s.commit()

        audit_log.info(
            f"Incident #{incident_id} created | suspect={suspect} | "
            f"files={len(stats.affected_files)} | evidence={evidence}"
        )

        if self._settings.response.terminate_process:
            if self._settings.app.simulation_mode:
                audit_log.warning(
                    f"SIMULATION: would terminate '{suspect}' (nothing was killed)"
                )
            else:
                audit_log.warning(
                    "Process termination is not implemented; nothing was killed"
                )
        return incident_id

    def _copy_evidence(
        self,
        incident_id: int,
        assessment: ThreatAssessment,
        stats: WindowStats,
        suspect: str | None,
        now: datetime,
    ) -> Path:
        """Copy affected files into a new quarantine folder. Originals stay put."""
        base = Path(self._settings.response.quarantine_dir).resolve()
        folder = base / f"incident_{incident_id}_{now:%Y%m%d_%H%M%S}"
        folder.mkdir(parents=True, exist_ok=True)

        copied: list[str] = []
        for i, name in enumerate(stats.affected_files[:MAX_EVIDENCE_FILES]):
            src = Path(name)
            try:
                if not src.is_file() or base in src.resolve().parents:
                    continue  # missing, or already inside quarantine
                shutil.copy2(src, folder / f"{i:03d}_{src.name}")  # copy, never move
                copied.append(str(src))
            except OSError as exc:
                audit_log.warning(f"Could not copy evidence {src}: {exc}")

        manifest = {
            "incident_id": incident_id,
            "time": now.isoformat(),
            "score": assessment.score,
            "level": assessment.level,
            "signals": assessment.breakdown,
            "suspect_process": suspect,
            "affected_files": stats.affected_files,
            "files_copied": copied,
        }
        (folder / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        return folder