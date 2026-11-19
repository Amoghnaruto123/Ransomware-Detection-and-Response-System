"""Incident reports: builds a report for one incident and saves JSON and CSV."""

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from app.database.db import Database
from app.database.models import EventRecord, IncidentRecord

TIMELINE_BEFORE = timedelta(seconds=120)  # events shown before the incident
TIMELINE_AFTER = timedelta(seconds=15)  # and shortly after it
MAX_TIMELINE = 500

RECOMMENDATIONS = {
    "rapid_encryption": "Many files were changed within seconds. Check whether a "
    "backup, archive extraction or installer explains it; if not, isolate the machine.",
    "mass_rename": "Files were renamed in bulk, often with a new extension. Compare "
    "the new extensions with known ransomware extensions.",
    "high_entropy": "New file contents look random (encrypted or compressed). Open "
    "the evidence copies and check whether they are still readable.",
    "cpu_spike": "A process is using unusually high CPU, which is common while "
    "encrypting. Review that process.",
    "unknown_program": "The most active program runs from a non-standard location. "
    "Verify its path, publisher and parent process.",
}
GENERAL_RECOMMENDATIONS = [
    "Disconnect the affected machine from the network to stop any spread.",
    "Do not delete or modify the original files; the quarantine folder holds copies.",
    "Restore affected files from a clean backup after the cause is understood.",
]


def _load_manifest(evidence_dir: str | None) -> dict:
    """Read the manifest.json that the responder saved with the evidence."""
    if not evidence_dir:
        return {}
    try:
        text = (Path(evidence_dir) / "manifest.json").read_text(encoding="utf-8")
        return json.loads(text)
    except (OSError, ValueError):
        return {}


def build_report(db: Database, incident_id: int) -> dict | None:
    """Collect everything about one incident. Returns None if it doesn't exist."""
    with db.session() as s:
        inc = s.get(IncidentRecord, incident_id)
        if inc is None:
            return None

        stmt = (
            select(EventRecord)
            .where(
                EventRecord.timestamp >= inc.timestamp - TIMELINE_BEFORE,
                EventRecord.timestamp <= inc.timestamp + TIMELINE_AFTER,
            )
            .order_by(EventRecord.timestamp)
            .limit(MAX_TIMELINE)
        )
        timeline = [
            {
                "time": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "path": e.path,
                "dest_path": e.dest_path,
                "entropy": round(e.entropy, 2) if e.entropy is not None else None,
            }
            for e in s.scalars(stmt)
        ]

        manifest = _load_manifest(inc.evidence_dir)
        signals = manifest.get("signals", {})
        recommendations = [RECOMMENDATIONS[n] for n in signals if n in RECOMMENDATIONS]
        if inc.suspect_process:
            recommendations.append(
                f"Investigate the suspect process '{inc.suspect_process}' "
                "(it is a best guess based on activity, not proof)."
            )
        recommendations.extend(GENERAL_RECOMMENDATIONS)

        return {
            "incident_id": inc.id,
            "generated_at": datetime.now().isoformat(),
            "detected_at": inc.timestamp.isoformat(),
            "threat_score": inc.score,
            "threat_level": inc.level,
            "status": inc.status,
            "suspect_process": inc.suspect_process,
            "signals": signals,
            "affected_files": json.loads(inc.affected_files or "[]"),
            "files_copied": manifest.get("files_copied", []),
            "evidence_dir": inc.evidence_dir,
            "timeline": timeline,
            "recommendations": recommendations,
        }


def write_json(report: dict, path: Path) -> None:
    """Save the report as pretty-printed JSON."""
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_csv(report: dict, path: Path) -> None:
    """Save the report as one flat table: section, time, item, detail."""
    rows: list[list] = [["section", "time", "item", "detail"]]
    detected = report["detected_at"]

    summary = {
        "incident_id": report["incident_id"],
        "threat_level": report["threat_level"],
        "threat_score": report["threat_score"],
        "status": report["status"],
        "suspect_process": report["suspect_process"],
        "evidence_dir": report["evidence_dir"],
    }
    rows += [["summary", detected, k, v] for k, v in summary.items()]
    rows += [["signal", detected, n, f"{p} points"] for n, p in report["signals"].items()]
    rows += [["affected_file", detected, f, ""] for f in report["affected_files"]]
    for e in report["timeline"]:
        item = e["path"] + (f" -> {e['dest_path']}" if e["dest_path"] else "")
        detail = f"entropy={e['entropy']}" if e["entropy"] is not None else ""
        rows.append(["timeline", e["time"], f"{e['event_type']}: {item}", detail])
    rows += [["recommendation", detected, r, ""] for r in report["recommendations"]]

    with path.open("w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(rows)


def generate_reports(
    db: Database, incident_id: int, out_dir: str = "./data/reports"
) -> dict[str, str] | None:
    """Build a report and save it as JSON and CSV. Returns the file paths."""
    report = build_report(db, incident_id)
    if report is None:
        return None
    folder = Path(out_dir).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    json_path = folder / f"incident_{incident_id}.json"
    csv_path = folder / f"incident_{incident_id}.csv"
    write_json(report, json_path)
    write_csv(report, csv_path)
    return {"json": str(json_path), "csv": str(csv_path)}