"""Detection pipeline: file event -> window stats -> threat score -> response."""

import threading

from app.core.config import Settings
from app.core.models import FileEvent
from app.database.db import Database
from app.database.models import ProcessSnapshot
from app.detectors.detection_engine import DetectionEngine, WindowStats
from app.detectors.response import IncidentResponder
from app.detectors.scoring import NORMAL, ThreatAssessment, calculate_score

# Programs installed in these folders are treated as "known"
TRUSTED_DIRS = ("c:\\windows", "c:\\program files", "c:\\program files (x86)")


def is_trusted(exe_path: str | None) -> bool:
    """True if the program lives in a standard system or install folder."""
    if not exe_path:
        return False
    return exe_path.lower().startswith(TRUSTED_DIRS)


class Pipeline:
    """Runs every file event through detection, scoring and response."""

    def __init__(self, db: Database, settings: Settings) -> None:
        self._settings = settings
        self._engine = DetectionEngine(
            settings.thresholds, settings.monitor.window_seconds
        )
        self._responder = IncidentResponder(db, settings)
        self._processes: list[ProcessSnapshot] = []
        self._lock = threading.Lock()
        self.latest = ThreatAssessment(
            score=0, level=NORMAL, signals=[], breakdown={}
        )
        self.latest_stats: WindowStats | None = None

    def update_processes(self, snapshots: list[ProcessSnapshot]) -> None:
        """Receive the newest process snapshots (called by the process thread)."""
        with self._lock:
            self._processes = list(snapshots)

    def _process_context(self) -> tuple[str | None, bool, bool]:
        """Return (suspect name, cpu_spike, unknown_program) from the snapshots."""
        with self._lock:
            snaps = list(self._processes)
        if not snaps:
            return None, False, False
        top = max(snaps, key=lambda p: (p.cpu_percent, p.disk_write_mb))
        cpu_spike = top.cpu_percent >= self._settings.thresholds.cpu_percent
        return top.name, cpu_spike, not is_trusted(top.exe_path)

    def process_event(
        self, event: FileEvent, entropy: float | None = None
    ) -> ThreatAssessment:
        """Analyse one event and respond if the threat level calls for it."""
        stats = self._engine.add_event(event, entropy)

        suspect: str | None = None
        cpu_spike = False
        unknown = False
        file_signal = stats.rapid_encryption or stats.mass_rename or stats.high_entropy
        if file_signal:  # process clues only matter once file activity looks bad
            suspect, cpu_spike, unknown = self._process_context()

        assessment = calculate_score(
            stats,
            self._settings.weights,
            self._settings.levels,
            cpu_spike=cpu_spike,
            unknown_program=unknown,
        )
        self._responder.respond(assessment, stats, suspect)
        self.latest = assessment
        self.latest_stats = stats
        return assessment