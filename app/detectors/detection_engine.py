"""Detection engine: analyses recent file events in a sliding time window."""

import threading
from collections import deque
from datetime import datetime, timedelta

from pydantic import BaseModel

from app.core.config import Thresholds
from app.core.models import EventType, FileEvent

MIN_ENTROPY_SAMPLES = 5  # need at least this many readings to trust the average


class WindowStats(BaseModel):
    """What the engine sees in the current window."""

    window_seconds: int
    modified_files: int = 0
    renames: int = 0
    extension_changes: int = 0
    avg_entropy: float = 0.0
    entropy_samples: int = 0
    rapid_encryption: bool = False
    mass_rename: bool = False
    high_entropy: bool = False
    affected_files: list[str] = []


class DetectionEngine:
    """Keeps a sliding window of events and checks it against the thresholds."""

    def __init__(self, thresholds: Thresholds, window_seconds: int = 60) -> None:
        self._t = thresholds
        self._window_seconds = window_seconds
        self._window = timedelta(seconds=window_seconds)
        self._events: deque[tuple[FileEvent, float | None]] = deque()
        self._lock = threading.Lock()

    def add_event(self, event: FileEvent, entropy: float | None = None) -> WindowStats:
        """Add one event to the window and return the freshly recomputed stats."""
        with self._lock:
            self._events.append((event, entropy))
        return self.stats()

    def _prune(self, now: datetime) -> None:
        """Drop events older than the window (caller must hold the lock)."""
        while self._events and now - self._events[0][0].timestamp > self._window:
            self._events.popleft()

    def stats(self) -> WindowStats:
        """Recount everything in the current window and check the thresholds."""
        with self._lock:
            self._prune(datetime.now())
            events = list(self._events)

        modified: set[str] = set()
        moved_from: set[str] = set()
        moved_to: set[str] = set()
        renames = 0
        ext_changes = 0
        entropies: list[float] = []

        for event, entropy in events:
            if event.event_type in (EventType.CREATED, EventType.MODIFIED):
                modified.add(event.path)
            elif event.event_type == EventType.MOVED:
                renames += 1
                moved_from.add(event.path)
                if event.dest_path:
                    moved_to.add(event.dest_path)
                if event.extension_changed:
                    ext_changes += 1
            if entropy is not None and event.event_type != EventType.DELETED:
                entropies.append(entropy)

        avg = sum(entropies) / len(entropies) if entropies else 0.0
        scale = 60 / self._window_seconds  # convert window counts to "per minute"
        t = self._t

        return WindowStats(
            window_seconds=self._window_seconds,
            modified_files=len(modified),
            renames=renames,
            extension_changes=ext_changes,
            avg_entropy=round(avg, 2),
            entropy_samples=len(entropies),
            rapid_encryption=len(modified) * scale >= t.files_modified_per_minute,
            mass_rename=(
                renames * scale >= t.renames_per_minute
                or ext_changes * scale >= t.extension_changes_per_minute
            ),
            high_entropy=(
                len(entropies) >= MIN_ENTROPY_SAMPLES and avg >= t.avg_entropy
            ),
            affected_files=sorted((modified - moved_from) | moved_to),
        )