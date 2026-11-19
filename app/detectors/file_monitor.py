"""Real-time file monitor built on watchdog."""

import os
import threading
from collections.abc import Callable
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from app.core.logger import get_logger
from app.core.models import EventType, FileEvent

log = get_logger("events")


class RDRSEventHandler(FileSystemEventHandler):
    """Turns raw watchdog events into FileEvent objects and counts them."""

    def __init__(self, callback: Callable[[FileEvent], None] | None = None) -> None:
        super().__init__()
        self._callback = callback
        self._lock = threading.Lock()
        self._counts: dict[EventType, int] = {t: 0 for t in EventType}

    def _emit(self, event_type: EventType, src: str, dest: str | None = None) -> None:
        event = FileEvent(
            event_type=event_type,
            path=src,
            extension=Path(src).suffix.lower(),
            dest_path=dest,
            dest_extension=Path(dest).suffix.lower() if dest else None,
        )
        with self._lock:
            self._counts[event_type] += 1
        log.info(f"{event_type.value} | {src}" + (f" -> {dest}" if dest else ""))
        if self._callback:
            self._callback(event)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit(EventType.CREATED, os.fsdecode(event.src_path))

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit(EventType.MODIFIED, os.fsdecode(event.src_path))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit(EventType.DELETED, os.fsdecode(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit(
                EventType.MOVED,
                os.fsdecode(event.src_path),
                os.fsdecode(event.dest_path),
            )

    @property
    def summary(self) -> dict[str, int]:
        """Event counts by type, e.g. {'created': 3, 'modified': 5, ...}."""
        with self._lock:
            return {t.value: n for t, n in self._counts.items()}

    @property
    def total(self) -> int:
        """Total number of events seen so far."""
        with self._lock:
            return sum(self._counts.values())


class FileMonitor:
    """Watches one or more folders and reports every file change."""

    def __init__(
        self,
        paths: list[str],
        callback: Callable[[FileEvent], None] | None = None,
    ) -> None:
        self._paths = paths
        self._handler = RDRSEventHandler(callback)
        self._observer = PollingObserver(timeout=1) if os.environ.get("RDRS_POLLING") == "1" else Observer()

    def start(self) -> None:
        """Begin watching all configured folders (runs in a background thread)."""
        for p in self._paths:
            full = Path(p).resolve()
            full.mkdir(parents=True, exist_ok=True)
            self._observer.schedule(self._handler, str(full), recursive=True)
            log.info(f"Watching {full}")
        self._observer.start()

    def stop(self) -> None:
        """Stop watching and wait for the background thread to finish."""
        self._observer.stop()
        self._observer.join()

    @property
    def summary(self) -> dict[str, int]:
        return self._handler.summary

    @property
    def total(self) -> int:
        return self._handler.total