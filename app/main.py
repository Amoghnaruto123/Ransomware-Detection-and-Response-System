"""RDRS entry point: monitors files and processes, then detects and responds."""

import argparse
import threading
import time
from collections.abc import Callable

from app.core.config import load_config
from app.core.entropy import file_entropy
from app.core.logger import get_logger, setup_logging
from app.core.models import EventType, FileEvent
from app.database.db import Database
from app.database.models import EventRecord, ProcessSnapshot
from app.detectors.file_monitor import FileMonitor
from app.detectors.pipeline import Pipeline
from app.detectors.process_monitor import take_snapshot

SNAPSHOT_INTERVAL = 10  # seconds between process snapshots
TOP_PROCESSES = 30  # keep only the busiest processes to limit database growth

log = get_logger("system")


def parse_args() -> argparse.Namespace:
    """Read command-line options."""
    parser = argparse.ArgumentParser(
        description="Ransomware Detection and Response System (RDRS)"
    )
    parser.add_argument(
        "--watch", nargs="+", help="folder(s) to watch (overrides config.yaml)"
    )
    parser.add_argument("--config", default="config.yaml", help="path to config file")
    return parser.parse_args()


def measure_entropy(path: str, retries: int = 3, delay: float = 0.1) -> float | None:
    """Entropy of a file, retrying briefly if it is still empty or locked.

    Returns None if the file stays empty or unreadable, so that averages
    ignore it instead of counting a false 0.0.
    """
    for _ in range(retries):
        value = file_entropy(path)
        if value > 0.0:
            return value
        time.sleep(delay)
    return None


def make_event_handler(db: Database, pipeline: Pipeline) -> Callable[[FileEvent], None]:
    """Build the function that runs for every file event."""

    def handle(event: FileEvent) -> None:
        try:
            entropy = None
            if event.event_type in (EventType.CREATED, EventType.MODIFIED):
                entropy = measure_entropy(event.path)
            elif event.event_type == EventType.MOVED and event.dest_path:
                entropy = measure_entropy(event.dest_path)  # file now lives here
            db.save_event(event, entropy)
            pipeline.process_event(event, entropy)
        except Exception:
            log.exception("Failed to process file event")

    return handle


def plain_copy(p: ProcessSnapshot) -> ProcessSnapshot:
    """Copy a snapshot so the pipeline's copy is independent of the database."""
    return ProcessSnapshot(
        pid=p.pid,
        name=p.name,
        cpu_percent=p.cpu_percent,
        memory_mb=p.memory_mb,
        disk_write_mb=p.disk_write_mb,
        exe_path=p.exe_path,
        parent_pid=p.parent_pid,
        parent_name=p.parent_name,
        timestamp=p.timestamp,
    )


def process_loop(
    db: Database, pipeline: Pipeline, stop: threading.Event, interval: int
) -> None:
    """Take a process snapshot every `interval` seconds until told to stop."""
    while not stop.is_set():
        try:
            snaps = take_snapshot()
            snaps.sort(key=lambda p: (p.cpu_percent, p.disk_write_mb), reverse=True)
            top = snaps[:TOP_PROCESSES]
            pipeline.update_processes([plain_copy(p) for p in top])
            db.save_processes(top)
        except Exception:
            log.exception("Failed to take process snapshot")
        stop.wait(interval)  # sleeps, but wakes instantly when stop is set


def main() -> None:
    """Start monitoring and show a live status line until Ctrl+C."""
    args = parse_args()
    settings = load_config(args.config)
    setup_logging(settings.paths.logs_dir)

    db = Database(settings.paths.database)
    pipeline = Pipeline(db, settings)
    paths = args.watch or settings.monitor.watch_paths

    monitor = FileMonitor(paths, callback=make_event_handler(db, pipeline))
    stop = threading.Event()
    proc_thread = threading.Thread(
        target=process_loop,
        args=(db, pipeline, stop, SNAPSHOT_INTERVAL),
        daemon=True,
    )

    monitor.start()
    proc_thread.start()
    log.info(f"RDRS started | simulation_mode={settings.app.simulation_mode}")
    print(f"Watching: {paths}  (press Ctrl+C to stop)")

    try:
        while True:
            now = pipeline.latest
            print(
                f"\rEvents: {monitor.total} | Threat: {now.level} ({now.score}) "
                f"| DB events: {db.count(EventRecord)}          ",
                end="",
                flush=True,
            )
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        monitor.stop()
        proc_thread.join(timeout=5)
        log.info("RDRS stopped")
        print(f"\nStopped. Final count: {monitor.total}")


if __name__ == "__main__":
    main()