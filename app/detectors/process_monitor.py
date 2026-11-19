"""Process monitor: takes snapshots of running processes using psutil."""

import time
from datetime import datetime

import psutil

from app.database.models import ProcessSnapshot

# Errors psutil raises for protected or vanished processes
_SKIP = (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess)
_MB = 1024 * 1024

# PID 0 is Windows' "System Idle Process": it reports unused CPU time, not a
# real program, so it would always look like the busiest process.
_IGNORED_PIDS = {0}


def take_snapshot(interval: float = 0.5) -> list[ProcessSnapshot]:
    """Return one ProcessSnapshot per readable running process.

    CPU usage needs two readings a moment apart, so we prime every process,
    wait `interval` seconds, then read the real values.
    """
    procs: list[psutil.Process] = []
    for p in psutil.process_iter():
        if p.pid in _IGNORED_PIDS:
            continue
        try:
            p.cpu_percent(None)  # first call only starts the measurement
            procs.append(p)
        except _SKIP:
            continue

    time.sleep(interval)
    now = datetime.now()
    cores = psutil.cpu_count() or 1
    snapshots: list[ProcessSnapshot] = []

    for p in procs:
        try:
            with p.oneshot():  # read many fields in one fast pass
                name = p.name()
                cpu = p.cpu_percent(None) / cores  # normalise to 0-100% of the whole CPU
                memory = p.memory_info().rss / _MB
                ppid = p.ppid()
        except _SKIP:
            continue  # protected or already gone: skip it gracefully

        try:
            disk_write = p.io_counters().write_bytes / _MB
        except (*_SKIP, AttributeError, OSError):
            disk_write = 0.0

        try:
            exe = p.exe() or None
        except (*_SKIP, OSError):
            exe = None

        try:
            parent_name = psutil.Process(ppid).name() if ppid else None
        except _SKIP:
            parent_name = None

        snapshots.append(
            ProcessSnapshot(
                pid=p.pid,
                name=name,
                cpu_percent=round(cpu, 2),
                memory_mb=round(memory, 2),
                disk_write_mb=round(disk_write, 2),
                exe_path=exe,
                parent_pid=ppid or None,
                parent_name=parent_name,
                timestamp=now,
            )
        )
    return snapshots