"""Database access layer: one class that saves and reads RDRS data."""

from pathlib import Path

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.models import FileEvent
from app.database.models import Base, EventRecord, ProcessSnapshot


class Database:
    """Wraps the SQLite connection and offers simple save/read methods."""

    def __init__(self, db_path: str = "./data/rdrs.db") -> None:
        full = Path(db_path).resolve()
        full.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: the file monitor runs in a background thread
        self._engine = create_engine(
            f"sqlite:///{full}", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(self._engine)
        self._session_factory = sessionmaker(bind=self._engine)

    def session(self) -> Session:
        """Open a new database session (use it in a `with` block)."""
        return self._session_factory()

    def save_event(self, event: FileEvent, entropy: float | None = None) -> None:
        """Store one file event, with its entropy if we measured it."""
        record = EventRecord(
            event_type=event.event_type.value,
            path=event.path,
            dest_path=event.dest_path,
            extension=event.extension,
            dest_extension=event.dest_extension,
            entropy=entropy,
            timestamp=event.timestamp,
        )
        with self.session() as s:
            s.add(record)
            s.commit()

    def save_processes(self, snapshots: list[ProcessSnapshot]) -> None:
        """Store many process snapshots in a single commit."""
        with self.session() as s:
            s.add_all(snapshots)
            s.commit()

    def count(self, table) -> int:
        """Return the number of rows in a table, e.g. db.count(EventRecord)."""
        with self.session() as s:
            return s.scalar(select(func.count()).select_from(table)) or 0

    def recent_events(self, limit: int = 20) -> list[EventRecord]:
        """Return the newest events first."""
        with self.session() as s:
            stmt = select(EventRecord).order_by(EventRecord.id.desc()).limit(limit)
            return list(s.scalars(stmt))