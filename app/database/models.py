"""Database tables for RDRS (SQLAlchemy ORM)."""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Parent class for all tables."""


class EventRecord(Base):
    """One file change seen by the monitor."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_type: Mapped[str] = mapped_column(String(20), index=True)
    path: Mapped[str] = mapped_column(Text)
    dest_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    extension: Mapped[str] = mapped_column(String(32), default="")
    dest_extension: Mapped[str | None] = mapped_column(String(32), nullable=True)
    entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)


class ProcessSnapshot(Base):
    """A snapshot of one running process at one moment."""

    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(primary_key=True)
    pid: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String(255))
    cpu_percent: Mapped[float] = mapped_column(Float, default=0.0)
    memory_mb: Mapped[float] = mapped_column(Float, default=0.0)
    disk_write_mb: Mapped[float] = mapped_column(Float, default=0.0)
    exe_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)


class ScoreRecord(Base):
    """A threat score calculated by the scoring engine."""

    __tablename__ = "scores"

    id: Mapped[int] = mapped_column(primary_key=True)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(20))
    signals: Mapped[str] = mapped_column(Text, default="[]")  # JSON list of fired signals
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)


class AlertRecord(Base):
    """An alert raised when a score reaches Warning or Critical."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    level: Mapped[str] = mapped_column(String(20), index=True)
    score: Mapped[int] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)


class IncidentRecord(Base):
    """A Critical incident with its evidence."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(20))
    suspect_process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    affected_files: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    evidence_dir: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="open")
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)