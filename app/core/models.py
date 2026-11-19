"""Shared data models used across RDRS."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """The four kinds of file change we track."""

    CREATED = "created"
    MODIFIED = "modified"
    MOVED = "moved"
    DELETED = "deleted"


class FileEvent(BaseModel):
    """One observed change to a file."""

    event_type: EventType
    path: str
    timestamp: datetime = Field(default_factory=datetime.now)
    extension: str = ""
    dest_path: str | None = None  # new path, only for MOVED (rename) events
    dest_extension: str | None = None  # new extension, only for MOVED events

    @property
    def extension_changed(self) -> bool:
        """True if a rename changed the file extension (e.g. .txt -> .locked)."""
        return (
            self.event_type == EventType.MOVED
            and self.dest_extension is not None
            and self.dest_extension != self.extension
        )