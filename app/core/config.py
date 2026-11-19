"""Configuration loader for RDRS: reads config.yaml into typed objects."""

from pathlib import Path

import yaml
from pydantic import BaseModel


class AppSettings(BaseModel):
    name: str = "RDRS"
    simulation_mode: bool = True


class MonitorSettings(BaseModel):
    watch_paths: list[str] = ["./data/sandbox"]
    window_seconds: int = 60


class Thresholds(BaseModel):
    files_modified_per_minute: int = 20
    renames_per_minute: int = 15
    extension_changes_per_minute: int = 10
    avg_entropy: float = 7.0
    cpu_percent: float = 80


class Weights(BaseModel):
    rapid_encryption: int = 40
    mass_rename: int = 30
    high_entropy: int = 25
    cpu_spike: int = 15
    unknown_program: int = 10


class Levels(BaseModel):
    warning: int = 40
    critical: int = 70


class ResponseSettings(BaseModel):
    terminate_process: bool = False
    quarantine_dir: str = "./data/quarantine"


class Paths(BaseModel):
    database: str = "./data/rdrs.db"
    logs_dir: str = "./logs"


class Settings(BaseModel):
    app: AppSettings = AppSettings()
    monitor: MonitorSettings = MonitorSettings()
    thresholds: Thresholds = Thresholds()
    weights: Weights = Weights()
    levels: Levels = Levels()
    response: ResponseSettings = ResponseSettings()
    paths: Paths = Paths()


def load_config(path: str = "config.yaml") -> Settings:
    """Read a YAML file and return validated settings."""
    text = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    return Settings(**data)