"""Threat scoring: combines detection signals into a transparent 0-100 score."""

from pydantic import BaseModel

from app.core.config import Levels, Weights
from app.detectors.detection_engine import WindowStats

NORMAL = "Normal"
WARNING = "Warning"
CRITICAL = "Critical"


class ThreatAssessment(BaseModel):
    """The result of scoring one window."""

    score: int
    level: str
    signals: list[str]
    breakdown: dict[str, int]  # points contributed by each signal that fired


def level_for(score: int, levels: Levels) -> str:
    """Map a 0-100 score to Normal / Warning / Critical."""
    if score >= levels.critical:
        return CRITICAL
    if score >= levels.warning:
        return WARNING
    return NORMAL


def calculate_score(
    stats: WindowStats,
    weights: Weights,
    levels: Levels,
    cpu_spike: bool = False,
    unknown_program: bool = False,
) -> ThreatAssessment:
    """Add up the weights of every signal that fired, capped at 100."""
    fired = {
        "rapid_encryption": stats.rapid_encryption,
        "mass_rename": stats.mass_rename,
        "high_entropy": stats.high_entropy,
        "cpu_spike": cpu_spike,
        "unknown_program": unknown_program,
    }
    breakdown = {
        name: getattr(weights, name) for name, is_on in fired.items() if is_on
    }
    score = min(sum(breakdown.values()), 100)
    return ThreatAssessment(
        score=score,
        level=level_for(score, levels),
        signals=list(breakdown),
        breakdown=breakdown,
    )