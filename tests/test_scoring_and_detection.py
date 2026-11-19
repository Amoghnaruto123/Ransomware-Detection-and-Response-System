"""Unit tests for threat scoring and the sliding-window detection engine."""

from datetime import datetime, timedelta

import pytest

from app.core.config import Levels, Thresholds, Weights
from app.core.models import EventType, FileEvent
from app.detectors.detection_engine import DetectionEngine, WindowStats
from app.detectors.scoring import (
    CRITICAL,
    NORMAL,
    WARNING,
    calculate_score,
    level_for,
)

WEIGHTS = Weights()
LEVELS = Levels()


def stats(**flags) -> WindowStats:
    return WindowStats(window_seconds=60, **flags)


# ---------- scoring ----------


def test_no_signals_is_normal_zero():
    result = calculate_score(stats(), WEIGHTS, LEVELS)
    assert (result.score, result.level, result.signals) == (0, NORMAL, [])


def test_single_signal_uses_its_weight():
    result = calculate_score(stats(rapid_encryption=True), WEIGHTS, LEVELS)
    assert result.score == 40
    assert result.level == WARNING
    assert result.breakdown == {"rapid_encryption": 40}


def test_rapid_plus_rename_is_critical():
    result = calculate_score(
        stats(rapid_encryption=True, mass_rename=True), WEIGHTS, LEVELS
    )
    assert result.score == 70
    assert result.level == CRITICAL


def test_score_is_capped_at_100():
    result = calculate_score(
        stats(rapid_encryption=True, mass_rename=True, high_entropy=True),
        WEIGHTS,
        LEVELS,
        cpu_spike=True,
        unknown_program=True,
    )
    assert sum(result.breakdown.values()) == 120
    assert result.score == 100


def test_process_signals_alone_stay_normal():
    result = calculate_score(
        stats(), WEIGHTS, LEVELS, cpu_spike=True, unknown_program=True
    )
    assert result.score == 25
    assert result.level == NORMAL


def test_custom_weights_are_respected():
    result = calculate_score(
        stats(mass_rename=True), Weights(mass_rename=5), LEVELS
    )
    assert result.score == 5


@pytest.mark.parametrize(
    "score,expected",
    [(0, NORMAL), (39, NORMAL), (40, WARNING), (69, WARNING), (70, CRITICAL), (100, CRITICAL)],
)
def test_level_boundaries(score, expected):
    assert level_for(score, LEVELS) == expected


# ---------- detection engine ----------


def make_event(kind=EventType.MODIFIED, path="a.txt", ext=".txt", dest=None, dest_ext=None, when=None):
    event = FileEvent(
        event_type=kind, path=path, extension=ext, dest_path=dest, dest_extension=dest_ext
    )
    if when is not None:
        event.timestamp = when
    return event


def engine() -> DetectionEngine:
    return DetectionEngine(Thresholds(), 60)


def test_calm_activity_raises_no_flags():
    e = engine()
    for i in range(3):
        result = e.add_event(make_event(path=f"n{i}.txt"), 3.4)
    assert not (result.rapid_encryption or result.mass_rename or result.high_entropy)


def test_burst_of_modifications_flags_rapid_encryption():
    e = engine()
    for i in range(25):
        result = e.add_event(make_event(path=f"f{i}.txt"), 7.9)
    assert result.rapid_encryption
    assert result.modified_files == 25


def test_repeated_events_for_one_file_count_once():
    e = engine()
    for _ in range(100):
        result = e.add_event(make_event(path="same.txt"), 3.0)
    assert result.modified_files == 1
    assert not result.rapid_encryption


def test_mass_rename_with_extension_change():
    e = engine()
    for i in range(15):
        result = e.add_event(
            make_event(EventType.MOVED, f"f{i}.txt", ".txt", f"f{i}.locked", ".locked")
        )
    assert result.renames == 15
    assert result.extension_changes == 15
    assert result.mass_rename


def test_rename_without_extension_change_is_not_counted_as_change():
    e = engine()
    result = e.add_event(make_event(EventType.MOVED, "a.txt", ".txt", "b.txt", ".txt"))
    assert result.renames == 1
    assert result.extension_changes == 0


def test_high_entropy_needs_enough_samples():
    e = engine()
    result = e.add_event(make_event(), 7.99)  # one reading is not enough
    assert not result.high_entropy
    for i in range(6):
        result = e.add_event(make_event(path=f"x{i}.txt"), 7.99)
    assert result.high_entropy


def test_events_without_entropy_are_ignored_in_the_average():
    e = engine()
    for i in range(6):
        result = e.add_event(make_event(path=f"x{i}.txt"), None)
    assert result.entropy_samples == 0
    assert result.avg_entropy == 0.0


def test_old_events_drop_out_of_the_window():
    e = engine()
    old = datetime.now() - timedelta(seconds=300)
    for i in range(30):
        e.add_event(make_event(path=f"old{i}.txt", when=old), 7.9)
    result = e.stats()
    assert result.modified_files == 0
    assert not result.rapid_encryption


def test_affected_files_lists_new_names_after_rename():
    e = engine()
    e.add_event(make_event(path="a.txt"), 7.9)
    result = e.add_event(
        make_event(EventType.MOVED, "a.txt", ".txt", "a.locked", ".locked"), 7.9
    )
    assert result.affected_files == ["a.locked"]