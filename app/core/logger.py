"""Logging setup for RDRS: separate rotating log files using loguru."""

import sys
from pathlib import Path

from loguru import logger

_configured = False


def setup_logging(logs_dir: str = "./logs") -> None:
    """Create the log folder and attach one rotating file per channel."""
    global _configured
    if _configured:
        return

    Path(logs_dir).mkdir(parents=True, exist_ok=True)
    logger.remove()  # drop loguru's default console handler

    # Console output (the noisy "events" channel is kept out of the screen)
    logger.add(
        sys.stderr,
        level="INFO",
        filter=lambda record: record["extra"].get("channel") != "events",
        format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}",
    )

    # One file per channel: system, events, alerts, audit
    for channel in ("system", "events", "alerts", "audit"):
        logger.add(
            Path(logs_dir) / f"{channel}.log",
            level="INFO",
            rotation="5 MB",
            retention=5,
            filter=lambda record, ch=channel: record["extra"].get("channel") == ch,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
        )

    # errors.log collects every ERROR from any channel
    logger.add(
        Path(logs_dir) / "errors.log",
        level="ERROR",
        rotation="5 MB",
        retention=5,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{line} | {message}",
    )

    _configured = True


def get_logger(channel: str):
    """Return a logger tagged with a channel name (system/events/alerts/audit)."""
    return logger.bind(channel=channel)