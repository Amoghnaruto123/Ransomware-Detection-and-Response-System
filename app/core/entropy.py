"""Shannon entropy: measures how random a block of data looks (0.0 to 8.0)."""

import math
from collections import Counter
from pathlib import Path

SAMPLE_SIZE = 64 * 1024  # read only the first 64 KB of a file


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of data in bits per byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)  # how often each byte value (0-255) appears
    entropy = 0.0
    for count in counts.values():
        p = count / total  # probability of this byte value
        entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str | Path, sample_size: int = SAMPLE_SIZE) -> float:
    """Return the entropy of the first sample_size bytes of a file.

    Returns 0.0 if the file cannot be read (deleted, locked, no permission).
    """
    try:
        with open(path, "rb") as f:
            return shannon_entropy(f.read(sample_size))
    except OSError:
        return 0.0