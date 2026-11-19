"""Unit tests for Shannon entropy."""

import os

import pytest

from app.core.entropy import file_entropy, shannon_entropy


def test_empty_data_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_identical_bytes_is_zero():
    assert shannon_entropy(b"A" * 1000) == 0.0


def test_two_equally_likely_bytes_is_one_bit():
    assert shannon_entropy(b"AB" * 500) == pytest.approx(1.0)


def test_all_256_byte_values_is_eight_bits():
    assert shannon_entropy(bytes(range(256)) * 10) == pytest.approx(8.0)


def test_text_is_low_and_random_is_high():
    text = shannon_entropy(b"normal document content " * 100)
    rand = shannon_entropy(os.urandom(20000))
    assert text < 5.0
    assert rand > 7.9


def test_file_entropy_reads_a_real_file(tmp_path):
    f = tmp_path / "random.bin"
    f.write_bytes(os.urandom(20000))
    assert file_entropy(f) > 7.9


def test_file_entropy_of_missing_file_is_zero(tmp_path):
    assert file_entropy(tmp_path / "nope.txt") == 0.0


def test_file_entropy_only_samples_the_start(tmp_path):
    f = tmp_path / "mixed.bin"
    f.write_bytes(b"A" * 100 + os.urandom(20000))
    assert file_entropy(f, sample_size=100) == 0.0