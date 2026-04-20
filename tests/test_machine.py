"""Tests for cross-platform machine ID computation."""

from locksmith.core.machine import compute_machine_id


def test_returns_nonempty_sha256_hex():
    result = compute_machine_id()
    assert isinstance(result, str), "machine ID should be a string"
    assert len(result) == 64, "SHA-256 hex digest should be 64 characters"
    int(result, 16)  # raises ValueError if not valid hex


def test_stable_across_calls():
    assert compute_machine_id() == compute_machine_id()
