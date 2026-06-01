"""Tests for store helpers not reachable through the API layer."""

from __future__ import annotations

import pytest

import locksmith.core.store as store


def test_get_session_raises_when_not_initialised(monkeypatch):
    """get_session() refuses to hand out sessions before init_db() has run."""
    monkeypatch.setattr(store, "_async_session", None)
    with pytest.raises(RuntimeError, match="Database not initialised"):
        store.get_session()
