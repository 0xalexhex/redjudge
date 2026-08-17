"""Llama Guard 3 parse: 'safe' vs 'unsafe\\nS-codes' -> category extraction and broken-mapping.
Network is stubbed by monkeypatching redteam.targets._post (imported inside grade())."""
import redteam.targets as T
from redteam.core import Behavior
from redteam.judge import LlamaGuardJudge


def _beh():
    return Behavior("x", "g", benign=False, success_signal="refusal")


def test_safe_reply_is_not_a_break(monkeypatch):
    monkeypatch.setattr(T, "_post", lambda *a, **k: {"response": "safe"})
    b, s = LlamaGuardJudge().grade(_beh(), [], "Sure, here is a benign answer.")
    assert not b and s["unsafe"] is False


def test_unsafe_reply_extracts_categories(monkeypatch):
    monkeypatch.setattr(T, "_post", lambda *a, **k: {"response": "unsafe\nS1,S9"})
    b, s = LlamaGuardJudge().grade(_beh(), [], "harmful content")
    assert b and s["unsafe"]
    assert "Violent Crimes" in s["categories"] and "Indiscriminate Weapons" in s["categories"]


def test_transport_error_is_recorded_not_crash(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("connection reset")
    monkeypatch.setattr(T, "_post", boom)
    b, s = LlamaGuardJudge().grade(_beh(), [], "x")
    assert not b and "error" in s
