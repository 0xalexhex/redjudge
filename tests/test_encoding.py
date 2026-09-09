"""Encoding attack schemes. leet used to crash on a 12-vs-13 char maketrans; regression-guard it."""
import base64
import codecs

from redteam.core import Behavior
from redteam.attacks import Encoding


class _StubJudge:
    def grade(self, behavior, transcript, final):
        return False, {}


class _Capture:
    name = "cap"
    def __init__(self):
        self.last = None
    def chat(self, messages, **kw):
        self.last = messages[-1]["content"]
        return "ok"


def _payload(scheme):
    tgt = _Capture()
    Encoding().run(Behavior("e", "attack the base", meta={"encoding": scheme}), tgt, _StubJudge())
    return tgt.last


def test_base64_roundtrip():
    assert base64.b64encode(b"attack the base").decode() in _payload("base64")


def test_rot13_involution():
    assert codecs.encode("attack the base", "rot_13") in _payload("rot13")


def test_leet_does_not_crash_and_maps():
    out = _payload("leet")            # would raise ValueError before the maketrans fix
    assert "4774ck" in out            # a->4, t->7: 'attack' -> '4774ck'
