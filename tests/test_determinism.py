"""The harmful / refinement attacks must query the target at temperature 0 so ASR is reproducible
(the injection and agentic suites already pin temp 0). Regression for the direct 0%-vs-25% flakiness
seen when the target ran at its default temperature 0.7."""
from redteam.core import Behavior
from redteam.attacks import Direct, Encoding, ManyShot, BestOfN


class _TempCapture:
    name = "cap"
    def __init__(self):
        self.temps = []
    def chat(self, messages, **kw):
        self.temps.append(kw.get("temperature"))
        return "no"


class _StubJudge:
    def grade(self, behavior, transcript, final):
        return False, {}


def _temps(attack):
    tgt = _TempCapture()
    attack.run(Behavior("b", "some goal"), tgt, _StubJudge())
    return tgt.temps


def test_direct_pins_temp0():
    assert _temps(Direct()) == [0]


def test_encoding_pins_temp0():
    assert _temps(Encoding()) == [0]


def test_manyshot_pins_temp0():
    assert _temps(ManyShot()) == [0]


def test_bon_queries_at_temp0():
    temps = _temps(BestOfN(n=3, seed=0))     # each sample goes through _one_query -> temp 0
    assert temps and all(t == 0 for t in temps)
