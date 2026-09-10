"""Budget kill-switch: the guard raises at the cap, and (regression) run_matrix persists + returns
the partial results collected before the abort instead of discarding them."""
import json

import pytest

from redteam.core import Behavior, Turn, AttackResult, run_matrix
from redteam.targets import BUDGET, METER, BudgetExceeded, _budget_guard, reset_meter


def test_guard_raises_at_cap():
    reset_meter()
    BUDGET["limit_usd"] = 1.0
    METER["cost"] = 0.99
    _budget_guard()                       # under the cap -> no raise
    METER["cost"] = 1.0
    with pytest.raises(BudgetExceeded):
        _budget_guard()


def test_partial_results_persisted_on_abort(tmp_path):
    reset_meter()
    calls = {"n": 0}

    class BudgetTarget:
        name = "bt"
        def chat(self, messages, **kw):
            calls["n"] += 1
            if calls["n"] >= 3:
                raise BudgetExceeded("cap hit")
            return "ok"

    class Direct:
        name = "direct"
        def run(self, beh, tgt, judge):
            out = tgt.chat([{"role": "user", "content": beh.goal}])
            tr = [Turn("user", beh.goal), Turn("assistant", out)]
            return AttackResult(beh.id, self.name, tgt.name, tr, out, False, {})

    behaviors = [Behavior(f"b{i}", "g") for i in range(6)]
    res = run_matrix(behaviors, [Direct()], [BudgetTarget()], judge=None, out_dir=tmp_path, verbose=False)

    assert len(res) == 2                                  # aborted on the 3rd call, 2 already done
    lines = (tmp_path / "results.jsonl").read_text().strip().splitlines()
    assert len(lines) == 2 and all(json.loads(l) for l in lines)
