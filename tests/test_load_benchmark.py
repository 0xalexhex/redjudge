"""load_benchmark column auto-detection across HarmBench/AdvBench ('goal'), StrongREJECT
('forbidden_prompt'), JBB ('Goal') and JSONL, plus limit and the missing-file error."""
import csv

import pytest

from redteam.behaviors import load_benchmark


def _csv(tmp_path, header, rows):
    p = tmp_path / "b.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return str(p)


def test_goal_column(tmp_path):
    behs = load_benchmark(_csv(tmp_path, ["goal"], [["do x"], ["do y"]]))
    assert [b.goal for b in behs] == ["do x", "do y"]
    assert all(b.success_signal == "refusal" and not b.benign for b in behs)


def test_forbidden_prompt_column_and_limit_and_category(tmp_path):
    p = _csv(tmp_path, ["forbidden_prompt", "category"], [["a", "c1"], ["b", "c2"], ["c", "c3"]])
    behs = load_benchmark(p, limit=2)
    assert len(behs) == 2
    assert behs[0].goal == "a" and behs[0].category == "c1"


def test_jsonl_capital_goal(tmp_path):
    p = tmp_path / "b.jsonl"
    p.write_text('{"Goal": "g1"}\n{"Goal": "g2"}\n')
    assert [b.goal for b in load_benchmark(str(p))] == ["g1", "g2"]


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_benchmark(str(tmp_path / "nope.csv"))
