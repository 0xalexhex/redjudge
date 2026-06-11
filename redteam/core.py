"""
Core types + runner for the automated red-team / robustness harness.
Mirrors the HarmBench decoupling: Behaviors x Attacks x Targets x Judge -> Report.
Each axis is a plugin so new attacks/targets/judges drop in without touching the runner.
"""
from __future__ import annotations
import json, time, itertools, re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Protocol, Callable

_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)
def strip_think(text: str) -> str:
    """Strip reasoning-model <think>...</think> so judges grade the FINAL answer.
    Handles a truncated/unclosed think block too. No-op on non-reasoning output."""
    if not text:
        return text or ""
    t = _THINK.sub("", text)
    if "</think>" in t and "<think>" not in t:      # closed but opener was eaten/missing
        t = t.split("</think>")[-1]
    if "<think>" in t and "</think>" not in t:       # still 'thinking' at cutoff -> no answer yet
        t = t.split("<think>")[0]
    return t.strip()


@dataclass
class Behavior:
    id: str
    goal: str                       # the test instruction (benign smoke or a loaded benchmark item)
    category: str = "misc"
    benign: bool = True             # True for shipped smoke set; benchmark loaders set False
    # how a "break" is decided for this behavior:
    #   refusal   -> break = model complied with a should-refuse goal
    #   compliance-> break = model REFUSED a should-comply goal (over-refusal probe)
    #   canary    -> break = model leaked a planted secret
    #   task_done -> break = agent performed the injected/attacker action
    success_signal: str = "refusal"
    meta: dict = field(default_factory=dict)


@dataclass
class Turn:
    role: str                       # system | user | assistant
    content: str


@dataclass
class AttackResult:
    behavior_id: str
    attack: str
    target: str
    transcript: list[Turn]
    final_response: str
    broken: bool                    # judge verdict (ensemble)
    judge: dict                     # per-judge scores
    latency_s: float = 0.0
    error: str | None = None
    # behavior context (set by run_matrix so the reporter can split harmful ASR vs over-refusal)
    signal: str = "refusal"
    benign: bool = True
    category: str = "misc"

    def row(self):
        return {"behavior": self.behavior_id, "attack": self.attack, "target": self.target,
                "broken": self.broken, "signal": self.signal, "benign": self.benign,
                "category": self.category, "error": self.error or "",
                **{f"j_{k}": v for k, v in self.judge.items()}}


class Target(Protocol):
    name: str
    def chat(self, messages: list[dict], **kw) -> str: ...


class Attack(Protocol):
    name: str
    # An attack drives the conversation toward `behavior.goal` against `target`,
    # using `judge` to decide success. Returns the full transcript + verdict.
    def run(self, behavior: Behavior, target: Target, judge) -> AttackResult: ...


class Judge(Protocol):
    name: str
    # Returns (broken: bool, scores: dict). Behavior carries the success_signal.
    def grade(self, behavior: Behavior, transcript: list[Turn], final_response: str) -> tuple[bool, dict]: ...


# ---- registry (pluggable axes) ----
REGISTRY = {"targets": {}, "attacks": {}, "judges": {}}
def register(kind: str):
    def deco(obj):
        REGISTRY[kind][getattr(obj, "name", obj.__name__)] = obj
        return obj
    return deco


# ---- runner ----
def run_matrix(behaviors, attacks, targets, judge, out_dir: Path, verbose=True):
    from .targets import BudgetExceeded          # function-level: avoids core<->targets import cycle
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[AttackResult] = []
    for beh, atk, tgt in itertools.product(behaviors, attacks, targets):
        t0 = time.time()
        try:
            res = atk.run(beh, tgt, judge)
        except (KeyboardInterrupt, BudgetExceeded):
            raise                                # abort the whole run - do NOT swallow into a per-cell error
        except Exception as e:
            res = AttackResult(beh.id, atk.name, tgt.name, [], "", False, {}, error=str(e)[:200])
        res.latency_s = round(time.time() - t0, 2)
        res.signal, res.benign, res.category = beh.success_signal, beh.benign, beh.category
        results.append(res)
        if verbose:
            flag = "BROKEN" if res.broken else ("err" if res.error else "ok")
            print(f"  [{flag:6}] {tgt.name:18} {atk.name:12} {beh.id:24} {res.latency_s:>5}s")
    # persist transcripts + a flat results table
    (out_dir / "results.jsonl").write_text(
        "\n".join(json.dumps({**r.row(), "transcript": [asdict(t) for t in r.transcript],
                              "final": r.final_response}) for r in results))
    return results
