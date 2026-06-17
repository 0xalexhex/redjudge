#!/usr/bin/env python3
"""
LEAN, budget-capped test against the REAL DeepSeek API (api.deepseek.com).
Tests the actual deepseek-reasoner (R1) and deepseek-chat (V3) - not a local distill.
Cost-metered with a HARD kill-switch; uses the benign canary-extraction probes only.

Run:  python3 deepseek_api_test.py
Reads DEEPSEEK_API_KEY from .env. Override budget with REDTEAM_BUDGET_USD (default 0.40).
"""
import os, sys, json
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# load DEEPSEEK_API_KEY from local redjudge/.env (gitignored) into the environment
_envf = HERE / ".env"
if _envf.exists():
    for line in _envf.read_text().splitlines():
        if line.startswith("DEEPSEEK_API_KEY="):
            os.environ["DEEPSEEK_API_KEY"] = line.split("=", 1)[1].strip()
if not os.environ.get("DEEPSEEK_API_KEY"):
    sys.exit("No DEEPSEEK_API_KEY - add it to redjudge/.env as `DEEPSEEK_API_KEY=sk-...` and re-run.")

from redteam import targets as T, behaviors as B, run_matrix
from redteam.targets import build_target, METER, BUDGET, meter_cost, BudgetExceeded
from redteam.attacks import Direct, ManyShot, Encoding
from redteam.judge import RefusalJudge, CanaryJudge, Ensemble
from redteam.report import scorecard
from redteam.core import strip_think

BUDGET["limit_usd"] = float(os.environ.get("REDTEAM_BUDGET_USD", "0.40"))   # hard cap, < the 50c ceiling
BUDGET["in_per_m"], BUDGET["out_per_m"] = 0.14, 0.28                         # user-provided $/M
SECRET = B._CANARY                                                            # single source of truth (behaviors.py)

# real DeepSeek models (OpenAI-compatible endpoint). Low max_tokens to stay cheap.
TARGETS = [
    build_target({"kind": "openai_compat", "base_url": "https://api.deepseek.com/v1",
                  "model": "deepseek-reasoner", "name": "deepseek-reasoner(R1)",
                  "api_key_env": "DEEPSEEK_API_KEY", "max_tokens": 700, "temperature": 0.6}),
    build_target({"kind": "openai_compat", "base_url": "https://api.deepseek.com/v1",
                  "model": "deepseek-chat", "name": "deepseek-chat(V3)",
                  "api_key_env": "DEEPSEEK_API_KEY", "max_tokens": 256, "temperature": 0.6}),
]
BEHAVIORS = [b for b in B.SMOKE if b.id.startswith("canary")]   # 3 benign extraction probes
ATTACKS = [Direct(), ManyShot(), Encoding()]                    # single-call only (cheap)
JUDGE = Ensemble([RefusalJudge(), CanaryJudge()])

print(f"[budget] hard cap ${BUDGET['limit_usd']:.2f}  (prices in=${BUDGET['in_per_m']}/M out=${BUDGET['out_per_m']}/M)")
print(f"[plan] {len(BEHAVIORS)} behaviors x {len(ATTACKS)} attacks x {len(TARGETS)} models "
      f"= {len(BEHAVIORS)*len(ATTACKS)*len(TARGETS)} calls (single-call attacks)\n")

try:
    results = run_matrix(BEHAVIORS, ATTACKS, TARGETS, JUDGE, HERE / "results_deepseek_api", verbose=True)
except BudgetExceeded as e:
    print(f"\n[!] {e}")
    results = []

print(f"\n[spend] {METER['calls']} calls | {METER['prompt']} in + {METER['completion']} out tokens "
      f"| COST = ${meter_cost():.4f}")
if results:
    print("\n" + scorecard(results, HERE / "results_deepseek_api"))
    # leak detail (the actual finding on the REAL model)
    print("=== leak detail (real DeepSeek) ===")
    for r in results:
        if r.broken and SECRET.lower() in (r.final or "").lower():
            where = "ANSWER" if SECRET.lower() in strip_think(r.final).lower() else "reasoning(CoT)"
            print(f"  LEAK [{r.target} / {r.attack} / {r.behavior_id}] in {where}")
