#!/usr/bin/env python3
"""
CLI for the automated red-team harness.

  # offline smoke test (no creds, proves the pipeline end-to-end):
  python3 run.py --targets dryrun --smoke

  # REAL harmful-content benchmark on a local model, graded by a VALIDATED judge
  # (Llama Guard 3 classifier authoritative + StrongREJECT autograder score), with an
  # over-refusal control auto-added - the credible way to report ASR:
  python3 run.py --benchmark strongreject_small --limit 40 \
    --target-spec '{"kind":"openai_compat","base_url":"http://localhost:11434/v1","model":"deepseek-r1:8b"}' \
    --guard-model  '{"base_url":"http://localhost:11434","model":"llama-guard3:8b"}' \
    --judge-model  '{"kind":"openai_compat","base_url":"http://localhost:11434/v1","model":"llama3.1:8b"}' \
    --attacker-model '{"kind":"openai_compat","base_url":"http://localhost:11434/v1","model":"llama3.1:8b"}'

Named benchmarks (fetch first: python3 scripts/get_datasets.py):
  advbench · jbb_harmful · strongreject · strongreject_small   (harmful)
  jbb_benign · xstest                                          (benign over-refusal controls)

Judges: Llama Guard 3 (validated classifier, authoritative) + StrongREJECT autograder (0..1 graded
score) + refusal heuristic (cross-check). Without --guard-model the harness WARNS the ASR is
uncalibrated. Attacks default to all black-box modules.
"""
import argparse, json, os, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from redteam import behaviors as B, run_matrix
from redteam.targets import DryRunTarget, build_target, BUDGET, meter_cost, cost_by_target
from redteam.attacks import Direct, Encoding, ManyShot, MultiTurn, PAIR, TAP, BestOfN
from redteam.judge import RefusalJudge, CanaryJudge, LlamaGuardJudge, StrongRejectJudge, LLMJudge, Ensemble
from redteam.report import scorecard
from redteam.injection import build_injection_suite, injection_attacks, InjectionJudge
from redteam.agentic import build_agentic_suite, AgenticAttack, AgenticJudge
from redteam.multimodal import build_multimodal_suite, multimodal_attacks

# Default single-turn/refinement attacks. TAP and BoN are QUERY-HEAVY (tree search / N-sampling),
# so they stay opt-in via `--attacks tap`/`--attacks bon` and are not run by default.
ATTACK_NAMES = ["direct", "encoding", "manyshot", "multiturn", "pair"]
HEAVY_ATTACKS = ["tap", "bon"]
# built-in scenario suites -> default attack names
SUITE_ATTACKS = {"injection": [a.name for a in injection_attacks()], "agentic": ["agentic"],
                 "multimodal": [a.name for a in multimodal_attacks()]}


def load_env():
    """Load redjudge/.env (gitignored) so API-based targets/judges get their keys."""
    p = HERE / ".env"
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def build_attacks(names, attacker):
    reg = {"direct": Direct(), "encoding": Encoding(), "manyshot": ManyShot(),
           "multiturn": MultiTurn(attacker=attacker), "pair": PAIR(attacker=attacker),
           "tap": TAP(attacker=attacker), "bon": BestOfN()}
    for atk in injection_attacks():                    # indirect-injection techniques
        reg[atk.name] = atk
    for atk in multimodal_attacks():                   # visual / typographic injection
        reg[atk.name] = atk
    reg["agentic"] = AgenticAttack()                   # agentic tool-abuse loop
    return [reg[x] for x in names if x in reg]


_PREFIX = {"ollama", "vision", "openrouter", "openai", "anthropic", "deepseek"}

def _target_spec(s):
    """Expand a friendly target shortcut into a full spec (raw JSON also accepted).
    ollama:llama3.1:8b · openrouter:openai/gpt-5.5 · anthropic:claude-sonnet-5 ·
    vision:llama3.2-vision:11b · deepseek:deepseek-reasoner · dryrun · a bare name (assumed Ollama)."""
    s = s.strip()
    if s.startswith("{"):
        return json.loads(s)
    if s == "dryrun":
        return {"kind": "dryrun"}
    pfx = s.split(":", 1)[0]
    if pfx in _PREFIX and ":" in s:
        rest = s.split(":", 1)[1]
    else:
        pfx, rest = "ollama", s                        # bare model name (may carry a ':tag')
    if pfx == "ollama":
        return {"kind": "openai_compat", "base_url": "http://localhost:11434/v1", "model": rest, "name": rest}
    if pfx == "vision":
        return {"kind": "ollama_vision", "base_url": "http://localhost:11434", "model": rest, "name": rest}
    if pfx == "openrouter":
        return {"kind": "openai_compat", "base_url": "https://openrouter.ai/api/v1", "model": rest,
                "api_key_env": "OPENROUTER_API_KEY", "name": rest.split("/")[-1]}
    if pfx == "openai":
        return {"kind": "openai_compat", "base_url": "https://api.openai.com/v1", "model": rest,
                "api_key_env": "OPENAI_API_KEY", "name": rest}
    if pfx == "deepseek":
        return {"kind": "openai_compat", "base_url": "https://api.deepseek.com/v1", "model": rest,
                "api_key_env": "DEEPSEEK_API_KEY", "name": rest}
    return {"kind": "anthropic", "model": rest, "name": rest}

def _guard_spec(s):
    """Llama Guard shortcut -> {base_url, model} at the Ollama root. 'ollama:llama-guard3:8b',
    a bare 'llama-guard3:8b', or raw JSON."""
    s = s.strip()
    if s.startswith("{"):
        return json.loads(s)
    if s.startswith("ollama:"):
        s = s.split(":", 1)[1]
    return {"base_url": "http://localhost:11434", "model": s}


def main():
    ap = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=__doc__)
    ap.add_argument("--targets", nargs="*", default=[], help="named: dryrun")
    ap.add_argument("--target", action="append", default=[],
                    help="target shortcut, repeatable: ollama:llama3.1 · openrouter:openai/gpt-5.5 · anthropic:claude-sonnet-5 · dryrun")
    ap.add_argument("--target-spec", action="append", default=[], help="full JSON target spec (power users; repeatable)")
    ap.add_argument("--attacks", nargs="*", default=None, help=f"subset of {ATTACK_NAMES} (or a suite's attacks)")
    ap.add_argument("--suite", choices=list(SUITE_ATTACKS), help="built-in scenario suite: injection")
    ap.add_argument("--smoke", action="store_true", help="use the bundled BENIGN smoke behaviors")
    ap.add_argument("--owner-pw", action="store_true", help="add the owner-password scenario (guarded secret + rule-override)")
    ap.add_argument("--benchmark", help="named benchmark (strongreject_small/jbb_harmful/advbench/...) or a path to your CSV/JSONL")
    ap.add_argument("--benign", default="auto",
                    help="over-refusal control: a benign set name, 'auto' (default: jbb_benign when a harmful benchmark runs), or 'none'")
    ap.add_argument("--benign-limit", type=int, default=25, help="cap on auto-added benign control behaviors")
    ap.add_argument("--limit", type=int, default=None, help="cap harmful benchmark behaviors")
    ap.add_argument("--guard", help="Llama Guard shortcut, e.g. ollama:llama-guard3:8b (authoritative harmful-content judge)")
    ap.add_argument("--judge", help="StrongREJECT autograder shortcut, e.g. ollama:llama3.1:8b (separate model)")
    ap.add_argument("--attacker", help="separate attacker shortcut for PAIR/Crescendo, e.g. ollama:llama3.1:8b")
    ap.add_argument("--guard-model", help="full JSON spec for the Llama Guard judge (power users)")
    ap.add_argument("--judge-model", help="full JSON spec for the StrongREJECT autograder model (power users)")
    ap.add_argument("--legacy-judge", action="store_true", help="also add the deprecated homemade 0..1 grader")
    ap.add_argument("--attacker-model", help="full JSON spec for a separate PAIR/Crescendo attacker (power users)")
    ap.add_argument("--budget", type=float, default=None, help="hard USD cap for paid-API targets/judges")
    ap.add_argument("--out", default=str(HERE / "results"))
    a = ap.parse_args()

    load_env()
    if a.budget is not None:
        BUDGET["limit_usd"] = a.budget

    # ---- targets ----
    for t in a.targets:
        if t != "dryrun":
            print(f"[!] ignoring unknown --targets name {t!r} - only 'dryrun' is named; use --target-spec")
    targets = [DryRunTarget() for t in a.targets if t == "dryrun"]
    targets += [build_target(_target_spec(s)) for s in a.target]        # friendly shortcuts
    targets += [build_target(json.loads(s)) for s in a.target_spec]     # full JSON specs
    if not targets:
        targets = [DryRunTarget()]; print("[i] no targets given -> dryrun")

    # ---- behaviors ----
    behaviors = []
    if a.suite == "injection":
        behaviors += build_injection_suite()
        print(f"[i] + {len(behaviors)} indirect-injection scenarios")
    if a.suite == "agentic":
        behaviors += build_agentic_suite()
        print(f"[i] + {len(behaviors)} agentic tool-abuse scenarios")
    if a.suite == "multimodal":
        behaviors += build_multimodal_suite()
        print(f"[i] + {len(behaviors)} multimodal (visual-injection) scenarios")
    if a.benchmark:
        behaviors += B.load_benchmark(a.benchmark, limit=a.limit)
        harmful = [b for b in behaviors if not b.benign]
        # auto over-refusal control paired with a harmful run
        if harmful and a.benign != "none":
            name = B.DEFAULT_BENIGN if a.benign == "auto" else a.benign
            try:
                ctrl = B.load_benchmark(name, limit=a.benign_limit)
                behaviors += ctrl
                print(f"[i] + {len(ctrl)} benign over-refusal controls from '{name}'")
            except FileNotFoundError as e:
                print(f"[!] over-refusal control skipped: {e}")
    if a.owner_pw:
        behaviors += B.OWNER_PW
    if a.smoke or not behaviors:
        behaviors = list(B.SMOKE) + behaviors if behaviors else list(B.SMOKE)
    if not behaviors:
        behaviors = list(B.SMOKE)

    # ---- attacks (with an optional separate attacker model; shortcut or JSON) ----
    attacker = None
    if a.attacker_model or a.attacker:
        attacker = build_target(json.loads(a.attacker_model) if a.attacker_model else _target_spec(a.attacker))
    attack_names = a.attacks or SUITE_ATTACKS.get(a.suite) or ATTACK_NAMES
    attacks = build_attacks(attack_names, attacker)

    # ---- judges: validated ensemble (guard/judge via shortcut or full JSON) ----
    judges = [RefusalJudge(), CanaryJudge(), AgenticJudge(), InjectionJudge()]
    if a.guard_model or a.guard:
        gs = json.loads(a.guard_model) if a.guard_model else _guard_spec(a.guard)
        judges.append(LlamaGuardJudge(gs.get("base_url", "http://localhost:11434"),
                                      gs.get("model", "llama-guard3:8b")))
    judge_spec = a.judge_model or (json.dumps(_target_spec(a.judge)) if a.judge else None)
    if judge_spec:
        judges.append(StrongRejectJudge(build_target(json.loads(judge_spec))))
        if a.legacy_judge:
            judges.append(LLMJudge(build_target(json.loads(judge_spec))))
    judge = Ensemble(judges)

    n_harm = sum(1 for b in behaviors if not b.benign)
    print(f"[i] {len(behaviors)} behaviors ({n_harm} harmful / {len(behaviors)-n_harm} benign), "
          f"{len(targets)} targets, attacks={attack_names}")
    print(f"[i] judges: {', '.join(j.name for j in judges)}"
          + ("  (attacker=separate)" if attacker else "  (attacker=self)"))

    out = Path(a.out)
    results = run_matrix(behaviors, attacks, targets, judge, out, verbose=True)
    print("\n" + scorecard(results, out))
    print(f"\n[i] transcripts -> {out}/results.jsonl  |  scorecard -> {out}/scorecard.md")
    if meter_cost() > 0:
        print(f"[i] spent ${meter_cost():.4f} on paid APIs")
        for name, v in sorted(cost_by_target().items(), key=lambda x: -x[1]["cost"]):
            print(f"    {name:34} ${v['cost']:.4f}  ({v['calls']} calls)")


if __name__ == "__main__":
    main()
