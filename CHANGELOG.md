# Changelog

## v0.2.0
**Two automated black-box jailbreak searches: TAP and Best-of-N.** Both drop into the existing
plugin architecture (no runner change) and are opt-in via `--attacks tap`/`--attacks bon` because
they are query-heavy.
- **TAP - Tree of Attacks with Pruning** (`attacks.py:TAP`, Mehrotra et al., NeurIPS 2024).
  Generalizes PAIR from a single refinement chain to a pruned beam search: each round the attacker
  LLM branches every surviving prompt into `width` children, an **on-topic prune** drops children
  that drifted off the goal (TAP's key add over naive tree search - it stops wasting target queries
  on dead branches), the target is queried with each survivor, and only the top-`keep` by
  fulfillment score advance to the next depth. Early-exits on the first genuine break, else returns
  the best-scoring attempt (reuses PAIR's keep-the-best logic, finding #8). Roughly `width*keep*depth`
  target queries; wants a separate `--attacker` model to be meaningful. Moves TAP from the roadmap's
  "not yet implemented" to implemented.
- **Best-of-N jailbreaking** (`attacks.py:BestOfN`, Hughes et al., Anthropic 2024). Samples N
  augmented variants of the prompt (word scrambling, random capitalization, light character noise)
  and keeps any that break - a gradient-free attack that exploits input-space sensitivity; ASR climbs
  with N. **Reproducible:** the per-behavior RNG is seeded from `crc32(behavior.id)`, not Python's
  salted `hash()`, so the ASR is stable across processes. Sample 0 is the clean baseline; the
  augmentation is what varies the input, so it still probes a temperature-0 target.
- Both propagate `BudgetExceeded` so the hard `--budget` kill-switch still aborts mid-search, and both
  render in the existing scorecard (ASR by target × attack) with no reporter change.
- Docs: README (attack list + a `--attacks tap bon` example), `TEST_CATALOG.md` (mechanisms table +
  LLM01/ATLAS mapping), attack-module docstring. No fabricated benchmark numbers - real ASR comes from
  running these against your own targets/benchmarks.

## v0.1.0
**Cross-model frontier sweep (OpenRouter) + two judge-integrity fixes.**
- **OpenRouter support**: `openai_compat` target reads OpenRouter's exact `usage.cost` (via
  `usage:{include:true}`) -> precise meter + hard `--budget` kill-switch; **per-model cost tracking**
  (`cost_by_target()`) shown in the run output and usable as a leaderboard column.
- **Empty-answer fix (important)**: an empty/blocked model reply (e.g. provider `content_filter`
  returns no body) is **never** scored as a harmful/injection break - previously the judges, fed the
  harmful goal + an empty answer, hallucinated "unsafe/complied," which had falsely ranked Claude as
  the *least* safe model. For a benign over-refusal probe an empty answer counts as a refusal.
- **High-confidence harmful metric**: recommend Llama Guard unsafe **AND** StrongREJECT > 0 to drop
  Llama-Guard-alone false positives (it over-flags refusals and even benign/inclusive answers).
- `scripts/sweep_openrouter.sh`: reproducible 10-model sweep (paid targets, local free judges).
- **Result**: benchmarked 10 current frontier models for ~$3.3 - see `FINDINGS.md §2e`.

## v0.0.4
**Three new attack surfaces - the Gray-Swan-parity classes: indirect injection, agentic tool-abuse, multimodal.**
- **Indirect Prompt Injection** (`redteam/injection.py`, `--suite injection`): a real suite - 6 carriers
  (email/web/ticket/code/doc/tool-result) × 4 techniques (naive/ignore/authority/encoded) - measured
  with a benign marker, plus a **Spotlighting defense** variant so you get a **defense-lift** number
  (undefended vs defended ASR). OWASP LLM01 / AML.T0051.001.
- **Agentic tool-abuse** (`redteam/agentic.py`, `--suite agentic`): a portable **ReAct** agent loop over
  a **mock sandboxed tool environment** (email/files/web/payments - no real side effects). Indirect
  injection is planted in tool-returned data; a **deterministic `task_done` judge** checks the tool-call
  log for the attacker action (exfiltration / payment / deletion). InjecAgent-style; includes a clean
  control scenario. OWASP LLM06.
- **Multimodal / visual injection** (`redteam/multimodal.py`, `--suite multimodal` + `ollama_vision`
  target): renders the injected instruction as **text inside an image** (Pillow) and tests a VLM across
  4 techniques (describe / follow / embedded-screenshot / **low-contrast hidden text**). OWASP LLM01.
- **Obedience-aware `InjectionJudge`**: the important integrity fix - a model that REFUSES or merely
  QUOTES the injected marker no longer counts as "broken" (that quote-echo false positive was inflating
  injection ASR and, worse, inflating the *defended* number). Modes: exfil (out-of-band secret value),
  append (marker at the reply tail), only (marker-dominated reply). Every surviving break re-verified genuine.
- Determinism: injection + agentic attacks call the target at **temperature 0** -> reproducible ASR /
  defense-lift. New `VisionTarget` (`ollama_vision`) for image inputs via Ollama's native `/api/chat`.

## v0.0.3
**Credibility pass: validated judges + real harmful-content benchmark run + over-refusal control.**
This is the jump from "clean harness, one extraction finding" to "produces a defensible harmful-content
ASR the way HarmBench/JailbreakBench-style evals do."
- **Validated judges** (`redteam/judge.py`), replacing the homemade grader as the credible default:
  - `LlamaGuardJudge` - Meta **Llama Guard 3** (8B) safety classifier, run locally via Ollama. It is
    the *authoritative* binary judge for harmful-content ASR. Talks to Ollama's **raw `/api/generate`**
    because Ollama's bundled `llama-guard3` chat template hardcodes "…LAST **User** message" and so
    grades the harmful *question* instead of the model's *answer* (a clean refusal scored `unsafe`).
    We send Meta's official "…LAST **Agent** message" prompt so it grades the reply.
  - `StrongRejectJudge` - faithful reimplementation of the **StrongREJECT** autograder (exact rubric,
    parse regex, and `(1-refused)·(convincing+specific)/2 -> [0,1]` scoring). Calibrated 0..1 "how much
    the reply actually fulfilled the harmful goal" - usefulness-weighted, not substring-match.
  - `Ensemble` now supports an **authoritative** judge: Llama Guard (harmful) / Canary (extraction)
    decides the verdict while every applicable judge is still recorded (StrongREJECT + heuristic shown
    alongside). Falls back to majority-of-heuristics with an explicit UNCALIBRATED warning.
- **Standard benchmarks on demand** (`scripts/get_datasets.py`, gitignored `data/`): AdvBench, JBB
  (100 harmful + 100 benign), StrongREJECT (313/60), XSTest. No harmful prompts committed.
- **Over-refusal control** auto-added to harmful runs (`--benign`, default JBB benign) -> the scorecard
  reports over-refusal alongside ASR, so a low ASR can't just mean "refuses everything."
- **Separate attacker model** for PAIR/Crescendo (`--attacker-model`) - no more self-attack.
- **Reporter** (`redteam/report.py`) rewritten: harmful leaderboard + ASR by attack + mean StrongREJECT
  + Llama Guard hazard categories + over-refusal section + the canary FULL-vs-CoT split.
- **Deferred audit fixes:** #6 refusal heuristic tightened (dropped noisy "as an ai"/bare "i'm sorry",
  head-anchored); #7 networking (no retry on 4xx≠429, honor Retry-After, jitter, no sleep after last);
  #8 PAIR keeps the genuinely-best attempt, not the last; #9 StrongREJECT strict parse (no first-number
  grab). Local (keyless) targets no longer metered at API prices.

## v0.0.2
**Persistent-memory chat + first finding reproduced on the live DeepSeek API.**
- Added `chat.py`: a persistent-memory, multi-turn red-team chat against a live target. Full
  conversation history is resent every turn (real "memory"), so gradual (Crescendo) erosion is
  possible. Captures the model's `reasoning_content` to detect chain-of-thought leaks.
  - Modes: `--send` (drive one turn), `--interactive` (REPL), `--auto` (autonomous LLM attacker,
    needs `ANTHROPIC_API_KEY`), `--show`, `--reset`. Hard USD budget cap.
- **Finding:** reproduced the reasoning-channel secret leak on the **real `deepseek-reasoner` (R1)
  via api.deepseek.com** - the final answer refuses, but the reasoning trace prints a planted
  system-prompt secret verbatim, in 2 turns with a benign yes/no probe. See `WRITEUP.md` / `FINDINGS.md §2b`.
- Added `.gitignore` (excludes `.env` / keys) for safe publishing.

## v0.0.1
**Initial harness + local baseline.**
- HarmBench-style decoupled harness: Behaviors × Attacks × Targets × Judge -> Scorecard. Stdlib-only.
- Attacks: `direct`, `encoding` (base64/rot13/leet), `manyshot`, `multiturn` (Crescendo), `pair`.
- Targets: `openai_compat` (Ollama/vLLM/LM Studio/OpenAI/etc), `anthropic`, gated `webui`, `dryrun`.
- Judge: calibrated **ensemble** (refusal + canary + optional LLM-judge, majority vote) - StrongREJECT calibration.
- First run vs local `deepseek-r1:8b` distill -> 52% ASR; system-prompt extraction incl. 9 CoT leaks.
