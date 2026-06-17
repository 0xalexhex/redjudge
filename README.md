# RedJudge - an automated LLM red-team / robustness harness

**v0.1.0** · [QUICKSTART.md](QUICKSTART.md) · [WRITEUP.md](WRITEUP.md) (finding) · [CHANGELOG.md](CHANGELOG.md) · [FINDINGS.md](FINDINGS.md)

A CI-style robustness-evaluation harness for LLMs.
Pluggable **Behaviors × Attacks × Targets × Judge -> Scorecard**, modeled on HarmBench's
decoupling. Tests local open-weights models, APIs, and (gated) web chat UIs.

> **Scope:** authorized robustness evaluation. Ships **benign** smoke tests only; you supply
> real safety benchmarks. The web-UI adapter is disabled unless you assert authorization.

## Quick start
Guided version: [QUICKSTART.md](QUICKSTART.md). In short, targets and judges are `provider:model`
shortcuts (no JSON):
```bash
cd redjudge

# offline smoke test (no creds, no network):
python3 run.py --target dryrun --smoke

# fetch the standard benchmarks into ./data (gitignored, not bundled):
python3 scripts/get_datasets.py

# real harmful-content benchmark on a local model, graded by validated judges:
python3 run.py --benchmark strongreject_small --limit 15 \
  --target ollama:llama3.1:8b --guard ollama:llama-guard3:8b --judge ollama:llama3.1:8b

# API models via OpenRouter (one key for all; judges stay local, so only the answers cost money):
python3 run.py --benchmark strongreject_small --limit 15 --budget 2.0 \
  --target openrouter:openai/gpt-5.5 --target openrouter:anthropic/claude-sonnet-5 \
  --guard ollama:llama-guard3:8b --judge ollama:llama3.1:8b

# bring your own set (auto-detects goal/behavior/Goal/forbidden_prompt columns):
python3 run.py --benchmark path/to/your.csv --target ollama:llama3.1:8b --guard ollama:llama-guard3:8b
```
Outputs: `results/<out>/scorecard.md` (harmful ASR + mean StrongREJECT + Llama Guard hazard categories
+ over-refusal control) and `results.jsonl` (full transcripts). Without `--guard` the scorecard is
flagged UNCALIBRATED (a heuristic number, not a defensible ASR). Pass `--target` more than once for a
head-to-head leaderboard. Full JSON specs (`--target-spec`) still work for power users.

## Datasets (fetched on demand, never committed)
`scripts/get_datasets.py` pulls the standard academic benchmarks into a gitignored `data/`:
`advbench` · `jbb_harmful` / `jbb_benign` · `strongreject` / `strongreject_small` · `xstest`. The repo
ships **no** operational harmful content - these are the same should-refuse behavior sets HarmBench/JBB
use to *measure robustness*, opted into explicitly. Reference `--benchmark <name>` or a path.

## Attack suites - injection · agentic · multimodal
Beyond single-turn jailbreaks, three built-in suites cover the modern high-impact classes. All measure
with benign markers (no harmful content) via the **obedience-aware** judge, so a model that merely
quotes an injected instruction is not miscounted as broken.
```bash
# Indirect prompt injection (6 carriers x 4 techniques) + a Spotlighting DEFENSE-LIFT number:
python3 run.py --suite injection --target ollama:llama3.1:8b

# Agentic tool-abuse: a ReAct agent over MOCK sandboxed tools; injection planted in tool output.
# Does the agent exfiltrate / pay / delete? (deterministic task_done judge; includes a clean control)
python3 run.py --suite agentic --target ollama:llama3.1:8b

# Multimodal: the instruction is rendered as TEXT IN AN IMAGE, fired at a vision model:
python3 run.py --suite multimodal --target vision:llama3.2-vision:11b
```

## What's implemented
- **Attacks** (`redteam/attacks.py`): `direct` (control), `encoding` (base64/rot13/leet obfuscation),
  `manyshot` (Anthropic many-shot, benign exemplars), `multiturn` (Crescendo-style escalation),
  `pair` (attacker-LLM iterative refinement). All are *mechanisms* operating on the supplied behavior.
- **Targets** (`redteam/targets.py`): `dryrun` mock · `openai_compat` (Ollama/vLLM/LM Studio/OpenAI/Together/Groq/OpenRouter) · `anthropic` · `webui` (gated).
- **Judge** (`redteam/judge.py`): **validated ensemble** - `llama-guard` (Meta Llama Guard 3
  classifier, *authoritative* harmful-content ASR) + `strongreject` (faithful StrongREJECT autograder,
  calibrated 0..1 usefulness) + `canary` (deterministic extraction) + `refusal` heuristic cross-check.
  An authoritative judge decides the verdict; the rest are recorded. Two judges plus a spot-check keep
  the ASR defensible instead of the near-100% inflation a single homemade grader tends to produce.
- **Behaviors** (`redteam/behaviors.py`): benign smoke set (canary extraction + over-refusal controls)
  + `load_benchmark()` - named standard benchmarks (AdvBench / JBB / StrongREJECT / XSTest) or your own
  CSV/JSONL, with auto over-refusal controls. Datasets are fetched by `scripts/get_datasets.py`.
- **Report** (`redteam/report.py`): robustness scorecard + leaderboard + ASR by attack×target.
- **Persistent-memory chat** (`chat.py`): continuous multi-turn conversation with a live
  target (memory resent each turn -> Crescendo pressure), capturing `reasoning_content` for CoT-leak
  detection. Modes: `--send` / `--interactive` / `--auto` (auto-attacker) / `--show` / `--reset`.
  This is how the DeepSeek-R1 reasoning-leak finding was reproduced - see `WRITEUP.md`.

## Not yet implemented (next, per the plan's phases)
- **GCG / AutoDAN (white-box):** need a local HF/transformers model with gradient access - add a
  `targets` adapter exposing logits and a `gcg` attack (use `nanogcg`). White-box only -> then
  **transfer** the suffixes to the black-box adapters. (The local RTX 3090 makes this feasible.)
- **Real many-shot / TAP / AutoDAN-Turbo:** deepen the jailbreak attacks (N=128+ harmful exemplars;
  tree-of-attacks; self-improving strategy library).
- **Multimodal audio** + a phishing/content-insertion objective graded by an LLM obedience-judge.
- **Web-UI driver:** wire Playwright into `WebUITarget.chat` (gated).
- **Standard agentic benchmarks:** run the real AgentDojo / InjecAgent / AgentHarm sets through the
  `--suite agentic` harness (the loop + judge exist; wire the datasets + tool schemas).

## Adding a plugin
Subclass the protocol and register: a `Target` needs `name` + `chat(messages)->str`; an `Attack`
needs `name` + `run(behavior, target, judge)->AttackResult`; a `Judge` needs `grade(...)->(bool, dict)`.

## Authorization / safety
- **Local + your own deployments:** unrestricted, including white-box.
- **APIs:** stay within each provider's usage/red-team policy; use their bug-bounty/red-team programs.
- **Web UI:** `WebUITarget` raises unless `REDTEAM_WEBUI_AUTHORIZED=1` - set it **only** for your own
  hosted UI or a sanctioned/opt-in arena; automating third-party chat UIs may violate ToS.
  Responsibly disclose any real finding.
- Grading uses standardized benchmark behaviors, so the harness measures *robustness* without you
  authoring novel harmful content.
