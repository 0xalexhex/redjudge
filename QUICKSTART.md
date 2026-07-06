# Quickstart

Get a real result in a few minutes. Three levels, easiest first.

## 0. Run it right now (no setup, no network)

```bash
cd redjudge
python3 run.py --target dryrun --smoke
```

This runs the whole pipeline against a mock model and writes `results/scorecard.md`. It proves the
harness works before you install anything. The core needs only Python 3.10+ (standard library).

## 1. Test a local model (free, private)

Install [Ollama](https://ollama.com), then pull a model to test plus the two local judges:

```bash
ollama pull llama3.1:8b        # the model under test
ollama pull llama-guard3:8b    # the harmful-content classifier (judge)
python3 scripts/get_datasets.py   # fetch the standard benchmarks into ./data (gitignored)
```

Run a real harmful-content benchmark. Targets and judges are passed as short `provider:model`
shortcuts (no JSON):

```bash
python3 run.py --benchmark strongreject_small --limit 15 \
  --target ollama:llama3.1:8b \
  --guard  ollama:llama-guard3:8b \
  --judge  ollama:llama3.1:8b
```

Read `results/scorecard.md`: attack success rate (ASR) per attack, the StrongREJECT usefulness score,
Llama Guard hazard categories, and an over-refusal control. Without `--guard` the score is flagged
UNCALIBRATED (a heuristic number, not a real ASR).

## 2. Test API models (OpenRouter = one key for every model)

Get a key at [openrouter.ai](https://openrouter.ai), add a few dollars of credit, then:

```bash
cp .env.example .env       # then edit .env and set OPENROUTER_API_KEY=sk-or-...
```

Run against any model. Judges stay local (free), so only the model's own answers cost money, and
`--budget` is a hard cap:

```bash
python3 run.py --benchmark strongreject_small --limit 15 --budget 2.0 \
  --target openrouter:openai/gpt-5.5 \
  --target openrouter:anthropic/claude-sonnet-5 \
  --guard  ollama:llama-guard3:8b \
  --judge  ollama:llama3.1:8b
```

Pass `--target` more than once to build a head-to-head leaderboard. Per-model cost is printed at the end.

## Attack suites

Beyond single-turn jailbreaks:

```bash
python3 run.py --suite injection  --target ollama:llama3.1:8b     # indirect prompt injection + defense test
python3 run.py --suite agentic    --target ollama:llama3.1:8b     # tool-using agent, injected tool data
python3 run.py --suite multimodal --target vision:llama3.2-vision:11b   # instruction hidden in an image
```

## Target shortcuts

| shortcut | expands to |
|---|---|
| `dryrun` | offline mock (no network) |
| `ollama:llama3.1:8b` | local Ollama server |
| `openrouter:openai/gpt-5.5` | OpenRouter (needs `OPENROUTER_API_KEY`) |
| `anthropic:claude-sonnet-5` | Anthropic API (needs `ANTHROPIC_API_KEY`) |
| `deepseek:deepseek-reasoner` | DeepSeek API (needs `DEEPSEEK_API_KEY`) |
| `vision:llama3.2-vision:11b` | local vision model (for `--suite multimodal`) |

Power users can still pass a full JSON spec with `--target-spec '{...}'`.
