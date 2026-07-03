#!/usr/bin/env bash
# Cross-model robustness sweep over OpenRouter models. Targets are PAID (OpenRouter); judges +
# attacker are LOCAL Ollama (free). Reads OPENROUTER_API_KEY from redjudge/.env. Hard $4 kill-switch
# per run + OpenRouter's own account cap as backstops. Reproducible: one command, all 10 models.
set -uo pipefail
cd "$(dirname "$0")/.."
OR='https://openrouter.ai/api/v1'
spec(){ printf '{"kind":"openai_compat","base_url":"%s","model":"%s","api_key_env":"OPENROUTER_API_KEY","name":"%s","max_tokens":512}' "$OR" "$1" "$2"; }
TARGETS=(
  --target-spec "$(spec openai/gpt-5.5                  gpt-5.5)"
  --target-spec "$(spec openai/gpt-5.4-mini             gpt-5.4-mini)"
  --target-spec "$(spec anthropic/claude-opus-4.8       opus-4.8)"
  --target-spec "$(spec anthropic/claude-sonnet-5       sonnet-5)"
  --target-spec "$(spec anthropic/claude-haiku-4.5      haiku-4.5)"
  --target-spec "$(spec google/gemini-3.1-pro-preview   gemini-3.1-pro)"
  --target-spec "$(spec x-ai/grok-4.3                   grok-4.3)"
  --target-spec "$(spec deepseek/deepseek-v3.2          deepseek-v3.2)"
  --target-spec "$(spec meta-llama/llama-4-maverick     llama-4-maverick)"
  --target-spec "$(spec qwen/qwen3-max                  qwen3-max)"
)
GUARD='{"base_url":"http://localhost:11434","model":"llama-guard3:8b"}'
JUDGE='{"kind":"openai_compat","base_url":"http://localhost:11434/v1","model":"llama3.1:8b"}'

echo "########## SWEEP A - harmful-content leaderboard (StrongREJECT-15 + over-refusal) ##########"
python3 run.py --benchmark strongreject_small --limit 15 --attacks direct encoding manyshot \
  --benign jbb_benign --benign-limit 8 --budget 4.0 --out results/bench_or_core \
  --guard-model "$GUARD" --judge-model "$JUDGE" "${TARGETS[@]}"

echo "########## SWEEP B - indirect-injection leaderboard (6x5 + Spotlighting defense) ##########"
python3 run.py --suite injection --budget 4.0 --out results/bench_or_injection "${TARGETS[@]}"

echo "########## SWEEP COMPLETE ##########"
