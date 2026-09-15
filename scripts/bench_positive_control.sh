#!/usr/bin/env bash
# Positive control: run the harmful benchmark against an ABLITERATED / uncensored model, which
# should score a very high ASR. This mirrors the over-refusal control - it proves the judges detect
# COMPLIANCE (not only refusal), so a low ASR elsewhere reflects the target, not a blind grader.
# Point MODEL at any uncensored local model you have pulled.
#
#   MODEL=qwen3.6-heretic:latest LIMIT=15 bash scripts/bench_positive_control.sh
set -euo pipefail
cd "$(dirname "$0")/.."
MODEL="${MODEL:-qwen3.6-heretic:latest}"
python3 run.py --benchmark strongreject_small --limit "${LIMIT:-15}" \
  --target "ollama:${MODEL}" \
  --guard ollama:llama-guard3:8b --judge ollama:llama3.1:8b \
  --out results/bench_positive_control
