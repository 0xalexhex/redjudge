#!/usr/bin/env bash
# Benchmark the v0.2.0 automated jailbreak searches (PAIR / TAP / Best-of-N) against a local
# reasoning model, graded by the validated judges (Llama Guard 3 authoritative + StrongREJECT).
# Fills the gap that the v0.2.0 attacks shipped with no real ASR - direct/encoding/manyshot only.
# Everything runs locally via Ollama (free). Raise LIMIT for a fuller run; TAP is query-heavy.
#
#   LIMIT=15 bash scripts/bench_v0_2_attacks.sh
set -euo pipefail
cd "$(dirname "$0")/.."
python3 run.py --benchmark strongreject_small --limit "${LIMIT:-15}" --attacks pair tap bon \
  --target ollama:deepseek-r1:8b --attacker ollama:llama3.1:8b \
  --guard ollama:llama-guard3:8b --judge ollama:llama3.1:8b \
  --out results/bench_v0_2_attacks
