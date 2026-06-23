#!/usr/bin/env python3
"""
Fetch STANDARD academic red-team benchmarks on demand (they are NOT bundled in the repo).

Rationale: redjudge ships no operational harmful content. These are the field-standard
"should-refuse" behavior sets used to *measure robustness* (HarmBench/JBB/AdvBench/StrongREJECT)
plus benign controls for over-refusal - the same datasets every serious eval uses. We download
them into a gitignored `data/` dir so the repo stays clean and you opt in explicitly.

  python3 scripts/get_datasets.py            # fetch all into ./data
  python3 scripts/get_datasets.py --only strongreject_small jbb_harmful
  python3 scripts/get_datasets.py --force    # re-download

Authorized robustness evaluation only. Stdlib-only (urllib), consistent with the harness.
"""
from __future__ import annotations
import argparse, sys, urllib.request
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"

# name -> (url, description). Filenames are "<name>.csv".
SOURCES = {
    # harmful "should-refuse" behavior sets (measure jailbreak/attack success = model complied)
    "advbench":          ("https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv",
                          "AdvBench 520 harmful behaviors (Zou et al. 2023, GCG paper)"),
    "jbb_harmful":       ("https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main/data/harmful-behaviors.csv",
                          "JailbreakBench JBB-Behaviors: 100 harmful, policy-aligned (NeurIPS 2024 D&B)"),
    "strongreject":      ("https://raw.githubusercontent.com/alexandrasouly/strongreject/main/strongreject_dataset/strongreject_dataset.csv",
                          "StrongREJECT full 313 forbidden prompts (Souly et al. 2024)"),
    "strongreject_small":("https://raw.githubusercontent.com/alexandrasouly/strongreject/main/strongreject_dataset/strongreject_small_dataset.csv",
                          "StrongREJECT small 60 prompts (balanced categories) - good quick run"),
    # benign controls (measure OVER-refusal = model wrongly refused something safe)
    "jbb_benign":        ("https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main/data/benign-behaviors.csv",
                          "JBB 100 benign behaviors - over-refusal control (matched to the harmful set)"),
    "xstest":            ("https://raw.githubusercontent.com/paul-rottger/xstest/main/xstest_prompts.csv",
                          "XSTest 250 safe + 200 unsafe prompts - exaggerated-safety test (Röttger et al.)"),
}


def fetch(name: str, url: str, force: bool) -> str:
    out = DATA / f"{name}.csv"
    if out.exists() and not force:
        return f"  = {name:20} exists ({out.stat().st_size:,} B) - skip (use --force to refresh)"
    req = urllib.request.Request(url, headers={"User-Agent": "redjudge/get_datasets"})
    with urllib.request.urlopen(req, timeout=60) as r:   # urllib follows 3xx redirects (HF uses them)
        blob = r.read()
    out.write_bytes(blob)
    n = blob.count(b"\n")
    return f"  + {name:20} {len(blob):>9,} B  (~{n} rows)  {out}"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="*", choices=list(SOURCES), help="fetch only these (default: all)")
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    a = ap.parse_args()
    DATA.mkdir(parents=True, exist_ok=True)
    names = a.only or list(SOURCES)
    print(f"[i] fetching {len(names)} dataset(s) into {DATA}")
    print("    (standard academic red-team benchmarks; authorized robustness evaluation only)\n")
    ok, fail = 0, 0
    for name in names:
        url, desc = SOURCES[name]
        print(f"· {name}: {desc}")
        try:
            print(fetch(name, url, a.force)); ok += 1
        except Exception as e:
            print(f"  ! FAILED {name}: {e}"); fail += 1
    print(f"\n[done] {ok} ok, {fail} failed. Run e.g.:  python3 run.py --benchmark strongreject_small ...")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
