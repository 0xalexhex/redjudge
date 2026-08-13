"""Best-of-N reproducibility. The augmentation RNG is seeded from crc32(behavior.id), NOT Python's
salted hash(), so the sampled sequence must be identical across processes with different
PYTHONHASHSEED. Run the same augmentation in subprocesses with different seeds and compare."""
import os
import subprocess
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

SNIP = f"""
import sys; sys.path.insert(0, {str(ROOT)!r})
import random, zlib
from redteam.attacks import BestOfN
b = BestOfN(n=6, seed=0, sigma=0.5)
rng = random.Random((b.seed * 1000003) ^ zlib.crc32(b"beh.123"))
print(repr([b._augment(rng, "the quick brown fox jumps over") for _ in range(5)]))
"""


def _run(hashseed):
    env = dict(os.environ, PYTHONHASHSEED=hashseed)
    r = subprocess.run([sys.executable, "-c", SNIP], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def test_augmentation_is_hashseed_independent():
    assert _run("0") == _run("1") == _run("987654")
