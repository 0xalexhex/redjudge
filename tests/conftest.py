"""Shared test setup: put the package on sys.path and isolate the global cost meter per test."""
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest
from redteam.targets import reset_meter


@pytest.fixture(autouse=True)
def _clean_meter():
    reset_meter()
    yield
    reset_meter()
