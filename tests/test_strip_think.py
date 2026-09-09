"""strip_think decides what the judges see. Everything downstream (refusal grading, canary
location, StrongREJECT/Llama Guard inputs) rides on it, so pin its behavior."""
from redteam.core import strip_think


def test_closed_block_removed():
    assert strip_think("<think>reasoning</think>Final answer.") == "Final answer."


def test_no_think_passthrough():
    assert strip_think("just an answer") == "just an answer"


def test_unclosed_opener_means_no_answer_yet():
    # truncated mid-reasoning at the token cutoff -> there is no final answer
    assert strip_think("<think>still working on it") == ""


def test_eaten_opener_keeps_tail():
    assert strip_think("leftover reasoning</think>the answer") == "the answer"


def test_multiple_blocks_removed():
    assert strip_think("<think>a</think>X<think>b</think>Y") == "XY"


def test_empty_and_none():
    assert strip_think("") == ""
    assert strip_think(None) == ""


def test_tags_are_case_insensitive():
    assert strip_think("<THINK>x</THINK>ans") == "ans"


def test_surrounding_whitespace_stripped():
    assert strip_think("<think>t</think>   answer  ") == "answer"
