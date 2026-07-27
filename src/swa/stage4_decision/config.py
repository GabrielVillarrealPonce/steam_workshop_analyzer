"""Tunable configuration for Stage 4's decision engine."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DecisionConfig:
    # Composite score at or above which an item is blocked outright.
    block_score: int = 60
    # Composite score at or below which an item is approved (when otherwise clean).
    approve_score: int = 15


DEFAULT_CONFIG = DecisionConfig()
