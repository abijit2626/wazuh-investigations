"""Abstract base class for all event generators.

Every concrete generator (auth, process, network, noise) extends this ABC
and must implement generate(), validate(), and enrich().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from core.context import SimContext
from core.models import NormalizedEvent


class BaseGenerator(ABC):
    """Abstract event generator.

    Subclasses produce NormalizedEvent instances from SimContext state
    and (in later phases) AI-enriched content pools.
    """

    def __init__(self, context: SimContext) -> None:
        """Bind this generator to a SimContext."""
        self._context = context

    @abstractmethod
    def generate(self, **kwargs: Any) -> NormalizedEvent:
        """Produce a single NormalizedEvent."""

    @abstractmethod
    def validate(self, event: NormalizedEvent) -> bool:
        """Return True if *event* is well-formed for this generator's domain."""

    @abstractmethod
    def enrich(self, event: NormalizedEvent) -> NormalizedEvent:
        """Enrich *event* with additional context (AI or template)."""
