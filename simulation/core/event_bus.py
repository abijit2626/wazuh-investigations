"""Synchronous event bus (Phase 1).

Receives validated NormalizedEvents and fans them out to all registered
output adapters.  Will be replaced by an async version in Phase 2.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from core.normalizer import Normalizer

if TYPE_CHECKING:
    from adapters.base import BaseOutputAdapter
    from core.models import NormalizedEvent

logger = structlog.get_logger(__name__)


class EventBus:
    """Synchronous publish-to-adapters event bus."""

    def __init__(self) -> None:
        """Initialize with an empty adapter list and a Normalizer."""
        self._adapters: list[BaseOutputAdapter] = []
        self._normalizer = Normalizer()
        self._event_count: int = 0

    def register_adapter(self, adapter: BaseOutputAdapter) -> None:
        """Register an output adapter to receive events."""
        self._adapters.append(adapter)
        logger.info("adapter_registered", adapter=type(adapter).__name__)

    def publish(self, event: NormalizedEvent) -> None:
        """Validate and fan-out *event* to all registered adapters."""
        validated = self._normalizer.validate(event)
        for adapter in self._adapters:
            try:
                adapter.write(validated)
            except Exception:
                logger.exception(
                    "adapter_write_failed",
                    adapter=type(adapter).__name__,
                    event_id=validated.event_id,
                )
        self._event_count += 1

    @property
    def event_count(self) -> int:
        """Total events published so far."""
        return self._event_count

    def close(self) -> None:
        """Close all registered adapters."""
        for adapter in self._adapters:
            try:
                adapter.close()
            except Exception:
                logger.exception(
                    "adapter_close_failed",
                    adapter=type(adapter).__name__,
                )
