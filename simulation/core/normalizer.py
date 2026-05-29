"""Schema validation and field stripping for NormalizedEvent.

The Normalizer is the single gatekeeper between generators and the event bus.
It enforces the canonical schema — no None fields leak through, no invalid
categories sneak past.
"""

from __future__ import annotations

import structlog

from core.models import (
    NormalizedEvent,
    VALID_EVENT_CATEGORIES,
    VALID_EVENT_TYPES,
    ProcessInfo,
    NetworkInfo,
    AttackInfo,
)

logger = structlog.get_logger(__name__)


class Normalizer:
    """Validates and strips NormalizedEvent instances before they enter the bus."""

    def validate(self, event: NormalizedEvent) -> NormalizedEvent:
        """Validate *event* against the canonical schema.

        Raises ``ValueError`` on any violation.  Returns the event unmodified
        when valid so callers can chain: ``bus.publish(normalizer.validate(e))``.
        """
        self._check_required_fields(event)
        self._check_category(event)
        self._check_event_type(event)
        self._check_sub_structures(event)
        self._check_no_empty_strings(event)
        return event

    # ------------------------------------------------------------------
    # Private validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _check_required_fields(event: NormalizedEvent) -> None:
        """Ensure all top-level required fields are present and non-None."""
        required = ("event_id", "timestamp", "host", "user", "event_category", "event_type")
        for field_name in required:
            value = getattr(event, field_name, None)
            if value is None:
                raise ValueError(f"Required field '{field_name}' is None")

    @staticmethod
    def _check_category(event: NormalizedEvent) -> None:
        """Ensure event_category is one of the allowed values."""
        if event.event_category not in VALID_EVENT_CATEGORIES:
            raise ValueError(
                f"Invalid event_category '{event.event_category}'. "
                f"Must be one of: {sorted(VALID_EVENT_CATEGORIES)}"
            )

    @staticmethod
    def _check_event_type(event: NormalizedEvent) -> None:
        """Ensure event_type is one of the allowed values."""
        if event.event_type not in VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{event.event_type}'. "
                f"Must be one of: {sorted(VALID_EVENT_TYPES)}"
            )

    @staticmethod
    def _check_sub_structures(event: NormalizedEvent) -> None:
        """Validate sub-structure types when present."""
        if event.process is not None and not isinstance(event.process, ProcessInfo):
            raise ValueError(
                f"'process' field must be ProcessInfo, got {type(event.process).__name__}"
            )
        if event.network is not None and not isinstance(event.network, NetworkInfo):
            raise ValueError(
                f"'network' field must be NetworkInfo, got {type(event.network).__name__}"
            )
        if event.attack is not None and not isinstance(event.attack, AttackInfo):
            raise ValueError(
                f"'attack' field must be AttackInfo, got {type(event.attack).__name__}"
            )
        if event.payload is not None and not isinstance(event.payload, dict):
            raise ValueError(
                f"'payload' field must be dict, got {type(event.payload).__name__}"
            )

    @staticmethod
    def _check_no_empty_strings(event: NormalizedEvent) -> None:
        """Reject empty-string values in top-level required fields."""
        string_fields = ("event_id", "timestamp", "host", "user", "event_category", "event_type")
        for field_name in string_fields:
            value = getattr(event, field_name)
            if isinstance(value, str) and value.strip() == "":
                raise ValueError(f"Required field '{field_name}' is an empty string")
