"""Abstract base class for output adapters.

Every concrete adapter (Wazuh file, JSON debug, syslog, elastic) extends
this ABC and must implement write() and close().
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from core.models import NormalizedEvent


class BaseOutputAdapter(ABC):
    """Abstract output adapter — receives validated NormalizedEvents."""

    @abstractmethod
    def write(self, event: NormalizedEvent) -> None:
        """Write a single event to the output destination."""

    @abstractmethod
    def close(self) -> None:
        """Flush buffers and release resources."""
