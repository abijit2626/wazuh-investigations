"""JSON debug output adapter.

Writes NormalizedEvents as pretty-printed ndjson for human inspection.
Always available regardless of phase — useful for development and debugging.
"""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from adapters.base import BaseOutputAdapter
from core.models import NormalizedEvent

logger = structlog.get_logger(__name__)


class JSONFileAdapter(BaseOutputAdapter):
    """Writes raw NormalizedEvent dicts as ndjson for debugging."""

    def __init__(self, file_path: str) -> None:
        """Open the debug output file.

        Args:
            file_path: Path to the ndjson debug log.
        """
        self._file_path = Path(file_path)
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._file_path, "a", encoding="utf-8")
        logger.info("json_debug_adapter_opened", path=str(self._file_path))

    def write(self, event: NormalizedEvent) -> None:
        """Write event as one ndjson line (compact JSON, no Wazuh mapping)."""
        line = json.dumps(event.to_dict(), separators=(",", ":")) + "\n"
        self._fh.write(line)
        self._fh.flush()

    def close(self) -> None:
        """Flush and close the file handle."""
        if self._fh and not self._fh.closed:
            self._fh.flush()
            self._fh.close()
            logger.info("json_debug_adapter_closed", path=str(self._file_path))
