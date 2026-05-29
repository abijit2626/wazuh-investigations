"""Wazuh file output adapter.

Writes NormalizedEvents as ndjson to a log file monitored by Wazuh's
localfile configuration.  Maps NormalizedEvent fields to Wazuh's expected
nested structure so Wazuh decoders can parse them correctly.

File rotation at a configurable size limit (default 50 MB).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import structlog

from adapters.base import BaseOutputAdapter
from core.models import NormalizedEvent

logger = structlog.get_logger(__name__)

# Wazuh rule ID mapping by event_type
_RULE_ID_MAP: dict[str, int] = {
    "auth_failure": 60122,
    "auth_success": 60106,
    "process_create": 92100,
    "network_connection": 92200,
}

_MAX_ROTATION_FILES: int = 5


class WazuhFileAdapter(BaseOutputAdapter):
    """Writes Wazuh-formatted ndjson to a monitored log file."""

    def __init__(self, file_path: str, max_size_mb: int = 50) -> None:
        """Open the output file and set the rotation threshold.

        Args:
            file_path: Path to the ndjson log file.
            max_size_mb: Rotate when file exceeds this size in megabytes.
        """
        self._file_path = Path(file_path)
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._file_path, "a", encoding="utf-8")
        self._bytes_written: int = (
            self._file_path.stat().st_size if self._file_path.exists() else 0
        )
        logger.info(
            "wazuh_adapter_opened",
            path=str(self._file_path),
            max_size_mb=max_size_mb,
        )

    def write(self, event: NormalizedEvent) -> None:
        """Map event to Wazuh format and write as one ndjson line."""
        wazuh_doc = self._map_to_wazuh(event)
        line = json.dumps(wazuh_doc, separators=(",", ":")) + "\n"
        self._fh.write(line)
        self._fh.flush()
        self._bytes_written += len(line.encode("utf-8"))
        if self._bytes_written >= self._max_size_bytes:
            self._rotate()

    def close(self) -> None:
        """Flush and close the underlying file handle."""
        if self._fh and not self._fh.closed:
            self._fh.flush()
            self._fh.close()
            logger.info("wazuh_adapter_closed", path=str(self._file_path))

    # ------------------------------------------------------------------
    # Wazuh field mapping
    # ------------------------------------------------------------------

    def _map_to_wazuh(self, event: NormalizedEvent) -> dict[str, Any]:
        """Convert a NormalizedEvent to Wazuh's nested field structure."""
        rule_id = _RULE_ID_MAP.get(event.event_type, 0)

        wazuh: dict[str, Any] = {
            "timestamp": event.timestamp,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "type": event.event_category,
            "agent": {"name": event.host},
            "rule": {"id": str(rule_id)},
        }

        # MITRE mapping
        if event.attack is not None:
            wazuh["rule"]["mitre"] = {
                "technique": [event.attack.technique],
                "tactic": [event.attack.tactic],
            }
            if event.attack.is_false_positive:
                wazuh["is_false_positive"] = True

        # User mapping — auth events use targetUserName, others use user
        eventdata: dict[str, Any] = {}
        if event.event_category == "auth":
            eventdata["targetUserName"] = event.user
        else:
            eventdata["user"] = event.user

        # Process fields
        if event.process is not None:
            eventdata["image"] = event.process.name
            eventdata["parentImage"] = event.process.parent
            eventdata["commandLine"] = event.process.command_line
            eventdata["processId"] = str(event.process.pid)

        # Network fields
        if event.network is not None:
            eventdata["sourceIp"] = event.network.src_ip
            eventdata["destinationIp"] = event.network.dst_ip
            eventdata["destinationPort"] = str(event.network.port)
            eventdata["protocol"] = event.network.protocol

        # Payload (open schema)
        if event.payload is not None:
            eventdata.update(
                {k: str(v) if not isinstance(v, str) else v for k, v in event.payload.items()}
            )

        if eventdata:
            wazuh["data"] = {"win": {"eventdata": eventdata}}

        return wazuh

    # ------------------------------------------------------------------
    # File rotation
    # ------------------------------------------------------------------

    def _rotate(self) -> None:
        """Rotate the log file, keeping up to _MAX_ROTATION_FILES backups."""
        self._fh.close()

        # Shift existing rotated files
        for i in range(_MAX_ROTATION_FILES - 1, 0, -1):
            src = self._file_path.with_suffix(f".log.{i}")
            dst = self._file_path.with_suffix(f".log.{i + 1}")
            if src.exists():
                src.rename(dst)

        # Rotate current file to .1
        rotated = self._file_path.with_suffix(f".log.1")
        if self._file_path.exists():
            self._file_path.rename(rotated)

        # Open fresh file
        self._fh = open(self._file_path, "a", encoding="utf-8")
        self._bytes_written = 0
        logger.info("wazuh_log_rotated", path=str(self._file_path))
