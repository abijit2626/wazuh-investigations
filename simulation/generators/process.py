"""Process execution event generator.

Produces process_create NormalizedEvents.  In Phase 1, values come from
hardcoded command-line lists.  AI enrichment is a no-op.
"""

from __future__ import annotations

import random
import uuid
from typing import Any

import structlog

from core.context import SimContext
from core.models import AttackInfo, NormalizedEvent, ProcessInfo
from generators.base import BaseGenerator

logger = structlog.get_logger(__name__)

# Realistic Windows process names for credential access
_LSASS_COMMAND_LINES: list[str] = [
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\lsass.exe --dump",
    r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\temp\lsass.dmp full",
    r"procdump.exe -accepteula -ma lsass.exe C:\temp\lsass.dmp",
    r"C:\Windows\System32\lsass.exe",
]

_PARENT_PROCESSES: list[str] = [
    "svchost.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
]

_SUSPICIOUS_PARENTS: list[str] = [
    "cmd.exe",
    "powershell.exe",
    "explorer.exe",
    "wmiprvse.exe",
]


class ProcessGenerator(BaseGenerator):
    """Generates process creation events."""

    def __init__(self, context: SimContext) -> None:
        """Bind to a SimContext."""
        super().__init__(context)

    def generate(self, **kwargs: Any) -> NormalizedEvent:
        """Generate a single process_create event.

        Keyword Args:
            timestamp: ISO8601 timestamp string (required).
            user: User context for the process (falls back to first user).
            host: Target hostname (falls back to first host).
            process_name: Name of the spawned process (default: lsass.exe).
            parent_name: Parent process name (default: random from list).
            command_line: Full command line (default: random from list).
            pid: Process ID (default: random).
            technique: MITRE technique ID (default: T1003.001).
            tactic: MITRE tactic name (default: Credential Access).
            suspicious: If True, use suspicious parent process (default: False).
        """
        timestamp: str = kwargs["timestamp"]
        user: str = kwargs.get("user", self._context.users[0].username)
        host: str = kwargs.get("host", self._context.hosts[0].name)
        process_name: str = kwargs.get("process_name", "lsass.exe")
        suspicious: bool = kwargs.get("suspicious", False)
        parent_name: str = kwargs.get(
            "parent_name",
            random.choice(_SUSPICIOUS_PARENTS if suspicious else _PARENT_PROCESSES),
        )
        command_line: str = kwargs.get("command_line", random.choice(_LSASS_COMMAND_LINES))
        pid: int = kwargs.get("pid", random.randint(500, 65535))
        technique: str = kwargs.get("technique", "T1003.001")
        tactic: str = kwargs.get("tactic", "Credential Access")

        event = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            host=host,
            user=user,
            event_category="process",
            event_type="process_create",
            process=ProcessInfo(
                name=process_name,
                parent=parent_name,
                command_line=command_line,
                pid=pid,
            ),
            attack=AttackInfo(
                technique=technique,
                tactic=tactic,
                is_false_positive=False,
            ),
            payload={
                "integrity_level": random.choice(["System", "High", "Medium"]),
                "token_elevation_type": random.choice(["%%1936", "%%1937", "%%1938"]),
                "mandatory_label": "S-1-16-16384",
                "current_directory": r"C:\Windows\System32",
            },
        )
        logger.debug(
            "process_event_generated",
            process=process_name,
            parent=parent_name,
            user=user,
            host=host,
        )
        return event

    def validate(self, event: NormalizedEvent) -> bool:
        """Check that a process event has the required fields."""
        if event.event_category != "process":
            return False
        if event.event_type != "process_create":
            return False
        if event.process is None:
            return False
        if event.attack is None:
            return False
        return True

    def enrich(self, event: NormalizedEvent) -> NormalizedEvent:
        """Enrich a process event (no-op in Phase 1)."""
        return event
