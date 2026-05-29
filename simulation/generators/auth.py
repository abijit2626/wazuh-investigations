"""Authentication event generator.

Produces auth_failure and auth_success NormalizedEvents using SimContext
state and fallback templates.  AI enrichment is a no-op in Phase 1.
"""

from __future__ import annotations

import random
import uuid
from typing import Any

import structlog

from core.context import SimContext
from core.models import AttackInfo, NetworkInfo, NormalizedEvent
from generators.base import BaseGenerator

logger = structlog.get_logger(__name__)

# Realistic Windows failure reasons
_FAILURE_REASONS: list[str] = [
    "%%2313",   # Unknown user name or bad password
    "%%2304",   # An Error occurred during Logon
    "%%2305",   # The specified user account has expired
    "%%2309",   # The specified account's password has expired
]

_STATUS_CODES: list[str] = [
    "0xC000006D",  # STATUS_LOGON_FAILURE
    "0xC000006A",  # STATUS_WRONG_PASSWORD
    "0xC0000064",  # STATUS_NO_SUCH_USER
    "0xC0000234",  # STATUS_ACCOUNT_LOCKED_OUT
]

_SUB_STATUS_CODES: list[str] = [
    "0xC000006A",  # STATUS_WRONG_PASSWORD
    "0xC0000064",  # STATUS_NO_SUCH_USER
    "0x00000000",  # No sub-status
]

_LOGON_TYPES: list[int] = [2, 3, 7, 10]  # Interactive, Network, Unlock, RemoteInteractive

_AUTH_PACKAGES: list[str] = ["Negotiate", "NTLM", "Kerberos"]


class AuthGenerator(BaseGenerator):
    """Generates authentication events (failures and successes)."""

    def __init__(self, context: SimContext) -> None:
        """Bind to a SimContext."""
        super().__init__(context)

    def generate(self, **kwargs: Any) -> NormalizedEvent:
        """Generate a single auth event.

        Keyword Args:
            event_type: ``"auth_failure"`` or ``"auth_success"`` (default: failure).
            timestamp: ISO8601 timestamp string (required).
            user: Target username (falls back to first user in context).
            host: Target hostname (falls back to first host in context).
            src_ip: Source IP of the auth attempt (falls back to attacker IP).
            technique: MITRE technique ID (default: T1110.001).
            tactic: MITRE tactic name (default: Credential Access).
        """
        event_type: str = kwargs.get("event_type", "auth_failure")
        timestamp: str = kwargs["timestamp"]
        user: str = kwargs.get("user", self._context.users[0].username)
        host: str = kwargs.get("host", self._context.hosts[0].name)
        src_ip: str = kwargs.get("src_ip", self._context.attacker.src_ip)
        dst_ip: str = kwargs.get("dst_ip", self._context.hosts[0].ip)
        technique: str = kwargs.get("technique", "T1110.001")
        tactic: str = kwargs.get("tactic", "Credential Access")

        if event_type == "auth_failure":
            payload = self._failure_payload()
        else:
            payload = self._success_payload()

        event = NormalizedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            host=host,
            user=user,
            event_category="auth",
            event_type=event_type,
            network=NetworkInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=3389,
                protocol="tcp",
            ),
            attack=AttackInfo(
                technique=technique,
                tactic=tactic,
                is_false_positive=False,
            ),
            payload=payload,
        )
        logger.debug(
            "auth_event_generated",
            event_type=event_type,
            user=user,
            host=host,
            src_ip=src_ip,
        )
        return event

    def validate(self, event: NormalizedEvent) -> bool:
        """Check that an auth event has the required fields."""
        if event.event_category != "auth":
            return False
        if event.event_type not in ("auth_failure", "auth_success"):
            return False
        if event.network is None:
            return False
        if event.attack is None:
            return False
        return True

    def enrich(self, event: NormalizedEvent) -> NormalizedEvent:
        """Enrich an auth event (no-op in Phase 1)."""
        return event

    # ------------------------------------------------------------------
    # Private payload builders
    # ------------------------------------------------------------------

    @staticmethod
    def _failure_payload() -> dict[str, Any]:
        """Build a realistic Windows auth failure payload."""
        return {
            "logon_type": random.choice(_LOGON_TYPES),
            "failure_reason": random.choice(_FAILURE_REASONS),
            "status": random.choice(_STATUS_CODES),
            "sub_status": random.choice(_SUB_STATUS_CODES),
            "auth_package": random.choice(_AUTH_PACKAGES),
            "workstation_name": f"WORK-{random.randint(100, 999)}",
        }

    @staticmethod
    def _success_payload() -> dict[str, Any]:
        """Build a realistic Windows auth success payload."""
        return {
            "logon_type": random.choice(_LOGON_TYPES),
            "logon_id": f"0x{random.randint(0x1000, 0xFFFF):X}",
            "auth_package": random.choice(_AUTH_PACKAGES),
            "elevated_token": random.choice(["%%1842", "%%1843"]),
            "workstation_name": f"WORK-{random.randint(100, 999)}",
        }
