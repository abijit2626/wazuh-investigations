"""Hardcoded fallback event templates.

Used when AI content generation is unavailable (Phase 1 always, Phase 3+
on failure/timeout).  Every template is a complete, schema-valid
NormalizedEvent dict ready for construction.
"""

from __future__ import annotations

from core.models import (
    AttackInfo,
    NormalizedEvent,
    NetworkInfo,
    ProcessInfo,
)


# ---------------------------------------------------------------------------
# Auth fallback templates
# ---------------------------------------------------------------------------

def auth_failure_template(
    *,
    event_id: str,
    timestamp: str,
    host: str,
    user: str,
    src_ip: str,
    technique: str = "T1110.001",
    tactic: str = "Credential Access",
) -> NormalizedEvent:
    """Create a fallback auth_failure event."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        host=host,
        user=user,
        event_category="auth",
        event_type="auth_failure",
        network=NetworkInfo(
            src_ip=src_ip,
            dst_ip="192.168.1.100",
            port=3389,
            protocol="tcp",
        ),
        attack=AttackInfo(
            technique=technique,
            tactic=tactic,
            is_false_positive=False,
        ),
        payload={
            "logon_type": 10,
            "failure_reason": "%%2313",
            "status": "0xC000006D",
            "sub_status": "0xC000006A",
            "auth_package": "Negotiate",
        },
    )


def auth_success_template(
    *,
    event_id: str,
    timestamp: str,
    host: str,
    user: str,
    src_ip: str,
    technique: str = "T1110.001",
    tactic: str = "Credential Access",
) -> NormalizedEvent:
    """Create a fallback auth_success event."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        host=host,
        user=user,
        event_category="auth",
        event_type="auth_success",
        network=NetworkInfo(
            src_ip=src_ip,
            dst_ip="192.168.1.100",
            port=3389,
            protocol="tcp",
        ),
        attack=AttackInfo(
            technique=technique,
            tactic=tactic,
            is_false_positive=False,
        ),
        payload={
            "logon_type": 10,
            "logon_id": "0x3E7",
            "auth_package": "Negotiate",
            "elevated_token": "%%1842",
        },
    )


# ---------------------------------------------------------------------------
# Process fallback templates
# ---------------------------------------------------------------------------

def process_create_template(
    *,
    event_id: str,
    timestamp: str,
    host: str,
    user: str,
    process_name: str = "lsass.exe",
    parent_name: str = "svchost.exe",
    command_line: str = "C:\\Windows\\System32\\lsass.exe",
    pid: int = 672,
    technique: str = "T1003.001",
    tactic: str = "Credential Access",
) -> NormalizedEvent:
    """Create a fallback process_create event."""
    return NormalizedEvent(
        event_id=event_id,
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
            "integrity_level": "System",
            "token_elevation_type": "%%1936",
            "mandatory_label": "S-1-16-16384",
        },
    )


# ---------------------------------------------------------------------------
# Template registry (for programmatic access by category)
# ---------------------------------------------------------------------------

TEMPLATE_REGISTRY: dict[str, dict[str, type]] = {
    "auth": {
        "auth_failure": auth_failure_template,  # type: ignore[dict-item]
        "auth_success": auth_success_template,  # type: ignore[dict-item]
    },
    "process": {
        "process_create": process_create_template,  # type: ignore[dict-item]
    },
}
