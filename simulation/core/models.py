"""Core data models for the adversary telemetry generator.

All domain objects are frozen-where-practical dataclasses.
NormalizedEvent is the single canonical event shape that every generator
emits and every adapter consumes.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Literal, Optional


# ---------------------------------------------------------------------------
# Sub-structures embedded in NormalizedEvent
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ProcessInfo:
    """Process execution details."""

    name: str
    parent: str
    command_line: str
    pid: int


@dataclass(slots=True)
class NetworkInfo:
    """Network connection details."""

    src_ip: str
    dst_ip: str
    port: int
    protocol: str


@dataclass(slots=True)
class AttackInfo:
    """MITRE ATT&CK classification."""

    technique: str
    tactic: str
    is_false_positive: bool = False


# ---------------------------------------------------------------------------
# Canonical event — the only shape that crosses module boundaries
# ---------------------------------------------------------------------------

VALID_EVENT_CATEGORIES: frozenset[str] = frozenset(
    {"process", "auth", "network", "dns", "registry", "filesystem"}
)

VALID_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "process_create",
        "auth_failure",
        "auth_success",
        "network_connection",
        "dns_query",
        "registry_modify",
        "file_create",
        "file_modify",
        "file_delete",
    }
)


@dataclass(slots=True)
class NormalizedEvent:
    """Single normalized telemetry event.

    Optional sub-structures (process, network, attack, payload) are omitted
    entirely when not relevant to the event type — never null, never empty.
    """

    event_id: str
    timestamp: str
    host: str
    user: str
    event_category: str
    event_type: str
    process: Optional[ProcessInfo] = None
    network: Optional[NetworkInfo] = None
    attack: Optional[AttackInfo] = None
    payload: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict, omitting None fields at every level."""
        result: dict[str, Any] = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "host": self.host,
            "user": self.user,
            "event_category": self.event_category,
            "event_type": self.event_type,
        }
        if self.process is not None:
            result["process"] = asdict(self.process)
        if self.network is not None:
            result["network"] = asdict(self.network)
        if self.attack is not None:
            result["attack"] = asdict(self.attack)
        if self.payload is not None:
            result["payload"] = self.payload
        return result


# ---------------------------------------------------------------------------
# Environment entities
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Host:
    """A simulated endpoint."""

    name: str
    ip: str
    os: str


@dataclass(frozen=True, slots=True)
class User:
    """A simulated user account."""

    username: str
    domain: str
    role: str


@dataclass(frozen=True, slots=True)
class Attacker:
    """Attacker profile."""

    src_ip: str
    geo: str
    isp: str = "Unknown"


# ---------------------------------------------------------------------------
# Scenario specification — typed handoff from ScenarioBrain to engine
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class ScenarioSpec:
    """Typed scenario descriptor.  No bare dicts cross module boundaries."""

    scenario_type: str
    mitre_technique: str
    tactic: str
    sophistication: int  # 1-5
    pacing: Literal["slow", "burst"]
    event_count: int
    dwell_seconds: float
    target_host: str
    target_user: str
    required_generators: list[str] = field(default_factory=list)
