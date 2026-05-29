"""Tests for core data models and schema validation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest

from core.models import (
    AttackInfo,
    Host,
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    ScenarioSpec,
    User,
    Attacker,
    VALID_EVENT_CATEGORIES,
    VALID_EVENT_TYPES,
)
from core.normalizer import Normalizer


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def normalizer() -> Normalizer:
    """Fresh normalizer instance."""
    return Normalizer()


@pytest.fixture
def valid_auth_event() -> NormalizedEvent:
    """A fully valid auth_failure event."""
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        host="DESKTOP-W11LAB",
        user="jsmith",
        event_category="auth",
        event_type="auth_failure",
        network=NetworkInfo(
            src_ip="185.220.101.47",
            dst_ip="192.168.1.100",
            port=3389,
            protocol="tcp",
        ),
        attack=AttackInfo(
            technique="T1110.001",
            tactic="Credential Access",
            is_false_positive=False,
        ),
        payload={"logon_type": 10, "failure_reason": "%%2313"},
    )


@pytest.fixture
def valid_process_event() -> NormalizedEvent:
    """A fully valid process_create event."""
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        host="DESKTOP-W11LAB",
        user="jsmith",
        event_category="process",
        event_type="process_create",
        process=ProcessInfo(
            name="lsass.exe",
            parent="svchost.exe",
            command_line=r"C:\Windows\System32\lsass.exe",
            pid=672,
        ),
        attack=AttackInfo(
            technique="T1003.001",
            tactic="Credential Access",
            is_false_positive=False,
        ),
    )


# ---------------------------------------------------------------------------
# NormalizedEvent tests
# ---------------------------------------------------------------------------

class TestNormalizedEvent:
    """Tests for NormalizedEvent dataclass."""

    def test_to_dict_omits_none_fields(self, valid_auth_event: NormalizedEvent) -> None:
        """None optional fields must not appear in the dict."""
        d = valid_auth_event.to_dict()
        assert "process" not in d
        assert "event_id" in d
        assert "network" in d
        assert "attack" in d

    def test_to_dict_includes_all_set_fields(self, valid_process_event: NormalizedEvent) -> None:
        """Set optional fields must appear in the dict."""
        d = valid_process_event.to_dict()
        assert "process" in d
        assert d["process"]["name"] == "lsass.exe"
        assert "network" not in d  # not set on process event

    def test_to_dict_payload_included(self, valid_auth_event: NormalizedEvent) -> None:
        """Payload dict must be included when present."""
        d = valid_auth_event.to_dict()
        assert "payload" in d
        assert d["payload"]["logon_type"] == 10

    def test_to_dict_no_payload_when_none(self) -> None:
        """Payload must not appear when not set."""
        event = NormalizedEvent(
            event_id="test-id",
            timestamp="2025-01-01T00:00:00Z",
            host="HOST",
            user="user",
            event_category="auth",
            event_type="auth_failure",
        )
        d = event.to_dict()
        assert "payload" not in d


# ---------------------------------------------------------------------------
# Normalizer validation tests
# ---------------------------------------------------------------------------

class TestNormalizerValidation:
    """Tests for Normalizer.validate()."""

    def test_valid_auth_event_passes(
        self, normalizer: Normalizer, valid_auth_event: NormalizedEvent
    ) -> None:
        """A well-formed auth event must pass validation."""
        result = normalizer.validate(valid_auth_event)
        assert result is valid_auth_event

    def test_valid_process_event_passes(
        self, normalizer: Normalizer, valid_process_event: NormalizedEvent
    ) -> None:
        """A well-formed process event must pass validation."""
        result = normalizer.validate(valid_process_event)
        assert result is valid_process_event

    def test_invalid_category_raises(self, normalizer: Normalizer) -> None:
        """An invalid event_category must raise ValueError."""
        event = NormalizedEvent(
            event_id="test-id",
            timestamp="2025-01-01T00:00:00Z",
            host="HOST",
            user="user",
            event_category="invalid_category",
            event_type="auth_failure",
        )
        with pytest.raises(ValueError, match="Invalid event_category"):
            normalizer.validate(event)

    def test_invalid_event_type_raises(self, normalizer: Normalizer) -> None:
        """An invalid event_type must raise ValueError."""
        event = NormalizedEvent(
            event_id="test-id",
            timestamp="2025-01-01T00:00:00Z",
            host="HOST",
            user="user",
            event_category="auth",
            event_type="nonexistent_type",
        )
        with pytest.raises(ValueError, match="Invalid event_type"):
            normalizer.validate(event)

    def test_empty_string_host_raises(self, normalizer: Normalizer) -> None:
        """An empty-string required field must raise ValueError."""
        event = NormalizedEvent(
            event_id="test-id",
            timestamp="2025-01-01T00:00:00Z",
            host="",
            user="user",
            event_category="auth",
            event_type="auth_failure",
        )
        with pytest.raises(ValueError, match="empty string"):
            normalizer.validate(event)

    def test_empty_string_user_raises(self, normalizer: Normalizer) -> None:
        """An empty-string user field must raise ValueError."""
        event = NormalizedEvent(
            event_id="test-id",
            timestamp="2025-01-01T00:00:00Z",
            host="HOST",
            user="  ",
            event_category="auth",
            event_type="auth_failure",
        )
        with pytest.raises(ValueError, match="empty string"):
            normalizer.validate(event)

    def test_wrong_process_type_raises(self, normalizer: Normalizer) -> None:
        """A non-ProcessInfo process field must raise ValueError."""
        event = NormalizedEvent(
            event_id="test-id",
            timestamp="2025-01-01T00:00:00Z",
            host="HOST",
            user="user",
            event_category="process",
            event_type="process_create",
            process={"name": "bad"},  # type: ignore[arg-type]
        )
        with pytest.raises(ValueError, match="ProcessInfo"):
            normalizer.validate(event)

    def test_wrong_network_type_raises(self, normalizer: Normalizer) -> None:
        """A non-NetworkInfo network field must raise ValueError."""
        event = NormalizedEvent(
            event_id="test-id",
            timestamp="2025-01-01T00:00:00Z",
            host="HOST",
            user="user",
            event_category="auth",
            event_type="auth_failure",
            network="bad",  # type: ignore[arg-type]
        )
        with pytest.raises(ValueError, match="NetworkInfo"):
            normalizer.validate(event)


# ---------------------------------------------------------------------------
# Environment entity tests
# ---------------------------------------------------------------------------

class TestEntityModels:
    """Tests for Host, User, Attacker, ScenarioSpec."""

    def test_host_frozen(self) -> None:
        """Host must be immutable."""
        host = Host(name="DESKTOP-W11LAB", ip="192.168.1.100", os="Windows 11")
        with pytest.raises(AttributeError):
            host.name = "changed"  # type: ignore[misc]

    def test_user_frozen(self) -> None:
        """User must be immutable."""
        user = User(username="jsmith", domain="LAB", role="user")
        with pytest.raises(AttributeError):
            user.username = "changed"  # type: ignore[misc]

    def test_attacker_frozen(self) -> None:
        """Attacker must be immutable."""
        attacker = Attacker(src_ip="1.2.3.4", geo="US")
        with pytest.raises(AttributeError):
            attacker.src_ip = "changed"  # type: ignore[misc]

    def test_scenario_spec_fields(self) -> None:
        """ScenarioSpec must hold all required fields."""
        spec = ScenarioSpec(
            scenario_type="brute_force",
            mitre_technique="T1110.001",
            tactic="Credential Access",
            sophistication=3,
            pacing="slow",
            event_count=52,
            dwell_seconds=480.0,
            target_host="DESKTOP-W11LAB",
            target_user="jsmith",
            required_generators=["auth", "process"],
        )
        assert spec.scenario_type == "brute_force"
        assert spec.sophistication == 3
        assert len(spec.required_generators) == 2

    def test_valid_event_categories_complete(self) -> None:
        """VALID_EVENT_CATEGORIES must contain all six categories."""
        expected = {"process", "auth", "network", "dns", "registry", "filesystem"}
        assert VALID_EVENT_CATEGORIES == expected
