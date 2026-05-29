"""Tests for event generators (AuthGenerator, ProcessGenerator)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.context import SimContext
from core.models import Attacker, Host, User
from core.normalizer import Normalizer
from generators.auth import AuthGenerator
from generators.process import ProcessGenerator


@pytest.fixture
def sim_context() -> SimContext:
    """Build a minimal SimContext for testing."""
    return SimContext(
        hosts=[Host(name="DESKTOP-W11LAB", ip="192.168.1.100", os="Windows 11")],
        users=[User(username="jsmith", domain="LAB", role="user")],
        attacker=Attacker(src_ip="185.220.101.47", geo="Netherlands", isp="Tor Exit Node"),
    )


@pytest.fixture
def normalizer() -> Normalizer:
    return Normalizer()


@pytest.fixture
def now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class TestAuthGenerator:
    def test_generates_auth_failure(self, sim_context, normalizer, now_iso):
        gen = AuthGenerator(sim_context)
        event = gen.generate(timestamp=now_iso)
        assert event.event_category == "auth"
        assert event.event_type == "auth_failure"
        assert event.network is not None
        assert event.network.src_ip == "185.220.101.47"
        normalizer.validate(event)

    def test_generates_auth_success(self, sim_context, normalizer, now_iso):
        gen = AuthGenerator(sim_context)
        event = gen.generate(event_type="auth_success", timestamp=now_iso)
        assert event.event_type == "auth_success"
        assert "logon_id" in event.payload
        normalizer.validate(event)

    def test_custom_user_and_host(self, sim_context, now_iso):
        gen = AuthGenerator(sim_context)
        event = gen.generate(timestamp=now_iso, user="admin", host="SERVER-DC01")
        assert event.user == "admin"
        assert event.host == "SERVER-DC01"

    def test_validate_rejects_wrong_category(self, sim_context, now_iso):
        gen = AuthGenerator(sim_context)
        event = gen.generate(timestamp=now_iso)
        object.__setattr__(event, "event_category", "process")
        assert gen.validate(event) is False

    def test_validate_accepts_good_event(self, sim_context, now_iso):
        gen = AuthGenerator(sim_context)
        event = gen.generate(timestamp=now_iso)
        assert gen.validate(event) is True

    def test_enrich_is_identity(self, sim_context, now_iso):
        gen = AuthGenerator(sim_context)
        event = gen.generate(timestamp=now_iso)
        assert gen.enrich(event) is event

    def test_unique_event_ids(self, sim_context, now_iso):
        gen = AuthGenerator(sim_context)
        ids = {gen.generate(timestamp=now_iso).event_id for _ in range(50)}
        assert len(ids) == 50

    def test_payload_has_required_failure_fields(self, sim_context, now_iso):
        gen = AuthGenerator(sim_context)
        event = gen.generate(timestamp=now_iso, event_type="auth_failure")
        required_keys = {"logon_type", "failure_reason", "status", "sub_status", "auth_package"}
        assert required_keys.issubset(event.payload.keys())


class TestProcessGenerator:
    def test_generates_process_create(self, sim_context, normalizer, now_iso):
        gen = ProcessGenerator(sim_context)
        event = gen.generate(timestamp=now_iso)
        assert event.event_category == "process"
        assert event.event_type == "process_create"
        assert event.process is not None
        normalizer.validate(event)

    def test_custom_process_params(self, sim_context, normalizer, now_iso):
        gen = ProcessGenerator(sim_context)
        event = gen.generate(
            timestamp=now_iso, process_name="mimikatz.exe",
            parent_name="cmd.exe", command_line="mimikatz.exe sekurlsa::logonpasswords", pid=1337,
        )
        assert event.process.name == "mimikatz.exe"
        assert event.process.parent == "cmd.exe"
        assert event.process.pid == 1337
        normalizer.validate(event)

    def test_validate_rejects_missing_process(self, sim_context, now_iso):
        gen = ProcessGenerator(sim_context)
        event = gen.generate(timestamp=now_iso)
        object.__setattr__(event, "process", None)
        assert gen.validate(event) is False

    def test_validate_accepts_good_event(self, sim_context, now_iso):
        gen = ProcessGenerator(sim_context)
        event = gen.generate(timestamp=now_iso)
        assert gen.validate(event) is True

    def test_suspicious_parent(self, sim_context, now_iso):
        gen = ProcessGenerator(sim_context)
        suspicious_parents = {"cmd.exe", "powershell.exe", "explorer.exe", "wmiprvse.exe"}
        event = gen.generate(timestamp=now_iso, suspicious=True)
        assert event.process.parent in suspicious_parents


class TestSimContext:
    def test_add_and_check_compromised(self, sim_context):
        assert sim_context.is_compromised("DESKTOP-W11LAB") is False
        sim_context.add_compromised("DESKTOP-W11LAB")
        assert sim_context.is_compromised("DESKTOP-W11LAB") is True

    def test_get_host(self, sim_context):
        host = sim_context.get_host("DESKTOP-W11LAB")
        assert host is not None
        assert host.ip == "192.168.1.100"
        assert sim_context.get_host("NONEXISTENT") is None

    def test_get_user(self, sim_context):
        user = sim_context.get_user("jsmith")
        assert user is not None
        assert user.domain == "LAB"
        assert sim_context.get_user("nonexistent") is None
