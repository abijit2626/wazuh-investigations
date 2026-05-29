"""Tests for output adapters (WazuhFileAdapter, JSONFileAdapter)."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from adapters.json_debug import JSONFileAdapter
from adapters.wazuh_file import WazuhFileAdapter
from core.models import AttackInfo, NetworkInfo, NormalizedEvent, ProcessInfo


@pytest.fixture
def sample_auth_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        host="DESKTOP-W11LAB",
        user="jsmith",
        event_category="auth",
        event_type="auth_failure",
        network=NetworkInfo(src_ip="185.220.101.47", dst_ip="192.168.1.100", port=3389, protocol="tcp"),
        attack=AttackInfo(technique="T1110.001", tactic="Credential Access", is_false_positive=False),
        payload={"logon_type": 10, "failure_reason": "%%2313"},
    )


@pytest.fixture
def sample_process_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        host="DESKTOP-W11LAB",
        user="jsmith",
        event_category="process",
        event_type="process_create",
        process=ProcessInfo(name="lsass.exe", parent="svchost.exe", command_line=r"C:\Windows\System32\lsass.exe", pid=672),
        attack=AttackInfo(technique="T1003.001", tactic="Credential Access"),
    )


class TestWazuhFileAdapter:
    def test_write_creates_valid_ndjson(self, tmp_path, sample_auth_event):
        log_file = str(tmp_path / "wazuh.log")
        adapter = WazuhFileAdapter(file_path=log_file)
        adapter.write(sample_auth_event)
        adapter.close()

        with open(log_file, "r") as f:
            lines = f.readlines()
        assert len(lines) == 1
        doc = json.loads(lines[0])
        assert "timestamp" in doc
        assert doc["type"] == "auth"

    def test_wazuh_field_mapping_auth(self, tmp_path, sample_auth_event):
        log_file = str(tmp_path / "wazuh.log")
        adapter = WazuhFileAdapter(file_path=log_file)
        adapter.write(sample_auth_event)
        adapter.close()

        with open(log_file, "r") as f:
            doc = json.loads(f.readline())
        assert doc["agent"]["name"] == "DESKTOP-W11LAB"
        assert doc["rule"]["id"] == "60122"
        assert doc["rule"]["mitre"]["technique"] == ["T1110.001"]
        assert doc["rule"]["mitre"]["tactic"] == ["Credential Access"]
        assert doc["data"]["win"]["eventdata"]["targetUserName"] == "jsmith"

    def test_wazuh_field_mapping_process(self, tmp_path, sample_process_event):
        log_file = str(tmp_path / "wazuh.log")
        adapter = WazuhFileAdapter(file_path=log_file)
        adapter.write(sample_process_event)
        adapter.close()

        with open(log_file, "r") as f:
            doc = json.loads(f.readline())
        assert doc["rule"]["id"] == "92100"
        assert doc["data"]["win"]["eventdata"]["user"] == "jsmith"
        assert doc["data"]["win"]["eventdata"]["image"] == "lsass.exe"
        assert doc["data"]["win"]["eventdata"]["parentImage"] == "svchost.exe"

    def test_rotation_at_size_limit(self, tmp_path, sample_auth_event):
        log_file = str(tmp_path / "wazuh.log")
        adapter = WazuhFileAdapter(file_path=log_file, max_size_mb=0)  # 0 MB = rotate immediately
        # First write triggers rotation after writing
        adapter.write(sample_auth_event)
        adapter.write(sample_auth_event)
        adapter.close()

        # Should have rotated — check for .1 file
        rotated = tmp_path / "wazuh.log.1"
        assert rotated.exists()

    def test_multiple_events_ndjson(self, tmp_path, sample_auth_event):
        log_file = str(tmp_path / "wazuh.log")
        adapter = WazuhFileAdapter(file_path=log_file)
        for _ in range(5):
            adapter.write(sample_auth_event)
        adapter.close()

        with open(log_file, "r") as f:
            lines = f.readlines()
        assert len(lines) == 5
        for line in lines:
            json.loads(line)  # must be valid JSON


class TestJSONFileAdapter:
    def test_write_creates_valid_ndjson(self, tmp_path, sample_auth_event):
        log_file = str(tmp_path / "debug.log")
        adapter = JSONFileAdapter(file_path=log_file)
        adapter.write(sample_auth_event)
        adapter.close()

        with open(log_file, "r") as f:
            lines = f.readlines()
        assert len(lines) == 1
        doc = json.loads(lines[0])
        assert doc["event_category"] == "auth"
        assert doc["event_type"] == "auth_failure"
        assert "process" not in doc  # None fields omitted

    def test_raw_schema_preserved(self, tmp_path, sample_process_event):
        log_file = str(tmp_path / "debug.log")
        adapter = JSONFileAdapter(file_path=log_file)
        adapter.write(sample_process_event)
        adapter.close()

        with open(log_file, "r") as f:
            doc = json.loads(f.readline())
        assert doc["process"]["name"] == "lsass.exe"
        assert doc["attack"]["technique"] == "T1003.001"
        assert "network" not in doc

    def test_multiple_writes(self, tmp_path, sample_auth_event):
        log_file = str(tmp_path / "debug.log")
        adapter = JSONFileAdapter(file_path=log_file)
        for _ in range(10):
            adapter.write(sample_auth_event)
        adapter.close()

        with open(log_file, "r") as f:
            lines = f.readlines()
        assert len(lines) == 10
