"""SOC Lab — Adversary Telemetry Generator (Phase 1).

Wires generators, event bus, and adapters together.  Runs a hardcoded
brute-force login scenario (MITRE T1110.001) producing exactly 52 events:
  50 auth_failure  → gaussian-jittered across 8 minutes
   1 auth_success  → 45 s after last failure
   1 process_create → 30 s after success (T1003.001 — LSASS credential dump)

Output: ndjson files at the paths specified in config.yaml.
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import structlog
import yaml

from adapters.json_debug import JSONFileAdapter
from adapters.wazuh_file import WazuhFileAdapter
from core.context import SimContext
from core.event_bus import EventBus
from core.models import Attacker, Host, User
from generators.auth import AuthGenerator
from generators.process import ProcessGenerator

# ---------------------------------------------------------------------------
# Structlog configuration — must run before any logger calls
# ---------------------------------------------------------------------------
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("main")


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> dict:
    """Load and return the YAML configuration as a dict."""
    config_path = Path(path)
    if not config_path.exists():
        logger.error("config_not_found", path=path)
        sys.exit(1)
    with open(config_path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Timestamp generation
# ---------------------------------------------------------------------------

def generate_brute_force_timestamps(
    start: datetime,
    failure_count: int,
    spread_minutes: int,
    jitter_sigma: float,
    success_delay: float,
    process_delay: float,
) -> list[tuple[str, str]]:
    """Generate (timestamp_iso, event_type) pairs for the brute-force scenario.

    Returns a list of exactly failure_count + 2 tuples:
      - failure_count auth_failure timestamps spread with gaussian jitter
      - 1 auth_success timestamp
      - 1 process_create timestamp
    """
    spread_seconds = spread_minutes * 60
    interval = spread_seconds / max(failure_count - 1, 1)

    # Generate failure timestamps with gaussian jitter
    failure_timestamps: list[datetime] = []
    for i in range(failure_count):
        base_offset = i * interval
        jittered_offset = base_offset + random.gauss(0, jitter_sigma)
        # Clamp so we don't go before start
        jittered_offset = max(0, jittered_offset)
        ts = start + timedelta(seconds=jittered_offset)
        failure_timestamps.append(ts)

    # Sort to maintain chronological order after jitter
    failure_timestamps.sort()

    # Build result list
    result: list[tuple[str, str]] = []
    for ts in failure_timestamps:
        result.append((ts.isoformat(), "auth_failure"))

    # auth_success: 45s after last failure
    last_failure = failure_timestamps[-1]
    success_ts = last_failure + timedelta(seconds=success_delay)
    result.append((success_ts.isoformat(), "auth_success"))

    # process_create: 30s after auth_success
    process_ts = success_ts + timedelta(seconds=process_delay)
    result.append((process_ts.isoformat(), "process_create"))

    return result


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------

def run_brute_force(config: dict) -> None:
    """Execute the brute-force login scenario end-to-end."""
    scenario_cfg = config["scenario"]["brute_force"]
    sim_cfg = config["simulation"]

    # Build SimContext
    hosts = [Host(**h) for h in config["hosts"]]
    users = [User(**u) for u in config["users"]]
    attacker = Attacker(**config["attacker"])
    context = SimContext(hosts=hosts, users=users, attacker=attacker)

    # Generators
    auth_gen = AuthGenerator(context)
    proc_gen = ProcessGenerator(context)

    # Event bus + adapters
    bus = EventBus()

    # Ensure output directory exists
    Path(sim_cfg["output_dir"]).mkdir(parents=True, exist_ok=True)

    wazuh_adapter = WazuhFileAdapter(
        file_path=sim_cfg["wazuh_log"],
        max_size_mb=sim_cfg["max_file_size_mb"],
    )
    debug_adapter = JSONFileAdapter(file_path=sim_cfg["debug_log"])

    bus.register_adapter(wazuh_adapter)
    bus.register_adapter(debug_adapter)

    # Generate timestamps
    start_time = datetime.now(tz=timezone.utc)
    timeline = generate_brute_force_timestamps(
        start=start_time,
        failure_count=scenario_cfg["failure_count"],
        spread_minutes=scenario_cfg["spread_minutes"],
        jitter_sigma=scenario_cfg["jitter_sigma_seconds"],
        success_delay=scenario_cfg["success_delay_seconds"],
        process_delay=scenario_cfg["process_delay_seconds"],
    )

    logger.info(
        "scenario_started",
        scenario="brute_force",
        technique=scenario_cfg["mitre_technique"],
        total_events=len(timeline),
        start_time=start_time.isoformat(),
    )

    # Emit events
    for timestamp, event_type in timeline:
        if event_type in ("auth_failure", "auth_success"):
            event = auth_gen.generate(
                event_type=event_type,
                timestamp=timestamp,
                user=scenario_cfg["target_user"],
                host=scenario_cfg["target_host"],
                src_ip=scenario_cfg["src_ip"],
                technique=scenario_cfg["mitre_technique"],
                tactic=scenario_cfg["mitre_tactic"],
            )
        elif event_type == "process_create":
            # Mark host as compromised after successful auth
            context.add_compromised(scenario_cfg["target_host"])
            event = proc_gen.generate(
                timestamp=timestamp,
                user=scenario_cfg["target_user"],
                host=scenario_cfg["target_host"],
                process_name="lsass.exe",
                parent_name="svchost.exe",
                command_line=r"C:\Windows\System32\lsass.exe",
                pid=672,
                technique=scenario_cfg["lsass_technique"],
                tactic=scenario_cfg["lsass_tactic"],
                suspicious=False,
            )
        else:
            logger.warning("unknown_event_type", event_type=event_type)
            continue

        bus.publish(event)

    # Done
    bus.close()

    logger.info(
        "scenario_completed",
        scenario="brute_force",
        events_published=bus.event_count,
        wazuh_log=sim_cfg["wazuh_log"],
        debug_log=sim_cfg["debug_log"],
        host_compromised=context.is_compromised(scenario_cfg["target_host"]),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Load config and run the Phase 1 brute-force scenario."""
    config = load_config()
    run_brute_force(config)


if __name__ == "__main__":
    main()
