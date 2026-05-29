# Full SOC Home Lab & Detection Engineering

This repository has evolved from a standalone detection engineering project into a **Full SOC Home Lab Simulation**. 
It combines a stateful adversary telemetry generator with hands-on SIEM investigations, allowing me to both simulate realistic cyber attacks and investigate them exactly as a SOC analyst would.

## 🏗 Architecture Overview

The project is split into two primary domains: **Simulation** and **Investigations**.

```
wazuh-investigations/
├── simulation/           # The Stateful Adversary Telemetry Generator (Python)
│   ├── core/             # Canonical event schemas, context, and bus
│   ├── generators/       # Stateful event generators (Auth, Process, etc.)
│   ├── adapters/         # Output adapters (Wazuh, JSON debug)
│   ├── tests/            # Test suite
│   ├── config.yaml       # Tunable scenario configurations
│   └── main.py           # Scenario orchestrator
└── investigations/       # Alert Triage, Detection Gaps & Writeups
    ├── Windows/          # Windows endpoint analysis
    └── Ubuntu/           # Linux endpoint analysis
```

### 1. The Simulation Engine (`/simulation`)
A Python-based stateful attack simulation engine. Unlike random log generators, this tool simulates realistic attack scenarios (e.g., T1110.001 Brute Force + T1003.001 LSASS dumping) and generates chronological, context-aware telemetry directly into Wazuh.

- **Stateful Context**: Tracks which users and hosts are compromised.
- **MITRE Aligned**: All events map strictly to MITRE ATT&CK techniques and tactics.
- **Wazuh Ready**: Outputs `ndjson` specifically formatted for Wazuh localfile ingestion.

### 2. The Investigations (`/investigations`)
Real-world testing of Wazuh's out-of-the-box detection rules against the simulated attacks (as well as other common techniques). 

- **Detection Gaps**: Finding missing detections (e.g., Scheduled tasks, PowerShell execution) and creating custom rules.
- **Alert Triage**: False positive analysis and root cause investigation.
- **Cross-Platform**: Covers both Windows (with Sysmon) and Ubuntu.

## 🚀 Getting Started

### Running the Simulator
```bash
cd simulation
pip install -r requirements.txt
python main.py
```
This generates the scenario output logs (`wazuh_sim.log` and `debug.log`) in the `simulation/output` directory, ready to be ingested by the Wazuh Agent.

## 💡 Why This Matters

Most SIEM tutorials show you how to *install* the tool. This project takes it further:
1. **Red Team (Simulation):** How to generate high-fidelity, interconnected adversary telemetry.
2. **Blue Team (Investigation):** How to actually *use* the SIEM to triage alerts, fix broken rules, and analyze false positives.

---

**Note:** This is a learning project. The detection rules and simulation engine are works in progress and are continuously being expanded.
