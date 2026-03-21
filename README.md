# Wazuh SIEM Detection Engineering

Testing and documenting Wazuh SIEM capabilities, detection gaps, and custom rule development.

## What This Is

Real-world testing of Wazuh's out-of-the-box detection rules against common attack techniques. I'm documenting what works, what doesn't, and building custom rules to fill the gaps.

**Current Setup:**
- Wazuh Manager (version TBD)
- Windows Agent (Sysmon configured)
- Ubuntu Agent (new)

## Repository Structure
```
stem_writeups/
├── Windows/
│   ├── Detection_gaps/     # Missing detections + root cause analysis
│   └── Investigations/      # Alert triage & false positive analysis
└── Ubuntu/
    └── (in progress)
```

## What's Documented

### Windows Agent

**Detection Gaps Found:**
- Scheduled Task Creation (T1053) - Event ID 4698 logged but not alerted
- Suspicious PowerShell Execution (T1059) - Bypass flags undetected
- Plaintext Credentials in Command Lines (T1552) - Password exposure missed

**Investigations:**
- NTFS Alternate Data Streams (Rule 510) - False positive analysis

Each gap includes:
- Attack simulation details
- What Wazuh detected vs. missed
- Root cause (missing rule/misconfiguration)
- MITRE ATT&CK mapping
- Proposed fix

## Testing Methodology

1. Execute attack technique
2. Check if Wazuh alerts
3. If no alert → document as detection gap
4. If alert fires → investigate for false positives
5. Map to MITRE ATT&CK framework

## Next Steps

- [ ] Ubuntu agent baseline testing
- [ ] Write custom rules for high-priority gaps
- [ ] Test rule effectiveness
- [ ] Document tuning process

## Why This Matters

Most SIEM tutorials show you how to *install* the tool. This shows you how to actually *use* it—what's broken, what needs tuning, and how to fix it.

---

**Note:** This is a learning project. Detection rules are works in progress and not production-ready.
