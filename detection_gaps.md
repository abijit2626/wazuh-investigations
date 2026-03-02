## Detection Gap: Scheduled Task Creation (Event ID 4698 + Sysmon Process Execution)

**Status:** Event Logged, No Alert

**What I Did:**
- Created scheduled task via schtasks command
- Event ID 4698 logged in Security Event Viewer
- Sysmon Event ID 1 captured schtasks.exe execution

**What Wazuh Did:**
- Agent collected both events
- Zero alerts fired

**Root Cause:**
- No Wazuh rule for Event ID 4698
- No Wazuh rule for schtasks.exe process execution detection

**Impact:**
- Scheduled task persistence (T1053) completely undetected

**Next Steps:**
- Write custom rule for schtasks.exe execution, OR
- Write custom rule for Event ID 4698, OR
- Prioritize after higher-severity gaps

**Date:** March 3, 2026
