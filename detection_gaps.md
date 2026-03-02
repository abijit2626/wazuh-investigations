## Detection Gap: Scheduled Task Creation (Event ID 4698)

**Status:** Not Detected

**What I Did:**
- Enabled Windows auditing for scheduled task creation
- Created a scheduled task via schtasks command
- Event ID 4698 was logged in Security Event Viewer

**What Wazuh Did:**
- Agent collected the event (4698 is not in exclusion list)
- No alert fired

**Root Cause:**
- Wazuh Manager has no rule for Event ID 4698
- Default ruleset does not detect scheduled task creation

**Impact:**
- Scheduled task persistence attacks (T1053) would go undetected in this lab

**Next Steps:**
- Write custom Wazuh rule for Event ID 4698
- Or add to higher-priority detection after covering critical gaps

**Date:** March 2, 2026
