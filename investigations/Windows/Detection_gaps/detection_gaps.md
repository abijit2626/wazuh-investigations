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




## Detection Gap: Suspicious PowerShell Execution (T1059)

**Status:** Process Captured by Sysmon, No Alert

**What I Did:**
- Executed PowerShell with suspicious flags: -NoProfile -ExecutionPolicy Bypass
- Command targeted lsass process (credential dumping pattern)
- Sysmon Event ID 1 captured full execution details

**What Wazuh Did:**
- Agent collected the Sysmon event
- Zero alerts fired

**Root Cause:**
- No Wazuh rule for suspicious PowerShell command lines
- No detection for -ExecutionPolicy Bypass pattern
- No detection for lsass targeting

**Impact:**
- PowerShell-based attacks (malware execution, credential theft) undetected
- Bypass flags not flagged as suspicious

**Next Steps:**
- Write custom rule detecting ExecutionPolicy Bypass
- Or detect PowerShell + suspicious command patterns
- High priority (PowerShell is heavily used in attacks)

**Date:** March 3, 2026




## Detection Gap: Plaintext Credentials in Command Line (T1552)

**Status:** Command Executed and Logged, No Alert

**What I Did:**
- Created user account with plaintext password in command: net user testpass Password123456! /add
- Sysmon Event ID 1 captured the full command with password visible
- Windows Event ID 4720 (account created) logged

**What Wazuh Did:**
- Alerted on Event 4720 (account creation)
- Did NOT alert on plaintext credential exposure in command line

**Root Cause:**
- Wazuh has rules for account events (4720, 4722, etc.)
- No rule for detecting plaintext credentials/passwords in command lines

**Impact:**
- Defenders miss credential leakage in logs
- Credentials exposed via CLI go undetected

**Next Steps:**
- Write rule detecting common password patterns in net.exe commands
- Or create generic rule for credential patterns in any command line

**Date:** March 3, 2026
