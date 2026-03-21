# Investigation 001 - NTFS Alternate Data Stream Detection

**Date:** 2026-03-01
**Alert Level:** 7
**Rule ID:** 510
**Agent:** Windows-host

## What Wazuh Detected
NTFS Alternate Data Stream found in C:\WINDOWS\tracing

## What is an ADS?
NTFS Alternate Data Streams allow data to be hidden inside files 
without being visible normally. Commonly abused by malware to 
hide payloads.

## Investigation
- Location: C:\WINDOWS\tracing (legitimate Windows system folder)
- Rule fired 26 times, suggesting recurring system behavior
- No other suspicious alerts correlated with this event

## Verdict
False Positive — normal Windows system behavior in a known 
legitimate directory.

## References
- MITRE ATT&CK T1564.004 - Hide Artifacts: NTFS File Attributes
