# Hunting Persistence: Registry Run Keys

## Overview

This report documents hunting for persistence artifacts under the Persistence tactic on the MITRE ATT&CK framework. The related technique is Registry Run Keys / Startup Folder (T1547.001). I used Splunk to search Sysmon registry events for entries added to the common Windows Run key persistence locations, then verified the processes responsible for creating them.

## Log Sources Available

- XmlWinEventLog:Application
- XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
- XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational
- XmlWinEventLog:Security
- XmlWinEventLog:System

## Investigation

### Step 1: Look for registry value changes

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=13
```

Sysmon Event ID 13 logs registry value sets. This returned a large, noisy result set, so I narrowed it down to the registry paths MITRE ATT&CK identifies as common persistence locations.

### Step 2: Filter down to Run key locations

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=13
TargetObject="*\Software\Microsoft\Windows\CurrentVersion\Run*"
| table _time, Computer, User, TargetObject, Details, Image
```

This surfaced several entries:

| Time | User | TargetObject | Details | Image |
|---|---|---|---|---|
| 22:30:48 | mary.ellen | `...\RunNotification\StartupTNotiUpdater` | DWORD (0x00000002) | sihost.exe |
| 22:38:44 | mary.ellen | `...\Run\MicrosoftEdgeAutoLaunch_A59984...` | msedge.exe --no-startup-window --win-session-start | msedge.exe |
| 22:38:55 | mary.ellen | `...\RunNotification\StartupTNotiMicrosoftEdgeAutoLaunch_A59984...` | DWORD (0x00000001) | sihost.exe |
| 22:42:45 | SYSTEM | `HKLM\...\RunOnce\msedge_cleanup_{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}` | setup.exe --msedgewebview --delete-old-versions --system-level --on-logon | setup.exe |
| 22:49:40 | mary.ellen | `...\Run\MicrosoftEdgeAutoLaunch_A59984...` | msedge.exe --no-startup-window --win-session-start | msedge.exe |
| 23:10:35 | mary.ellen | `...\Run\MicrosoftEdgeAutoLaunch_A59984...` | msedge.exe --no-startup-window --win-session-start | msedge.exe |

At first glance, `msedge.exe` and its related entries look like legitimate Microsoft Edge auto-launch and update behavior rather than attacker activity.

### Step 3: Add ProcessGuid for unique tracking

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=13
TargetObject="*\Software\Microsoft\Windows\CurrentVersion\Run*"
| table _time, Computer, User, TargetObject, Details, Image, ProcessGuid
```

![Screenshot placeholder: Run key events with ProcessGuid](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/141da97d6558f536e1ef2d726ce6da0ecdb16511/02-Hunting%20For%20Persistence/media/runkeys/step3.png)

Adding `ProcessGuid` gave each registry-writing process a unique identifier, which I could use to verify exactly which process performed each write, rather than relying on the image path alone.

### Step 4: Verify the responsible processes

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
[ search index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=13
TargetObject="*\Software\Microsoft\Windows\CurrentVersion\Run*"
| fields ProcessGuid ]
| table _time, Computer, User, Image, CommandLine, Company, MD5, SHA256
| sort _time
```

I used the `ProcessGuid` values from the previous search as a subsearch to pull full process creation details for each process that wrote to a Run key, including company attribution and file hashes.

![Screenshot placeholder: process verification table with hashes](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/141da97d6558f536e1ef2d726ce6da0ecdb16511/02-Hunting%20For%20Persistence/media/runkeys/step4.png)

This confirmed two unique binaries and hashes:

| Time | User | Image | Company | MD5 |
|---|---|---|---|---|
| 22:32:29 | SYSTEM | setup.exe (EdgeWebView Installer) | Microsoft Corporation | F8B8278BD510843E63F2D9587341453F |
| 22:37:50 | mary.ellen | msedge.exe | Microsoft Corporation | 7AB41BE2849631765066C98377239025 |
| 22:43:39 | mary.ellen | msedge.exe | Microsoft Corporation | 7AB41BE2849631765066C98377239025 |
| 23:03:26 | mary.ellen | msedge.exe | Microsoft Corporation | 7AB41BE2849631765066C98377239025 |

I ran both hashes through VirusTotal and they came back clean, confirming both as legitimate Microsoft binaries rather than malicious tooling.

## Key Findings

- All Run key entries created by `sihost.exe`, `msedge.exe`, and `setup.exe` traced back to legitimate Microsoft Edge update and notification behavior.
- Verifying with `ProcessGuid`, company attribution, and hash lookups confirmed these entries as clean, even though they initially stood out as auto-run persistence locations.
- Even when results turn out clean, it's still correct practice to hunt down and verify every Run key entry rather than assuming legitimacy from the file name alone.

## Key Takeaways

- Registry Run keys are one of the most common and easiest persistence mechanisms to check, and Sysmon Event ID 13 is the primary log source for catching them.
- Filtering on MITRE ATT&CK's documented persistence registry paths cuts a noisy search down to the events that actually matter.
- `ProcessGuid` and hash verification are what separate a real finding from a false positive — a suspicious-looking registry path doesn't always mean malicious activity.

## Conclusion

I hunted Windows Registry Run key persistence (T1547.001) using Sysmon Event ID 13, and verified that the entries found were created by legitimate, hash-confirmed Microsoft Edge processes rather than attacker tooling.
