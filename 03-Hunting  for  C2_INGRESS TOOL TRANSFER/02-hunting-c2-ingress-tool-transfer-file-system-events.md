# Hunting C2: Ingress Tool Transfer (File System Events)

## Overview

This report documents hunting for command-and-control artifacts under the Command and Control tactic on the MITRE ATT&CK framework. The related technique is Ingress Tool Transfer (T1105). Rather than looking at the download commands themselves, I hunted for the resulting file system evidence — files dropped on disk after a transfer — using Sysmon file creation events.

## Investigation

### Step 1: Check common file drop locations

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=11
(TargetFilename="C:\Users\Public\*" OR TargetFilename="C:\Windows\Temp\*" OR
TargetFilename="C:\ProgramData\*")
| table _time, Computer, User, TargetFilename, Image, ProcessId
| sort -_time
```

![Screenshot placeholder: file creation events in common drop locations](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/d54dd53d54e16fa30c917eebdabcef4f28ffa4c8/03-Hunting%20%20for%20%20C2_INGRESS%20TOOL%20TRANSFER/Media/file%20system%20events/step1.png)

This returned mostly expected, benign activity: a batch of Windows diagnostic script files (`SDIAG_...\TS_*.ps1`, `RS_*.ps1`, `DiagPackage.dll`) written by `taskhostw.exe`, and a Microsoft Edge shortcut written by the Edge installer to the Start Menu. Nothing in these three common drop locations stood out as suspicious.

### Step 2: Pivot to executables dropped directly under the Windows folder

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=11
TargetFilename="C:\Windows\*.exe"
| table _time, Computer, User, TargetFilename, Image, ProcessId
| sort -_time
```

![Screenshot placeholder: executable files dropped under C:\Windows](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/d54dd53d54e16fa30c917eebdabcef4f28ffa4c8/03-Hunting%20%20for%20%20C2_INGRESS%20TOOL%20TRANSFER/Media/file%20system%20events/step2.png)

This search was far more productive:

| Time | User | TargetFilename | Image | ProcessId |
|---|---|---|---|---|
| 22:28:11 | SYSTEM | C:\Windows\THybZSNv.exe | System | 4 |
| 22:31:19 | SYSTEM | C:\Windows\SysWOW64\mimi.exe | C:\Windows\SysWOW64\certutil.exe | 3244 |
| 22:31:19 | SYSTEM | ...\INetCache\IE\mimi[1].exe | C:\Windows\SysWOW64\certutil.exe | 3244 |

Two findings stood out immediately: `mimi.exe` dropped by `certutil.exe` — confirming the download identified in the LOLBAS report actually landed on disk — and `THybZSNv.exe`, an executable created with a parent image of simply `System`, meaning it appeared without any normal installer or process context.

### Step 3: Get a broader view of what's creating files

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=11
| stats count by Image
```

Aggregating by `Image` made it easy to separate expected high-volume noise (`svchost.exe` with 1043 file creation events, `mscorsvw.exe` with 69, Windows Update components) from the small number of events tied to `certutil.exe` (2) and the standalone `System` entry (1) — both of which warranted a closer look and were already explained by the previous step.

### Step 4: Check files created specifically by PowerShell

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=11
Image="C:\WINDOWS\*\WindowsPowerShell\v1.0\powershell.exe"
| table _time, Computer, User, TargetFilename, Image, ProcessId
| sort -_time
```

![Screenshot placeholder: file creation counts by image](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/d54dd53d54e16fa30c917eebdabcef4f28ffa4c8/03-Hunting%20%20for%20%20C2_INGRESS%20TOOL%20TRANSFER/Media/file%20system%20events/step4.png)

Most of these results were `__PSScriptPolicyTest_*.ps1` files under `C:\Windows\SystemTemp\` — this is expected, benign PowerShell script policy testing behavior, not malicious activity. One entry stood apart from the rest:

| Time | User | TargetFilename | Image | ProcessId |
|---|---|---|---|---|
| 22:29:50 | SYSTEM | C:\Windows\SysWOW64\dghelper.dll | C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe | 2748 |

This confirmed that the PowerShell `Invoke-WebRequest` download identified in the LOLBAS report successfully wrote `dghelper.dll` to disk.

## Key Findings

- Both files identified in the LOLBAS ingress tool transfer report were confirmed to have actually landed on disk: `mimi.exe` via `certutil.exe`, and `dghelper.dll` via `powershell.exe`.
- A third executable, `THybZSNv.exe`, was found sitting directly under `C:\Windows\` with a parent image of `System` — no installer, no normal software deployment context — a strong anomaly on its own.
- The `__PSScriptPolicyTest_*.ps1` files are routine PowerShell script policy validation artifacts and were ruled out as noise rather than malicious activity.

## Key Takeaways

- Common drop locations (`Public`, `Temp`, `ProgramData`) aren't always where the real payload lands — checking directly under `C:\Windows\` for stray executables caught what the first search missed.
- A `stats count by Image` aggregation is one of the fastest ways to separate expected high-volume file creation activity from rare, anomalous entries worth investigating.
- A dropped executable with no legitimate parent process or installer context is one of the strongest anomalies in file system data, even before any hash or network correlation is done.

## Conclusion

I confirmed on-disk evidence for two ingress tool transfer downloads — `mimi.exe` and `dghelper.dll` — and flagged a third unexplained executable, `THybZSNv.exe`, that appeared under `C:\Windows\` with no installer or parent process context.
