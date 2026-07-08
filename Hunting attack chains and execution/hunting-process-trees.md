# Hunting Process Trees

## Overview

This report documents hunting for execution artifacts under the Execution tactic on the MITRE ATT&CK framework. Rather than mapping to a single technique, building a process tree is an investigative method that helped confirm and connect several techniques already identified in the PowerShell and Cmd execution hunts, including Command and Scripting Interpreter (T1059), Registry Run Keys / Startup Folder (T1547.001), and Indicator Removal (T1070.001). I used Splunk's `pstree` command to visualize parent-child process relationships and reconstruct the full attack sequence on the host.

## Investigation

### Step 1: Build a basic process tree

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
| fields *
| pstree child=Image parent=ParentImage
| table tree
```

![Screenshot placeholder: initial process tree output](screenshots/1c-process-tree-basic.png)

This produced a tree of every process on the host and what spawned it, including the malicious branch:

```
C:\Windows\THybZSNv.exe
  |--- C:\Windows\SysWOW64\cmd.exe
        |--- C:\Windows\SysWOW64\mimi.exe
        |--- C:\Windows\SysWOW64\certutil.exe
        |--- C:\Windows\SysWOW64\wevtutil.exe
        |--- C:\Windows\SysWOW64\reg.exe
        |--- C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
        |--- C:\Windows\SysWOW64\ipconfig.exe
        |--- C:\Windows\SysWOW64\whoami.exe
```

This confirmed `THybZSNv.exe` — sitting directly under `C:\Windows\` — as the true root of the malicious activity, spawning `cmd.exe`, which in turn spawned every command identified in the previous report.

### Step 2: Enrich the tree with timestamps and command lines

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
| rex field=ParentImage "\x5c(?<ParentName>[^\x5c]+)$"
| rex field=Image "\x5c(?<ProcessName>[^\x5c]+)$"
| eval parent = ParentName." (".ParentProcessId.")"
| eval child = ProcessName." (".ProcessId.")"
| eval detail=strftime(_time,"%Y-%m-%d %H:%M:%S")." ".CommandLine
| pstree child=child parent=parent detail=detail spaces=50
| table tree
```

I based this query on Splunk's PSTree app documentation to add process IDs, timestamps, and command lines directly into the tree output, rather than just process names.

![Screenshot placeholder: enriched process tree with timestamps and command lines](screenshots/1c-process-tree-enriched.png)

### Step 3: Isolate the malicious branch

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1
| rex field=ParentImage "\x5c(?<ParentName>[^\x5c]+)$"
| rex field=Image "\x5c(?<ProcessName>[^\x5c]+)$"
| eval parent = ParentName." (".ParentProcessId.")"
| eval child = ProcessName." (".ProcessId.")"
| eval detail=strftime(_time,"%Y-%m-%d %H:%M:%S")." ".CommandLine
| pstree child=child parent=parent detail=detail spaces=50
| search tree=*THybZSNv.exe
| table tree
```

Filtering the tree down to only the branch containing `THybZSNv.exe` produced a clean, timestamped view of the entire attack sequence in the order it happened:

```
THybZSNv.exe (10228) 2025-06-11 22:28:11
  |--- cmd.exe (3916) 2025-06-11 22:28:14
        |--- whoami.exe (1760) 2025-06-11 22:28:37 whoami /all
        |--- ipconfig.exe (6080) 2025-06-11 22:28:44 ipconfig /all
        |--- powershell.exe (2748) 2025-06-11 22:29:46 Invoke-WebRequest dghelper.dll
        |--- reg.exe (2256) 2025-06-11 22:30:38 reg add Run key persistence
        |--- wevtutil.exe (3892) 2025-06-11 22:30:48 wevtutil cl Security
        |--- wevtutil.exe (6288) 2025-06-11 22:30:54 wevtutil cl System
        |--- wevtutil.exe (8480) 2025-06-11 22:30:58 wevtutil cl Application
        |--- certutil.exe (3244) 2025-06-11 22:31:19 certutil download mimi.exe
        |--- mimi.exe (9296) 2025-06-11 22:31:33
```

![Screenshot placeholder: isolated malicious process tree branch](screenshots/1c-process-tree-malicious-branch.png)

## Key Findings

- `THybZSNv.exe`, spawned from `services.exe`, is the true root process of the entire attack chain.
- The enriched process tree confirms the exact order of operations: reconnaissance (`whoami`, `ipconfig`), tool transfer (PowerShell download), persistence (Registry Run key), defense evasion (event log clearing), and a second tool transfer (`certutil` download of `mimi.exe`).
- Visualizing the tree made it possible to confirm, in a single view, that every suspicious command identified separately in the PowerShell and Cmd reports belonged to the same attack session.

## Key Takeaways

- A process tree turns a list of isolated suspicious events into a single visual timeline, which is often faster to reason about than scrolling through a raw event table.
- Enriching the tree with timestamps and command lines removes the need to pivot back and forth between multiple queries to understand what happened and when.
- Identifying the true root process of an attack chain is critical — everything else in the investigation branches out from that one binary.

## Conclusion

I built and enriched a Splunk process tree that confirmed `THybZSNv.exe` as the root of the attack chain and visually connected every execution, persistence, and defense evasion artifact identified across the investigation.
