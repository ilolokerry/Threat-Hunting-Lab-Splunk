# Hunting Cmd Execution

## Overview

This report documents hunting for execution artifacts under the Execution tactic on the MITRE ATT&CK framework. The related technique is Command and Scripting Interpreter: Windows Command Shell (T1059.003). I used Splunk to search Windows Security logs for evidence of `cmd.exe` being used to carry out an attack, continuing from the PowerShell activity traced in the previous report.

## Log Source

- XmlWinEventLog:Security (Event ID 4688 — process creation)

## Investigation

### Step 1: Search for suspicious cmd.exe process creation

```spl
index="aa15cbf9" source="xmlwineventlog:security" EventID=4688
NewProcessName="*\cmd.exe" AND ParentProcessName!="C:\Windows\explorer.exe"
```

This returned a single event, which I expanded into a full table.

```spl
index="aa15cbf9" source="xmlwineventlog:security" EventID=4688
NewProcessName="*\cmd.exe" AND ParentProcessName!="C:\Windows\explorer.exe"
| table _time, Computer, SubjectUserName, NewProcessName, NewProcessId, CommandLine, ParentProcessName, ProcessId
```

![Screenshot placeholder: cmd.exe process creation event](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/b3a770b96ce48c064e167ad223855f2bb1b08a3f/Hunting%20attack%20chains%20and%20execution/media/cmd/step1.png)

The result showed `cmd.exe` running under `WKS-4F1D.avongate.local`, with a parent process of `C:\Windows\THybZSNv.exe` — an unfamiliar binary sitting directly in `C:\Windows\`, which is not a normal location for a legitimate application.

### Step 2: Convert process IDs from hex to decimal

```spl
index="aa15cbf9" source="xmlwineventlog:security" EventID=4688
NewProcessName="*\cmd.exe" AND ParentProcessName!="C:\Windows\explorer.exe"
| eval NewProcessId=tonumber(NewProcessId, 16), ProcessId=tonumber(ProcessId, 16)
| table _time, Computer, SubjectUserName, NewProcessName, NewProcessId, CommandLine, ParentProcessName, ProcessId
```

Windows Security logs record process IDs in hexadecimal, so I converted them to decimal to make correlation with Sysmon data straightforward. This gave `cmd.exe` a `NewProcessId` of 3916.

### Step 3: Pivot on the cmd.exe process ID to reconstruct activity

```spl
index="aa15cbf9" source="xmlwineventlog:security" EventID=4688
| eval NewProcessId=tonumber(NewProcessId, 16), ProcessId=tonumber(ProcessId, 16)
| search ProcessId=3916
| table _time, Computer, SubjectUserName, NewProcessName, NewProcessId, CommandLine, ParentProcessName, ProcessId
| sort - _time
```

![Screenshot placeholder: full list of child processes spawned by cmd.exe](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/b3a770b96ce48c064e167ad223855f2bb1b08a3f/Hunting%20attack%20chains%20and%20execution/media/cmd/step3.png)

Searching for every process with a `ParentProcessId` of 3916 exposed the full sequence of commands run from that `cmd.exe` session, in order:

| Time | Process | Command |
|---|---|---|
| 22:28:37 | whoami.exe | whoami /all |
| 22:28:44 | ipconfig.exe | ipconfig /all |
| 22:29:46 | powershell.exe | Invoke-WebRequest to download dghelper.dll |
| 22:30:38 | reg.exe | reg add Run key persistence for dghelper.dll |
| 22:30:48 | wevtutil.exe | wevtutil cl Security |
| 22:30:54 | wevtutil.exe | wevtutil cl System |
| 22:30:58 | wevtutil.exe | wevtutil cl Application |
| 22:31:18 | certutil.exe | certutil -urlcache -split -f to download mimi.exe |
| 22:31:33 | mimi.exe | executed |

## Key Findings

- This single `cmd.exe` session was responsible for the entire attack sequence: reconnaissance, tool download, persistence, defense evasion, and credential theft tooling.
- `whoami /all` and `ipconfig /all` show reconnaissance of the local user context and network configuration.
- The Registry Run key addition (`reg add ... /v Updater ...`) established persistence by pointing to `dghelper.dll` — covered in more depth in the persistence hunting report.
- Clearing the Security, System, and Application event logs with `wevtutil cl` is a defense evasion technique meant to remove evidence of the activity.
- `certutil -urlcache -split -f` was used to download `mimi.exe`, a credential-theft-style tool named similarly to Mimikatz, from the same external host used for the earlier DLL download.

## Key Takeaways

- Pivoting on a process ID rather than a single event turns one suspicious line into a full timeline of attacker behavior.
- Hex-to-decimal conversion is a small but necessary step when correlating Windows Security log process IDs with Sysmon data.
- A single `cmd.exe` session can chain together multiple ATT&CK tactics — reconnaissance, persistence, defense evasion, and credential access — which is why tracking the full process ancestry matters more than looking at isolated events.

## Conclusion

I reconstructed a full attacker command sequence executed through `cmd.exe` (T1059.003), spanning reconnaissance, persistence, log clearing, and credential theft tooling, by pivoting on a single process ID.
