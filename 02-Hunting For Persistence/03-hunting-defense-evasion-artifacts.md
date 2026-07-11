# Hunting Defense Evasion Artifacts

## Overview

This report documents hunting for defense evasion artifacts under the Defense Evasion tactic on the MITRE ATT&CK framework. The related technique is Indicator Removal: Clear Windows Event Logs (T1070.001). I used Splunk to check whether Windows event logs had been cleared, then correlated that activity with Sysmon process data to identify exactly which process was responsible.

## Investigation

### Step 1: Check for Security log clearing (Event ID 1102)

```spl
index="aa15cbf9" source="xmlwineventlog:security" EventID=1102
| table _time, Computer, Channel, EventID, ClientProcessId, SubjectUserName, name
```

![Screenshot placeholder: Security log 1102 audit log cleared event](screenshots/1c-security-1102-cleared.png)

| Time | Computer | Channel | EventID | ClientProcessId | SubjectUserName | name |
|---|---|---|---|---|---|---|
| 22:30:49 | WKS-4F1D.avongate.local | Security | 1102 | 3892 | SYSTEM | The audit log was cleared |

This returned one event confirming the Security log was cleared, run under the `SYSTEM` account, with a `ClientProcessId` of 3892.

### Step 2: Correlate with Sysmon using the process ID

```spl
index="aa15cbf9" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=1
ProcessId=3892
earliest="06/11/2025:22:30:45" latest="06/11/2025:22:30:55"
| table _time, host, user, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel
```

Narrowing the Sysmon search to the exact process ID and a tight time window around the log-clear event identified the responsible process:

| Time | Host | User | Image | CommandLine | ParentImage | IntegrityLevel |
|---|---|---|---|---|---|---|
| 22:30:48 | WKS-4F1D | SYSTEM | C:\Windows\SysWOW64\wevtutil.exe | wevtutil cl Security | C:\Windows\SysWOW64\cmd.exe | System |

Parent process: `C:\Windows\SysWOW64\cmd.exe`, running at `System` integrity level.

### Step 3: Confirm with System log clearing (Event ID 104)

```spl
index="aa15cbf9" source="xmlwineventlog:system" EventID=104
| table _time, Computer, Channel, EventID, Object, action
```

![Screenshot placeholder: System log 104 cleared events](screenshots/1c-system-104-cleared.png)

| Time | Computer | Channel | EventID | Object | action |
|---|---|---|---|---|---|
| 22:30:54 | WKS-4F1D.avongate.local | System | 104 | — | cleared |
| 22:30:58 | WKS-4F1D.avongate.local | System | 104 | — | cleared |

This returned two additional log-clear events on the System channel, confirming more than just the Security log had been targeted.

### Step 4: Find every wevtutil clear command

```spl
index="aa15cbf9" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=1
| search Image="*\wevtutil.exe" AND CommandLine="*cl*"
| table _time, Computer, user, Image, CommandLine, ParentImage
| sort -_time
```

![Screenshot placeholder: full wevtutil log-clearing sequence](screenshots/1c-wevtutil-clear-sequence.png)

This confirmed the full log-clearing sequence, all run as `SYSTEM` from the same parent `cmd.exe` process:

| Time | Command | Log Cleared |
|---|---|---|
| 22:30:48 | wevtutil cl Security | Security |
| 22:30:54 | wevtutil cl System | System |
| 22:30:58 | wevtutil cl Application | Application |

## Key Findings

- The attacker cleared three Windows event logs — Security, System, and Application — using `wevtutil cl`, in that order, roughly 4-6 seconds apart.
- All three clearing commands were run as `SYSTEM` from the same `cmd.exe` parent process identified in the earlier execution-hunting reports, confirming this was part of the same attack session.
- Cross-referencing the native Security (1102) and System (104) log-clear events with Sysmon process creation (Event ID 1) confirmed both the fact that logs were cleared and exactly which process and command line did it.

## Key Takeaways

- Event ID 1102 (Security log cleared) and Event ID 104 (System log cleared) are the two native indicators to check first when confirming anti-forensic log clearing.
- Correlating a native log-clear event with Sysmon process data via process ID and a tight time window is what confirms the responsible command line, since the native events alone don't always show the full command.
- An attacker clearing multiple logs in quick succession, from the same parent process as earlier execution and persistence activity, is a strong signal that log clearing was a deliberate cleanup step at the end of an attack chain rather than routine maintenance.

## Conclusion

I confirmed Windows Event Log clearing (T1070.001) across the Security, System, and Application logs by correlating native 1102 and 104 log-clear events with Sysmon process data, tracing all three `wevtutil cl` commands back to the same attacker-controlled `cmd.exe` session.
