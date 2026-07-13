# Hunting C2: Ingress Tool Transfer (Network Connection Events)

## Overview

This report documents hunting for command-and-control artifacts under the Command and Control tactic on the MITRE ATT&CK framework. The related technique is Ingress Tool Transfer (T1105). Having already confirmed the download commands and the resulting files on disk, I used Sysmon network connection events to confirm the network-layer evidence and tie it back to the exact responsible process.

## Investigation

### Step 1: Search for network connection events

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=3
| table _time, Computer, User, Image, SourceIp, SourcePort, DestinationIp, Protocol, ProcessGuid
| sort -_time
```

![Screenshot placeholder: Sysmon network connection events](screenshots/1c-network-connection-events.png)

This surfaced a TCP connection made by PowerShell:

| Time | User | Image | SourceIp | SourcePort | DestinationIp | Protocol |
|---|---|---|---|---|---|---|
| 22:29:51 | SYSTEM | C:\WINDOWS\SysWOW64\WindowsPowerShell\v1.0\powershell.exe | 10[.]0[.]2[.]7 | 50637 | 10[.]0[.]2[.]6 | tcp |

The timing lines up almost exactly with the `Invoke-WebRequest` download of `dghelper.dll` identified in the LOLBAS report, which ran at 22:29:46 — a few seconds before this connection was logged.

### Step 2: Confirm the responsible process using ProcessGuid

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 ProcessGuid="{57bdb984-035a-684a-3e02-000000000f00}"
| table _time, host, user, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel
```

![Screenshot placeholder: process creation event matched by ProcessGuid](screenshots/1c-processguid-correlation.png)

Pivoting on the exact `ProcessGuid` from the network event confirmed the process that made the connection:

| Time | Host | User | Image | ParentImage | IntegrityLevel |
|---|---|---|---|---|---|
| 22:29:46 | WKS-4F1D | SYSTEM | C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe | C:\Windows\SysWOW64\cmd.exe | System |

This is the same `powershell.exe` process, spawned from the same `cmd.exe`, already identified across the execution, persistence, and LOLBAS reports — confirming every piece of evidence gathered so far belongs to a single, continuous attack session.

## Key Findings

- Sysmon Event ID 3 confirmed a real network connection from the compromised host (`10[.]0[.]2[.]7`) to the attacker-controlled host (`10[.]0[.]2[.]6`) over TCP, matching the timing of the PowerShell download command.
- Pivoting on `ProcessGuid` tied the network connection directly to the exact `powershell.exe` process creation event, closing the loop between "what connected" and "what command line caused it."
- This `powershell.exe` process, and its `cmd.exe` parent, are the same processes already confirmed responsible for the execution, persistence, and file-drop activity documented in the earlier reports.

## Key Takeaways

- Sysmon Event ID 3 is the definitive source for confirming that a suspicious download command actually resulted in real network traffic, rather than just being a command that was typed but never executed.
- `ProcessGuid` is the strongest correlation key available in Sysmon data — it ties a network connection to one exact process instance, even when process IDs get reused over time.
- When every stage of an investigation — execution, persistence, file drops, and network activity — keeps tracing back to the same process ancestry, that's strong confirmation the findings represent one coherent attack rather than several unrelated events.

## Conclusion

I confirmed the network-layer evidence for the PowerShell-based ingress tool transfer (T1105) by identifying the exact TCP connection to `10[.]0[.]2[.]6` and tying it back, via ProcessGuid, to the same `powershell.exe` process already traced through the execution and file system hunts.
