# Threat Hunting Investigation Report

**Host:** WKS-4F1D.avongate.local
**Investigation Date:** June 11, 2025 (event timeframe) — reported July 2026
**Analyst:** Ilolo Kerry
**Tools Used:** Splunk (SPL), Sysmon, Windows Event Logs, VirusTotal
**Status:** Closed — malicious activity confirmed

## Executive Summary

I investigated a single host, WKS-4F1D.avongate.local, and confirmed a full attack chain spanning initial execution, persistence, defense evasion, command-and-control tool transfer, and lateral movement. All activity traced back to one continuous attacker session, rooted in a single malicious binary (`THybZSNv.exe`) that was confirmed as malware via hash lookup. The attacker downloaded additional tooling, established registry-based persistence, attempted to erase evidence by clearing Windows event logs, and installed a remote-execution service consistent with PsExec-style lateral movement tooling.

## Scope and Environment

- **Host investigated:** WKS-4F1D.avongate.local
- **User context observed:** AVONGATE\mary.ellen, NT AUTHORITY\SYSTEM
- **Log sources:** XmlWinEventLog:Security, XmlWinEventLog:System, XmlWinEventLog:Application, Microsoft-Windows-Sysmon/Operational, Microsoft-Windows-PowerShell/Operational
- **Index:** aa15cbf9

## Attack Chain Timeline

| Time (2025-06-11) | Tactic | Activity |
|---|---|---|
| 22:28:11 | Execution / Lateral Movement | `THybZSNv.exe` appears on host, spawned from `services.exe`; service `PtQC` installed pointing to this binary |
| 22:28:12–14 | Lateral Movement | Named pipes created and connected (`RemCom_stdin`, `RemCom_stdout`, `RemCom_stderr`, `RemCom_communicaton`) |
| 22:28:14 | Execution | `THybZSNv.exe` spawns `cmd.exe` |
| 22:28:37 | Discovery | `whoami /all` executed |
| 22:28:44 | Discovery | `ipconfig /all` executed |
| 22:29:46 | Command and Control | PowerShell `Invoke-WebRequest` downloads `dghelper.dll` from `hxxp://10[.]0[.]2[.]6` |
| 22:29:50 | Command and Control | `dghelper.dll` confirmed written to `C:\Windows\SysWOW64\` |
| 22:29:51 | Command and Control | Network connection confirmed from host to `10[.]0[.]2[.]6` over TCP |
| 22:30:38 | Persistence | Registry Run key `Updater` added, pointing to `rundll32 dghelper.dll,MainFunc` |
| 22:30:48 | Defense Evasion | Security event log cleared (`wevtutil cl Security`) |
| 22:30:54 | Defense Evasion | System event log cleared (`wevtutil cl System`) |
| 22:30:58 | Defense Evasion | Application event log cleared (`wevtutil cl Application`) |
| 22:31:19 | Command and Control | `certutil -urlcache` downloads `mimi.exe` from `hxxp://10[.]0[.]2[.]6` |
| 22:31:33 | Execution | `mimi.exe` executed |

## Detailed Findings by Tactic

**Execution** — Confirmed malicious PowerShell and Cmd activity spawned from a single `cmd.exe` session, itself spawned by `THybZSNv.exe`. Process tree analysis confirmed `THybZSNv.exe`, launched from `services.exe`, as the root of the entire attack chain.

**Persistence** — A Registry Run key (`Updater`) was added under the 32-bit registry redirection path (`WOW6432Node`), pointing to `dghelper.dll`. This entry was missed by an initial manual hunt and only surfaced through a MITRE ATT&CK-mapped lookup table enrichment.

**Defense Evasion** — All three primary Windows event logs (Security, System, Application) were cleared within a 10-second window using `wevtutil cl`, in an attempt to remove evidence of the preceding activity.

**Command and Control / Ingress Tool Transfer** — Two separate tools (`certutil` and PowerShell) were used to download payloads (`mimi.exe` and `dghelper.dll`) from the same external host. Both downloads were confirmed at the network layer and on disk.

**Lateral Movement** — `THybZSNv.exe` installed itself as a Windows service (`PtQC`) with `LocalSystem` privileges, matching the random 4-letter/8-letter naming convention of a known PsExec-style (Impacket-based) remote execution tool. Named pipes matching the RemCom naming convention confirmed an active command channel.

## Indicators of Compromise

| Indicator | Type | Description |
|---|---|---|
| `10[.]0[.]2[.]6` | IP address | Attacker-controlled staging server for tool downloads |
| `THybZSNv.exe` | File | Root malicious binary; confirmed malware via VirusTotal (MD5: `6983F7001DE10F4D19FC2D794C3EB534`) |
| `dghelper.dll` | File | Persistence payload, loaded via `rundll32 ...,MainFunc` |
| `mimi.exe` | File | Credential-theft-style tool downloaded via `certutil` |
| `PtQC` | Service name | Malicious service installed for lateral movement execution |
| `HKLM\...\Run\Updater` | Registry key | Persistence entry pointing to `dghelper.dll` |
| `HKLM\...\Services\PtQC\ImagePath` | Registry key | Service registration pointing to `THybZSNv.exe` |
| `RemCom_stdin` / `_stdout` / `_stderr` / `_communicaton` | Named pipe | Command channel used by the lateral movement tool |

## MITRE ATT&CK Technique Summary

| Tactic | Technique ID | Technique Name |
|---|---|---|
| Execution | T1059.001 | Command and Scripting Interpreter: PowerShell |
| Execution | T1059.003 | Command and Scripting Interpreter: Windows Command Shell |
| Discovery | T1033 | System Owner/User Discovery |
| Discovery | T1016 | System Network Configuration Discovery |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs |
| Command and Control | T1105 | Ingress Tool Transfer |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares |

## Impact Assessment

The confirmed activity gave the attacker persistent, SYSTEM-level access to the host, a working command-and-control channel, and a functioning lateral movement capability via a remote service installer. The attempted log clearing indicates deliberate anti-forensic intent, meaning full scope of activity prior to detection cannot be ruled out from log data alone.

## Recommendations

- Isolate WKS-4F1D.avongate.local from the network pending full remediation.
- Remove the `PtQC` service, the `Updater` Run key, and all identified malicious files (`THybZSNv.exe`, `dghelper.dll`, `mimi.exe`).
- Block outbound traffic to `10[.]0[.]2[.]6` at the network perimeter.
- Reset credentials for any accounts active on the host during the incident window.
- Review other hosts on the network for the same service name pattern, registry persistence path, and named pipe naming convention, since this tooling generates new random names on each run.
- Enable centralized, tamper-resistant log forwarding to prevent local log clearing from destroying investigative evidence in future incidents.

## Conclusion

I traced a complete attacker session on WKS-4F1D.avongate.local from initial execution through lateral movement tooling, confirming every stage of the MITRE ATT&CK chain with corroborating evidence across process, registry, file system, and network log sources.
