# Hunting Lateral Movement: PsExec (Named Pipes)

## Overview

This report documents hunting for lateral movement artifacts under the Lateral Movement tactic on the MITRE ATT&CK framework. The related technique is Remote Services: SMB/Windows Admin Shares (T1021.002). PsExec-style tools establish named pipes to redirect standard input, output, and error streams between the attacker and the remote command execution session. I used Splunk to hunt for the creation and connection of these named pipes.

## Background: Named Pipes in PsExec-Style Tools

Named pipes are how PsExec-style tools carry command output back to the attacker over the same SMB connection used to install the service. A common open-source PsExec alternative uses these standard pipe names:

- `RemComSTDOUT` = `"RemCom_stdout"`
- `RemComSTDIN` = `"RemCom_stdin"`
- `RemComSTDERR` = `"RemCom_stderr"`

## Investigation

### Step 1: Search for RemCom-related pipe activity

```spl
index="aa15cbf9" source="xmlwineventlog:microsoft-windows-sysmon/operational"
(EventID=17 OR EventID=18) PipeName="*RemCom*"
| table _time, Computer, User, EventID, EventType, PipeName, Image, ProcessId
```

Sysmon Event ID 17 logs pipe creation, and Event ID 18 logs pipe connection — searching both together shows the full lifecycle of each named pipe.

![Screenshot placeholder: RemCom named pipe creation and connection events](screenshots/1c-remcom-pipe-events.png)

| Time | EventID | EventType | PipeName | Image | ProcessId |
|---|---|---|---|---|---|
| 22:28:12 | 17 | CreatePipe | \RemCom_communicaton | C:\WINDOWS\THybZSNv.exe | 1022 |
| 22:28:14 | 17 | CreatePipe | \RemCom_stdoutlsVQ33337 | C:\WINDOWS\THybZSNv.exe | 1022 |
| 22:28:14 | 17 | CreatePipe | \RemCom_stderrlsVQ33337 | C:\WINDOWS\THybZSNv.exe | 1022 |
| 22:28:14 | 17 | CreatePipe | \RemCom_stdinlsVQ33337 | C:\WINDOWS\THybZSNv.exe | 1022 |
| 22:28:14 | 18 | ConnectPipe | \RemCom_communicaton | System | 4 |
| 22:28:14 | 18 | ConnectPipe | \RemCom_stderrlsVQ33337 | System | 4 |
| 22:28:14 | 18 | ConnectPipe | \RemCom_stdoutlsVQ33337 | System | 4 |
| 22:28:14 | 18 | ConnectPipe | \RemCom_stdinlsVQ33337 | System | 4 |

## Key Findings

- `THybZSNv.exe` — the same malicious binary identified in the service creation and regex hunting reports — created four named pipes matching the RemCom naming convention: a communication pipe plus separate stdin, stdout, and stderr pipes, each with a randomized suffix (`lsVQ33337`).
- The `System` process (PID 4) connected to each of these pipes immediately after creation, which is the expected behavior for the kernel-level SMB/named pipe file system handling the connection on the local side.
- The pipe creation timestamps (22:28:12–22:28:14) align closely with the service creation timestamp (22:28:11) already confirmed in the service creation report, showing the full PsExec-style sequence — service install, then immediate pipe-based command channel setup — happening within about three seconds.

## Key Takeaways

- Named pipes with recognizable tool-specific naming patterns (like `RemCom_stdin`, `RemCom_stdout`, `RemCom_stderr`) are a strong, tool-specific indicator that's hard for an attacker to avoid if they're using that tool unmodified.
- Sysmon Event ID 17 (pipe created) and Event ID 18 (pipe connected) together show the full lifecycle of the channel, which is useful for confirming that a pipe wasn't just created but was actually used.
- Correlating pipe creation timestamps with the service creation timestamp from earlier in the investigation confirms these events are all part of one fast, automated attack sequence rather than unrelated activity.

## Conclusion

I identified the named pipe creation and connection sequence used by a PsExec-style remote execution tool, tied it to the same malicious binary (`THybZSNv.exe`) confirmed in the service creation hunt, and showed its command channel setup happened within seconds of the malicious service being installed.
