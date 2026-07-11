# Threat Hunting Lab — Splunk

## Overview

This project documents a hands-on threat hunting exercise conducted in Splunk. I traced a simulated attack chain end-to-end, hunting for execution, persistence, defense evasion, command-and-control, and lateral movement artifacts using SPL queries against Windows event log data. Each report maps the hunted technique to the MITRE ATT&CK framework and documents the exact query logic used to surface it.

## What I Did

- Traced a full attack chain in Splunk, correlating events from initial execution through lateral movement to reconstruct attacker activity step by step.
- Hunted execution artifacts, including PowerShell and Cmd-based execution, to identify malicious command-line activity.
- Hunted process trees to map parent-child process relationships and surface anomalous execution patterns.
- Hunted persistence artifacts, including Registry Run Keys and lookup table abuse, to detect attacker-established footholds.
- Hunted defense evasion artifacts used to bypass or blind security monitoring.
- Hunted command-and-control activity, including ingress tool transfer detected via LOLBAS execution, file system events, and network connection logs.
- Hunted lateral movement via PsExec, detecting service creation, regex-based log parsing, and named pipe activity used to move between hosts.

## Tools and Data Sources

- Splunk (SPL queries, field extraction, event correlation)
- Windows Event Logs / Sysmon telemetry
- MITRE ATT&CK framework for technique mapping

## Repository Structure

```
threat-hunting-lab-splunk/
├── README.md
├── part1-attack-chain-and-execution/
│   ├── hunting-powershell-execution.md
│   ├── hunting-cmd-execution.md
│   ├── hunting-process-trees.md
│   └── screenshots/
├── part2-persistence/
│   ├── hunting-persistence-registry-run-keys.md
│   ├── hunting-persistence-lookup-tables.md
│   ├── hunting-defense-evasion-artifacts.md
│   └── screenshots/
├── part3-command-and-control/
│   ├── hunting-c2-artifacts.md
│   ├── hunting-c2-ingress-tool-transfer-lolbas.md
│   ├── hunting-c2-ingress-tool-transfer-file-system-events.md
│   ├── hunting-c2-ingress-tool-transfer-network-connection-events.md
│   └── screenshots/
└── part4-lateral-movement/
    ├── hunting-lateral-movement-artifacts.md
    ├── hunting-lateral-movement-psexec-service-creation.md
    ├── hunting-lateral-movement-psexec-reversing-regex.md
    ├── hunting-lateral-movement-psexec-named-pipes.md
    └── screenshots/
```

## MITRE ATT&CK Mapping

| Report | Technique | Tactic |
|---|---|---|
| Hunting PowerShell Execution | T1059.001 | Execution |
| Hunting Cmd Execution | T1059.003 | Execution |
| Hunting Process Trees | T1057 | Discovery |
| Hunting Persistence: Registry Run Keys | T1547.001 | Persistence |
| Hunting Persistence: Lookup Tables | T1546 | Persistence |
| Hunting Defense Evasion Artifacts | T1562 | Defense Evasion |
| Hunting C2: Ingress Tool Transfer | T1105 | Command and Control |
| Hunting Lateral Movement: PsExec | T1021.002 | Lateral Movement |

## Key Takeaways

- SPL correlation across multiple log sources is what turns isolated events into a full attack chain.
- Execution and persistence artifacts are often the earliest and most reliable signals of compromise.
- LOLBAS-based tool transfer blends in with normal admin activity, so file system and network events are needed to confirm intent.
- PsExec-based lateral movement leaves distinct traces in service creation, named pipes, and log formatting that can be hunted for directly.

## Conclusion

I built and documented a complete Splunk-based threat hunt covering execution, persistence, defense evasion, command-and-control, and lateral movement, with each technique mapped to MITRE ATT&CK.
