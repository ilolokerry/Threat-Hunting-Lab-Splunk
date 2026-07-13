# Hunting Lateral Movement: PsExec (Service Creation)

## Overview

This report documents hunting for lateral movement artifacts under the Lateral Movement tactic on the MITRE ATT&CK framework. The related technique is Remote Services: SMB/Windows Admin Shares (T1021.002), commonly carried out using PsExec-style tools. These tools move laterally by copying a binary to a remote host and installing it as a Windows service to gain execution. I used Splunk to hunt for the service creation event this technique leaves behind, then corroborated it with registry evidence.

## Investigation

### Step 1: Search for newly created services

```spl
index="aa15cbf9" source="xmlwineventlog:system" EventCode=7045
| table _time, Computer, AccountName, ServiceName, ImagePath, ServiceType, StartType
```

![Screenshot placeholder: Event ID 7045 new service created](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/50b7f9277ba07942a3f9ecb69cca5b517b2cfe23/04-Hunting%20%20for%20Lateral%20Movement/Media/psexec(service%20creation)/step1.png)

| Time | Computer | AccountName | ServiceName | ImagePath | ServiceType | StartType |
|---|---|---|---|---|---|---|
| 22:28:11 | WKS-4F1D.avongate.local | LocalSystem | PtQC | %systemroot%\THybZSNv.exe | user mode service | demand start |

This single result stood out immediately: the service name `PtQC` is not a recognizable Windows or third-party service name, and the image path points to `THybZSNv.exe` — a binary already confirmed as malicious in the earlier execution hunting reports. Because it was installed as a `LocalSystem` service, it runs with full system privileges.

### Step 2: Corroborate with registry evidence

Service creation also writes or modifies a registry key under the Services hive, so I checked there for matching evidence.

```spl
index="aa15cbf9" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=13
TargetObject="HKLM\System\CurrentControlSet\Services\*\ImagePath"
| table _time, Computer, User, TargetObject, Details, Image, ProcessId
| sort -_time
```

![Screenshot placeholder: registry service ImagePath keys](https://github.com/ilolokerry/Threat-Hunting-Lab-Splunk/blob/50b7f9277ba07942a3f9ecb69cca5b517b2cfe23/04-Hunting%20%20for%20Lateral%20Movement/Media/psexec(service%20creation)/step2.png)

| Computer | User | TargetObject | Details | Image | ProcessId |
|---|---|---|---|---|---|
| WKS-4F1D.avongate.local | SYSTEM | HKLM\...\Services\MicrosoftEdgeElevationService\ImagePath | "...\Edge\Application\137.0.3296.68\elevation_service.exe" | C:\WINDOWS\system32\services.exe | 728 |
| WKS-4F1D.avongate.local | SYSTEM | HKLM\...\Services\PtQC\ImagePath | %%systemroot%%\THybZSNv.exe | C:\WINDOWS\system32\services.exe | 728 |

Both registry keys were written by `services.exe`, which is expected — this is the normal Windows process responsible for registering services. The first entry is a legitimate Microsoft Edge component. The second confirms the same malicious service found in Step 1, tying the Event ID 7045 service creation event directly to a registry artifact from the same process and timestamp.

## Key Findings

- A new Windows service named `PtQC` was installed, pointing to the known-malicious `THybZSNv.exe`, running as `LocalSystem`.
- The registry evidence under `HKLM\System\CurrentControlSet\Services\PtQC\ImagePath` independently confirmed the same service, written by the legitimate `services.exe` process — meaning the malicious entry itself is genuine, not a logging artifact.
- An oddly short, non-descriptive service name (`PtQC`) installed by a binary already flagged elsewhere in the investigation is a strong indicator of PsExec-style lateral movement tooling.

## Key Takeaways

- Event ID 7045 (new service installed) is the primary native Windows signal for this technique, and should always be checked for unfamiliar or randomly-named services.
- Confirming a suspicious service against its registry `ImagePath` key adds a second, independent data source pointing to the same conclusion, which strengthens confidence before escalating a finding.
- A short, meaningless service name is itself a detail worth flagging — legitimate software almost always registers services with descriptive, recognizable names.

## Conclusion

I identified a malicious Windows service (`PtQC`) installed by a known-malicious binary (`THybZSNv.exe`) running as `LocalSystem`, and confirmed it through matching Event ID 7045 and registry `ImagePath` evidence — consistent with PsExec-style lateral movement (T1021.002).
