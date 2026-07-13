# Hunting Lateral Movement: PsExec (Reversing Regex)

## Overview

This report documents hunting for lateral movement artifacts under the Lateral Movement tactic on the MITRE ATT&CK framework. The related technique is Remote Services: SMB/Windows Admin Shares (T1021.002). Rather than relying only on the single service identified in the previous report, I reviewed the source code of a PsExec-style tool to understand its default naming behavior, then built regex-based Splunk queries to hunt for that pattern across multiple log sources.

## Background: Understanding the Tool's Naming Convention

I reviewed a service install helper script from Impacket, the Python library used to build tools like `psexec.py` and `smbrelayx.py`. The relevant logic is in its `ServiceInstall` class:

```python
self.__service_name = serviceName if len(serviceName) > 0 else \
    ''.join([random.choice(string.ascii_letters) for i in range(4)])
...
if binary_service_name is None:
    self.__binary_service_name = ''.join([random.choice(string.ascii_letters) for i in range(8)]) + '.exe'
```

This confirmed two important defaults:

- If no service name is provided, the tool generates a **random 4-letter service name**.
- If no binary name is provided, the tool generates a **random 8-letter filename** with a `.exe` extension.

This matches exactly what was found in the previous report: service name `PtQC` (4 letters) pointing to `THybZSNv.exe` (8 letters + extension). Since this naming pattern regenerates on every run, hunting for the literal name isn't reliable — hunting for the *pattern* is.

## Investigation

### Step 1: Hunt for 4-letter service names

```spl
index="aa15cbf9" source="xmlwineventlog:system" EventCode=7045
| regex ServiceName="^[A-Za-z]{4}$"
| table _time, Computer, AccountName, ServiceName, ImagePath
```

![Screenshot placeholder: regex match on 4-letter service names](screenshots/1b-regex-4letter-servicename.png)

| Time | Computer | AccountName | ServiceName | ImagePath |
|---|---|---|---|---|
| 22:28:11 | WKS-4F1D.avongate.local | LocalSystem | PtQC | %systemroot%\THybZSNv.exe |

### Step 2: Confirm the same pattern in the registry

```spl
index="aa15cbf9" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=13
| regex TargetObject="HKLM\\System\\CurrentControlSet\\Services\\[A-Za-z]{4}\\ImagePath"
| table _time, Computer, User, TargetObject, Details, Image
```

![Screenshot placeholder: regex match on 4-letter service registry key](screenshots/1b-regex-4letter-registry.png)

| Time | Computer | User | TargetObject | Details | Image |
|---|---|---|---|---|---|
| 22:28:11 | WKS-4F1D.avongate.local | NT AUTHORITY\SYSTEM | HKLM\...\Services\PtQC\ImagePath | %%systemroot%%\THybZSNv.exe | C:\WINDOWS\system32\services.exe |

### Step 3: Hunt for the 8-letter binary name in service creation

```spl
index="aa15cbf9" source="xmlwineventlog:system" EventCode=7045
| regex ImagePath=".\\[A-Za-z]{8}\.exe$"
| table _time, Computer, AccountName, ServiceName, ImagePath
```

![Screenshot placeholder: regex match on 8-letter binary name](screenshots/1b-regex-8letter-binary.png)

| Time | Computer | AccountName | ServiceName | ImagePath |
|---|---|---|---|---|
| 22:28:11 | WKS-4F1D.avongate.local | LocalSystem | PtQC | %systemroot%\THybZSNv.exe |

### Step 4: Confirm the 8-letter binary pattern in the registry

```spl
index="aa15cbf9" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=13
TargetObject="HKLM\System\CurrentControlSet\Services\*\ImagePath"
| regex Details=".*\\[A-Za-z]{8}\.exe"
| table _time, Computer, User, TargetObject, Details, Image
```

![Screenshot placeholder: regex match on 8-letter binary in registry Details](screenshots/1b-regex-8letter-registry.png)

| Time | Computer | User | TargetObject | Details | Image |
|---|---|---|---|---|---|
| 22:28:11 | WKS-4F1D.avongate.local | NT AUTHORITY\SYSTEM | HKLM\...\Services\PtQC\ImagePath | %%systemroot%%\THybZSNv.exe | C:\WINDOWS\system32\services.exe |

### Step 5: Confirm the file itself was dropped matching the pattern

```spl
index="aa15cbf9" source="xmlwineventlog:microsoft-windows-sysmon/operational" EventID=11
| regex TargetFilename="C:\\Windows\\[A-Za-z]{8}\.exe"
| table _time, Computer, User, TargetFilename, Image
```

I scoped this specifically to files created directly in `C:\Windows\` — not a subfolder — since that's where this tool drops its binary by default, and it kept the results limited to genuinely relevant hits.

![Screenshot placeholder: regex match on 8-letter exe file drop](screenshots/1b-regex-8letter-filedrop.png)

| Time | Computer | User | TargetFilename | Image |
|---|---|---|---|---|
| 22:28:11 | WKS-4F1D.avongate.local | NT AUTHORITY\SYSTEM | C:\Windows\THybZSNv.exe | System |

## Key Findings

- Every regex-based query, across three independent log sources — service creation (7045), registry (Sysmon Event ID 13), and file creation (Sysmon Event ID 11) — converged on the exact same service name and binary, `PtQC` and `THybZSNv.exe`.
- This cross-source agreement confirms the finding isn't a fluke of one log source, and matches precisely what the tool's own source code predicts it would generate.
- Building the hunt around the tool's naming *pattern*, rather than the specific name found once, means this same set of queries would also catch a different run of the same tool with different random characters.

## Key Takeaways

- Reading the source code of common attacker tooling — even open-source, publicly available projects like Impacket — turns a one-off finding into a repeatable, pattern-based detection.
- Regex hunting is most valuable when a finding is based on a generated or randomized value; searching for the literal string only ever catches that one occurrence.
- Cross-referencing the same suspected pattern across service, registry, and file system logs is a reliable way to confirm a finding, since an attacker would need to fake evidence in all three places simultaneously to produce a false positive here.

## Conclusion

I used knowledge of Impacket's PsExec-style service installer source code to build regex-based hunts for its default 4-letter service name and 8-letter binary name convention, and confirmed the same malicious service and binary across service creation, registry, and file system logs.
