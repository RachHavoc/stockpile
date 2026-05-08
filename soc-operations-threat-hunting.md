# SOC Operations Threat Hunting Reference

Hunt reference for CCB SOC-Fundies adversary operations. Each section maps to a Caldera adversary profile and lists the abilities it runs, the events each generates, and a KQL query to find it in Kibana.

---

## L4 - Silent Host (`4a200001`)

> Disable Filebeat on a chosen host mid-morning of L4 so students detect the telemetry gap via Zeek log absence.

| Step | Ability | Tactic | Technique | Windows Events | Sysmon | KQL |
|---|---|---|---|---|---|---|
| 1 | **4a100001** Disable Filebeat | Defense Evasion | T1562.001 – Impair Defenses | 7036 (service stopped), 7040 (config change) | 1 | `winlog.event_id: "7036" AND winlog.event_data.param2: "stopped"` |

---

## L5 - Alert Generator (`4a200002`)

> Eight-step attack chain fired ~10 minutes apart during L5 morning; each step generates a distinct alert for live student triage.

| Step | Ability | Tactic | Technique | Windows Events | Sysmon | KQL |
|---|---|---|---|---|---|---|
| 1 | **4a100002** Encoded PowerShell | Execution | T1059.001 – PowerShell | 4688, **4104** (script block) | 1 | `event.code: "4104" AND powershell.file.script_block_text: *-EncodedCommand*` |
| 2 | **4a100003** DNS query to unknown domain | C2 | T1071.004 – DNS | — | **22** (DNS query) | `winlog.event_id: "22" AND winlog.event_data.QueryName: *.invalid` |
| 3 | **4a100004** Burst of failed logons vs DC | Credential Access | T1110.001 – Password Guessing | **4625** (failed logon), 4776 (NTLM fail) | 3 | `event.code: "4625" AND winlog.event_data.SubStatus: "0xC000006A"` |
| 4 | **4a100005** WMI lateral movement | Lateral Movement | T1021.006 – WMI | 4688, 4624 (logon type 3 on remote) | 1, 3 | `winlog.event_id: "3" AND destination.port: 135 AND process.name: "powershell.exe"` |
| 5 | **4a100006** Large outbound data transfer | Exfiltration | T1041 – Exfil Over C2 | 4688 | 3 | `winlog.event_id: "3" AND process.name: "powershell.exe" AND NOT destination.port: (80 OR 443 OR 53)` |
| 6 | **4a100007** Scheduled task creation | Persistence | T1053.005 – Scheduled Task | **4698** (task created) | 1 | `event.code: "4698" AND winlog.event_data.TaskContent: *powershell*` |
| 7 | **4a100008** Process injection via CreateRemoteThread | Defense Evasion | T1055.003 – Thread Hijacking | 4688 | **8** (CreateRemoteThread) | `winlog.event_id: "8" AND NOT winlog.event_data.SourceImage: ("*svchost.exe" OR "*csrss.exe")` |
| 8 | **4a100009** Add account to local Administrators | Persistence | T1098 – Account Manipulation | **4720** (acct created), **4732** (added to group) | 1 | `event.code: "4732" AND winlog.event_data.TargetUserName: "Administrators"` |

---

## L6 - Ransomware Chain (`4a200003`)

> Four-step kill chain simulating phishing to ransomware impact — phishing doc open, encoded PS dropper, AD account abuse, mass file rename.

| Step | Ability | Tactic | Technique | Windows Events | Sysmon | KQL |
|---|---|---|---|---|---|---|
| 1 | **4a10000a** Phishing simulant – open lure doc | Execution | T1204.002 – Malicious File | 4688 | 1 | `process.name: "notepad.exe" AND process.parent.name: "powershell.exe"` |
| 2 | **4a10000b** Encoded PowerShell dropper | Execution | T1059.001 – PowerShell | 4688, **4104** | 1 | `event.code: "4104" AND powershell.file.script_block_text: (*-EncodedCommand* OR *-Enc*)` |
| 3 | **4a10000c** AD account abuse – add to Admins | Credential Access | T1098 – Account Manipulation | 4720, **4732** | 1 | `event.code: "4732" AND winlog.event_data.TargetUserName: "Administrators"` |
| 4 | **4a10000d** Simulated mass file rename | Impact | T1486 – Data Encrypted for Impact | **4104** | 1 | `event.code: "4104" AND powershell.file.script_block_text: *Rename-Item*` |

---

## L7 - Anomaly Patterns (`4a200004`)

> Three behavioral anomalies spread across L7 morning for students to detect and write detection rules against.

| Step | Ability | Tactic | Technique | Windows Events | Sysmon | KQL |
|---|---|---|---|---|---|---|
| 1 | **4a10000e** Periodic HTTP C2 beaconing | C2 | T1071.001 – Web Protocols | 4688 | **3** (network connect) | `event.code: "4688" AND process.name: "powershell.exe" AND process.args: *-EncodedCommand*` |
| 2 | **4a10000f** HTTPS beacon / unusual JA3 | C2 | T1071.001 – Web Protocols | 4688 | 3 | `event.code: "4688" AND process.name: "powershell.exe" AND process.args: *-EncodedCommand*` |
| 3 | **4a100010** Scheduled task persistence | Persistence | T1053.005 – Scheduled Task | **4698**, 4702 (task updated) | 1 | `event.category: "process" AND process.command_line: *Register-ScheduledTask*` |

---

## L8 Scenario 1 - Phishing to C2 (`4a200005`)

> Full phishing-to-C2 kill chain — lure email delivered via mail VM, victim executes payload, persistent C2 beacon established.

| Step | Ability | Tactic | Technique | Windows Events | Sysmon | KQL |
|---|---|---|---|---|---|---|
| 1 | **4a100011** Send phishing lure email | Execution | T1566.001 – Spearphishing Attachment | 4688, 4104 | 1, 3 (port 25) | `winlog.event_id: "3" AND destination.port: 25 AND process.name: "powershell.exe"` |
| 2 | **4a100012** Phishing payload execution on victim | Execution | T1204.001 – Malicious Link | 4688, **4104** | 1, 3 | `event.code: "4104" AND powershell.file.script_block_text: (*Invoke-WebRequest* OR *WebClient*)` |
| 3 | **4a100013** Establish persistent C2 beacon | C2 | T1071.001 – Web Protocols | 4688 | 3 | `winlog.event_id: "3" AND process.name: "powershell.exe" AND NOT destination.port: (80 OR 443 OR 53)` |

---

## L8 Scenario 2 - Credential Misuse + Exfil (`4a200006`)

> Three-step post-compromise chain — credential misuse, SMB lateral movement to svr-db01, high-volume data exfiltration visible in Arkime/Zeek.

| Step | Ability | Tactic | Technique | Windows Events | Sysmon | KQL |
|---|---|---|---|---|---|---|
| 1 | **4a100014** Valid account credential misuse | Credential Access | T1078.002 – Domain Accounts | **4624** (logon type 3), **4648** | 1, 3 | `event.code: "4624" AND winlog.event_data.LogonType: "3" AND winlog.event_data.AuthenticationPackageName: "NTLM"` |
| 2 | **4a100015** Lateral movement to svr-db01 via SMB | Lateral Movement | T1021.002 – SMB/Windows Admin Shares | **5140** (share accessed), 4624 logon type 3 | 3 (port 445) | `event.code: "5140" AND winlog.event_data.ShareName: *C$` |
| 3 | **4a100016** Data exfiltration to svr-db01:1433 | Exfiltration | T1041 – Exfil Over C2 Channel | 4688 | 3 (port 1433) | `winlog.event_id: "3" AND destination.port: 1433 AND NOT process.name: ("sqlservr.exe" OR "ssms.exe")` |

---

## Quick Reference: Event IDs

### Sysmon
| ID | Event |
|---|---|
| 1 | Process creation |
| 3 | Network connection |
| 8 | CreateRemoteThread |
| 11 | File created |
| 12/13 | Registry key created / value set |
| 22 | DNS query |

### Windows Security Log
| ID | Event |
|---|---|
| 4104 | PowerShell script block logged |
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4688 | Process created |
| 4698 | Scheduled task created |
| 4702 | Scheduled task updated |
| 4720 | User account created |
| 4732 | Member added to local group |
| 4776 | NTLM credential validation |
| 5140 | Network share accessed |

### Windows System Log
| ID | Event |
|---|---|
| 7036 | Service started or stopped |
| 7040 | Service start type changed |

---

## Prerequisites

For full visibility, the following must be enabled on Windows endpoints:

- **Sysmon** installed with a config capturing events 1, 3, 8, 11, 22
- **PowerShell Script Block Logging** enabled (`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`)
- **Audit Process Creation** enabled in Group Policy (generates 4688 with command line)
- **Filebeat** shipping Winlogbeat + Sysmon logs to Elastic
