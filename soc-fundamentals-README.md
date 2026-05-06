# SOC Fundamentals — Stockpile Content

This file documents the Caldera abilities, adversary profiles, payloads, and fact source added for the **SOC Fundamentals** course. All content uses the UUID prefix scheme `4a1xxxxx` (abilities), `4a2xxxxx` (adversaries), and `4a3xxxxx` (sources) to avoid collisions with upstream stockpile content.

---

## Fact source

**File:** `data/sources/4a300001-cafe-4003-8001-c0ffee300001.yml`
**Name in UI:** SOC Fundamentals Lab - Range Facts

Attach this source to every operation before running. Edit all `CHANGEME` values for your range:

| Fact | Description |
|---|---|
| `domain` | NetBIOS domain name (e.g. `SOCRANGE`) |
| `domain.user.name` | sAMAccountName of the test AD account |
| `domain.user.password` | Plaintext password for the test account |
| `remote.host.ip` | IP of wks02 (used by L5-4 WMI lateral) |
| `lateral.host.ip` | IP of svr-db01 (used by L8 Sc.2) |
| `mail.server.ip` | IP of the range mail VM (used by L8 Sc.1) |
| `target.user.email` | Recipient address for the phishing email |
| `attacker.host.ip` | IP of Attacker-WKS (used by all beaconing) |

---

## Pre-operation setup (range engineer)

### Before running L7 - Anomaly Patterns or L8 Sc.1 - Phishing to C2

Start a lightweight HTTP listener on **Attacker-WKS** so beaconing traffic has somewhere to land and registers byte volume in Zeek and Arkime:

```
python3 -m http.server 8080
```

The L7 JA3 anomaly ability also attempts port **8443** (HTTPS). If you want the TLS session visible in Zeek `ssl.log`, stand up a simple TLS listener there as well (e.g. with `openssl s_server -accept 8443 -cert ...`). The ability catches the failed handshake gracefully if nothing is listening, but the `ssl.log` entry will only appear if the handshake completes.

---

## Adversary profiles

### L4 — Silent Host
**File:** `data/adversaries/4a200001-cafe-4002-8001-c0ffee200001.yml`
**Trigger:** Mid-morning of L4
**Steps:** 1

Stops and disables the Filebeat service on the chosen host. Students detect the blind spot by noticing the host disappears from Zeek log coverage.

| # | Ability | Technique | Expected telemetry |
|---|---|---|---|
| 1 | Disable Filebeat on target host | T1562.001 | Service state change; host absent from Zeek |

---

### L5 — Alert Generator
**File:** `data/adversaries/4a200002-cafe-4002-8001-c0ffee200002.yml`
**Trigger:** Morning of L5, steps spaced ~10 minutes apart (total ~80 min)
**Steps:** 8

Eight distinct attack steps, each producing a different alert type for live student triage.

| # | Ability | Technique | Expected telemetry |
|---|---|---|---|
| 1 | Encoded PowerShell execution | T1059.001 | Sysmon EID 1; Windows 4688 with `-enc` flag |
| 2 | DNS query to never-before-seen domain | T1071.004 | Zeek `dns.log`; Suricata DNS rule hit |
| 3 | Burst of failed logons against dc01 | T1110.001 | Windows 4625 spike on dc01 |
| 4 | WMI remote process execution (wks01 → wks02) | T1021.006 | Sysmon EID 3; WMI activity logs; Windows 4688 on wks02 |
| 5 | Large outbound data transfer | T1041 | Zeek `conn.log` high byte volume; Arkime session |
| 6 | Scheduled task creation | T1053.005 | Windows 4698 |
| 7 | Process injection via CreateRemoteThread | T1055.003 | Sysmon EID 8 |
| 8 | Add account to local Administrators | T1098.001 | Windows 4732 |

---

### L6 — Ransomware Chain
**File:** `data/adversaries/4a200003-cafe-4002-8001-c0ffee200003.yml`
**Trigger:** Morning of L6
**Steps:** 4

Full kill chain from phishing to simulated ransomware impact. Files are renamed with `.soc_encrypted`; cleanup restores original names.

| # | Ability | Technique | Expected telemetry |
|---|---|---|---|
| 1 | Phishing simulant — open malicious document | T1204.002 | Sysmon EID 1 (notepad spawned from lure file); lure file in `%TEMP%` |
| 2 | Encoded PowerShell stage-2 dropper | T1059.001 | Sysmon EID 1 with `-enc`; marker file in `%APPDATA%` |
| 3 | AD account abuse — add to Domain Admins | T1098.001 | Windows 4728 (member added to global group) |
| 4 | Simulated mass file rename | T1486 | High-volume file-rename events in Sysmon/Windows; `.soc_encrypted` extension |

---

### L7 — Anomaly Patterns
**File:** `data/adversaries/4a200004-cafe-4002-8001-c0ffee200004.yml`
**Trigger:** Throughout L7 morning
**Steps:** 3

Behavioral anomalies for students to detect and write rules against.

> **Requires:** HTTP listener on Attacker-WKS port 8080 (see Pre-operation setup above).

| # | Ability | Technique | Expected telemetry |
|---|---|---|---|
| 1 | Periodic HTTP C2 beaconing | T1071.001 | Regular-interval connections to `attacker.host.ip:8080` in Zeek `conn.log` |
| 2 | HTTPS beacon with unusual JA3 fingerprint | T1071.001 | Unusual JA3 hash in Zeek `ssl.log` and Arkime; custom User-Agent |
| 3 | Scheduled task persistence with recurring beacon | T1053.005 | Windows 4698; follow-on beacon traffic every 5 min |

---

### L8 Sc.1 — Phishing to C2
**File:** `data/adversaries/4a200005-cafe-4002-8001-c0ffee200005.yml`
**Trigger:** Start of L8 morning
**Steps:** 3

Full phishing-to-C2 chain visible at both network and endpoint layers.

> **Requires:** HTTP listener on Attacker-WKS port 8080 (see Pre-operation setup above).

| # | Ability | Technique | Expected telemetry |
|---|---|---|---|
| 1 | Send phishing lure email via mail server | T1566.001 | SMTP trace in `logs-mail.*`; mail headers visible |
| 2 | Phishing payload execution on victim host | T1204.001 | Sysmon EID 1; marker file dropped in `%APPDATA%`; outbound beacon to `attacker.host.ip:8080` |
| 3 | Establish persistent C2 beacon channel | T1071.001 | Recurring connections to `attacker.host.ip:8080` in Zeek and Arkime |

---

### L8 Sc.2 — Credential Misuse + Exfil
**File:** `data/adversaries/4a200006-cafe-4002-8001-c0ffee200006.yml`
**Trigger:** After L8 Sc.1 debrief
**Steps:** 3

Post-compromise chain targeting svr-db01.

| # | Ability | Technique | Expected telemetry |
|---|---|---|---|
| 1 | Valid account credential misuse | T1078.002 | Windows 4624 (logon) and 4648 (explicit credentials) on target |
| 2 | Lateral movement to svr-db01 via SMB | T1021.002 | Zeek `smb_files.log`; Windows 4624 on svr-db01 |
| 3 | 10 MB data exfil to svr-db01:1433 | T1041 | Zeek `conn.log` high byte volume to svr-db01; Arkime session |

---

## Payload scripts

| File | Used by | Purpose |
|---|---|---|
| `payloads/simulate_ransomware_rename.ps1` | L6 step 4 | Renames up to 50 files with `.soc_encrypted`; cleanup in ability reverses it |
| `payloads/beacon_loop.ps1` | L7 steps 1 & 3, L8 Sc.1 step 3 | Sends N HTTP GET beacons at a fixed interval to a configurable URI |
| `payloads/create_remote_thread_sim.ps1` | L5 step 7 | P/Invokes `CreateRemoteThread` (suspended thread) into a spawned notepad process to trigger Sysmon EID 8; kills notepad on exit |
| `payloads/phishing_lure.ps1` | L8 Sc.1 step 2 | Drops a timestamped marker file in `%APPDATA%` and fires an initial outbound beacon |

---

## Ability UUIDs quick reference

| UUID | Name |
|---|---|
| `4a100001-cafe-4001-8001-c0ffee000001` | Disable Filebeat on target host |
| `4a100002-cafe-4001-8001-c0ffee000002` | Encoded PowerShell execution (L5-1) |
| `4a100003-cafe-4001-8001-c0ffee000003` | DNS query to never-before-seen domain (L5-2) |
| `4a100004-cafe-4001-8001-c0ffee000004` | Burst of failed logons against dc01 (L5-3) |
| `4a100005-cafe-4001-8001-c0ffee000005` | WMI remote process execution (L5-4) |
| `4a100006-cafe-4001-8001-c0ffee000006` | Large outbound data transfer (L5-5) |
| `4a100007-cafe-4001-8001-c0ffee000007` | Scheduled task creation (L5-6) |
| `4a100008-cafe-4001-8001-c0ffee000008` | Process injection via CreateRemoteThread (L5-7) |
| `4a100009-cafe-4001-8001-c0ffee000009` | Add account to local Administrators (L5-8) |
| `4a10000a-cafe-4001-8001-c0ffee00000a` | Phishing simulant — open malicious document (L6-1) |
| `4a10000b-cafe-4001-8001-c0ffee00000b` | Encoded PowerShell stage-2 dropper (L6-2) |
| `4a10000c-cafe-4001-8001-c0ffee00000c` | AD account abuse — add to Domain Admins (L6-3) |
| `4a10000d-cafe-4001-8001-c0ffee00000d` | Simulated mass file rename (L6-4) |
| `4a10000e-cafe-4001-8001-c0ffee00000e` | Periodic C2 beaconing (L7-1) |
| `4a10000f-cafe-4001-8001-c0ffee00000f` | HTTPS beacon with unusual JA3 fingerprint (L7-2) |
| `4a100010-cafe-4001-8001-c0ffee000010` | Scheduled task persistence with recurring beacon (L7-3) |
| `4a100011-cafe-4001-8001-c0ffee000011` | Send phishing lure email via mail server (L8-1) |
| `4a100012-cafe-4001-8001-c0ffee000012` | Phishing payload execution on victim host (L8-2) |
| `4a100013-cafe-4001-8001-c0ffee000013` | Establish persistent C2 beacon channel (L8-3) |
| `4a100014-cafe-4001-8001-c0ffee000014` | Valid account credential misuse (L8sc2-1) |
| `4a100015-cafe-4001-8001-c0ffee000015` | Lateral movement to svr-db01 via SMB (L8sc2-2) |
| `4a100016-cafe-4001-8001-c0ffee000016` | 10 MB data exfil to svr-db01:1433 (L8sc2-3) |
