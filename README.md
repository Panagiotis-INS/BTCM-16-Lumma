# BTCMP-16 — Digital Forensics Lab Environment - Lumma ClickFix

Applied to **BTCMP-16 — Lumma Stealer / ClickFix Intrusion Evidence Analysis**.

## Overview

Single-analyst DFIR range. The student receives a pre-collected evidence
pack from a fictional Finance workstation (`FIN-WKS-07` at Northwind Solar
Analytics) that was compromised via the **ClickFix / Fake CAPTCHA**
social-engineering technique that drops a Lumma-family info-stealer.
Every artefact in the pack is a **parsed textual output** — the student
never needs the raw memory image or pcap.

The range therefore ships only an analyst workstation; there is no live
victim host and no C2 to emulate.

---

## Topology

| Host   | Role                                     | Network       | CIDR            | IP          |
|--------|------------------------------------------|---------------|-----------------|-------------|
| axvm   | Analyst Workstation (Xubuntu Noble)      | access-switch | 10.10.10.0/24   | 10.10.10.3  |
| router | Network Router (Debian 12)               | access-switch | 10.10.10.0/24   | 10.10.10.1  |

WAN: `10.10.100.0/24` (router uplink).

No victim / evidence machine (`wvvm`) — the "victim" is materialised as
the text-only evidence pack pulled from the lab repo during provisioning.
No Sliver C2.

---

## Machines

### AXVM — Analyst Workstation (Xubuntu Noble)

User `analyst` / `Password123!` (sudoer, SSH enabled).

**Software (via apt):**
- `git`, `curl`, `wget`, `unzip`
- `jq`, `ripgrep`, `less`, `xxd`
- `terminator` (default multi-pane terminal for the analyst)
- `yara` (offline PE/memory scanning for the trainer's YARA rules)
- `suricata` (offline pcap replay for the trainer's Suricata rules)
- `python3`, `python3-pip`, `pipx`

**Additional tooling (installed by provisioner):**
- `chainsaw` — Sigma-on-EVTX runner; binary from the WithSecureLabs
  GitHub release, symlinked into `/usr/local/bin/chainsaw`.
- `sigma-cli` — installed for the `analyst` user via `pipx` for
  rule-conversion exercises.

**Lab pack:**
- The lab tree (this repository) is rsync'd from the provisioner into
  `/home/analyst/lab` at provision time (excluding `.git` and
  `provisioning/`). The evidence pack lives under
  `/home/analyst/lab/evidence/`. Student pack / instructor pack /
  writeup markdown files sit at the repo root.

**Notes:**
- No Sliver C2 is installed. This lab is investigation-only.
- No SMB mount is required — the evidence is text on the local disk.

---

## The scenario

The student plays a Tier-2 SOC analyst at Northwind Solar Analytics.
The compromised user is `katerina.morfopoulou@northwind.lab` on host
`FIN-WKS-07`. Fifteen minutes after a suspicious outbound HTTPS burst,
the endpoint was isolated and the evidence pack collected.

The student must reconstruct the kill-chain and answer 15 flag
questions covering:

| Phase | Focus                                | # Flags |
|-------|--------------------------------------|---------|
| A     | Initial access (ClickFix)            | 3       |
| B     | Second-stage execution               | 2       |
| C     | Persistence (Run key)                | 1       |
| D     | Discovery, collection & privilege    | 2       |
| E     | Command & Control                    | 4       |
| F     | Exfiltration & impact                | 3       |

Each flag is submitted in `CTF{...}` form and is answerable **entirely
from the text pack** — no live host, no memory image, no pcap
required.

---

## Detection content shipped with the pack

- `detections/clickfix-precursor.sigma.yml` — Sigma rule for the
  `explorer.exe → powershell.exe → iwr/iex` ClickFix pattern.
- `detections/lumma-c2.suricata.rules` — Suricata rules for the
  `TeslaBrowser/5.5` UA + `POST /c2sock` C2 pattern and the
  `steamcommunity.com` dead-drop.
- `detections/northwind-clickfix.yar` — YARA rules for the trainer
  PE and its in-memory markers (ChaCha20 constants, ABE marker,
  FNV-1a basis).

Text-track: read the rules and map each clause to the corresponding
row in `evidence/*`. Engines-track: run the rules with `yara`,
`suricata -r`, and `chainsaw` — all three tools are pre-installed on
`axvm`.

---

## Notes

- No Ansible Windows collection is required — the lab is Linux-only.
- The `analyst` account is granted passwordless sudo for convenience;
  the range is single-tenant.
- Network egress is required at provision time to pull the Chainsaw
  release binary and the `sigma-cli` PyPI package.
