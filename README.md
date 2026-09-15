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

No victim / evidence machine (`wvvm`). No Sliver C2.

---

## Machines

### AXVM — Analyst Workstation (Xubuntu Noble)

User `analyst` / `Password123!` (sudoer, SSH enabled).

**Software (via apt):**
- `git`, `curl`, `wget`, `unzip`
- `jq`, `less`, `xxd`
- `terminator` (default multi-pane terminal for the analyst)
- `python3`

**Evidence:**
- The parsed textual artefacts under this repo's `evidence/`
  directory are copied to `/home/analyst/evidence/` at provision
  time. Nothing else from the repo is deployed to the VM.

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

## Notes

- No Ansible Windows collection is required — the lab is Linux-only.
- The `analyst` account is granted passwordless sudo for convenience;
  the range is single-tenant.
