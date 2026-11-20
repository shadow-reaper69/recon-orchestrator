# 🛡️ ReconOrchestrator

> **Automated Reconnaissance & Attack-Surface Inventory Pipeline (Educational Prototype)**
> 
> *A defensive, policy-enforced security orchestration tool designed for authorised assessments, cybersecurity students, and bug bounty asset discovery.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-13%20Passed-brightgreen.svg)]()
[![Design](https://img.shields.io/badge/Design-Strict%20Scope%20Guardrails-red.svg)]()

---

> [!WARNING]
> ### ⚖️ Authorisation Notice & Legal Warning
> This software is an educational prototype built exclusively for **AUTHORISED SECURITY ASSESSMENTS** on assets you own (personal lab/domains) or targets for which you possess explicit, written permission (such as in-scope vulnerability disclosure and bug bounty programs).
>
> Unauthorised scanning, network probing, or vulnerability checking against third-party systems is illegal under national and international cybercrime legislation, including:
> - **United States**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
> - **United Kingdom**: Computer Misuse Act 1990
> - **India**: Information Technology Act 2000, Section 43 & Section 66
> 
> **Zero Exploit Policy**: This tool writes no exploits, crafts no attacks, executes no brute-forcing, and performs no stealth evasion. All findings are labeled *"tool-reported, unverified"*.

---

## 📑 Table of Contents
1. [Architecture & Workflow](#1-architecture--workflow)
2. [Safety Guardrails](#2-safety-guardrails)
3. [Terminal Interface](#3-terminal-interface)
4. [Installation & Prerequisites](#4-installation--prerequisites)
5. [Usage Guide](#5-usage-guide)
6. [Output Artifacts](#6-output-artifacts)
7. [Running Tests](#7-running-tests)
8. [Limitations & Roadmap](#8-limitations--roadmap)

---

## 1. Architecture & Workflow

ReconOrchestrator brings together four open-source security tools into a sequential asset-inventory workflow:

```
                  ┌──────────────────────────────┐
                  │    Target Scope File (.txt)   │
                  │  (Domains / CIDRs Allowlist) │
                  └──────────────┬───────────────┘
                                 │
              [ --i-have-authorization check passed ]
                                 │
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ Stage 1: Subdomain OSINT (Subfinder)                        │
   │ » Passive asset enumeration for root domains                │
   └─────────────────────────────┬───────────────────────────────┘
                                 │ (Only In-Scope Subdomains)
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ Stage 2: HTTP Service Probing (httpx)                       │
   │ » Live status codes, page titles, tech-stack detection      │
   └─────────────────────────────┬───────────────────────────────┘
                                 │ (Active In-Scope Hosts)
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ Stage 3: Port & Service Fingerprinting (Nmap)               │
   │ » Conservative -sV -T3 timing on top ports                  │
   └─────────────────────────────┬───────────────────────────────┘
                                 │ (Live In-Scope Web Targets)
                                 ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ Stage 4: Template-Based Exposure Checks (Nuclei)            │
   │ » Non-intrusive severity filter (excludes intrusive/dos)   │
   └─────────────────────────────┬───────────────────────────────┘
                                 │
                                 ▼
                  ┌──────────────────────────────┐
                  │    Consolidated Reports      │
                  │  report.json  ·  report.md   │
                  └──────────────────────────────┘
```

---

## 2. Safety Guardrails

- **Mandatory Dual-Gate Execution**: Requires both a valid `scope.txt` and the explicit `--i-have-authorization` flag. Without both, the process terminates immediately.
- **Pre-Execution Scope Boundary Verification**: Every target, discovered subdomain, and resolved host is checked against the scope allowlist *before* passing to any active tool. Out-of-scope targets are dropped and logged.
- **Subprocess Security**: Commands use strictly formatted argument lists (`subprocess.run(..., shell=False)`). Flag injection is prevented by rejecting targets starting with `-` or containing illegal shell characters (`;`, `&`, `|`, `$`, `` ` ``, `<`, `>`, newlines).
- **Conservative Defaults**:
  - Request rate capped at 25 req/sec.
  - Nmap timing locked to `-T3` or lower (`-T4`/`-T5` are rejected).
  - Port scans default to the top 100 ports rather than all 65,535.
  - Nuclei automatically excludes `intrusive`, `dos`, and `fuzz` tags.
- **Tool Mismatch Protection**: Differentiates between Python's standard `httpx` package CLI and ProjectDiscovery's `httpx` reconnaissance binary.

---

## 3. Terminal Interface

The CLI uses the `rich` Python library for styled console presentation:
- **Terminal Header**: Displays assessment context and safety notices.
- **Tool Environment Table**: Real-time inspection of your PATH with binary versions and availability status.
- **Visual Stage Panels**: High-contrast stage indicators for each active inventory phase.
- **Run Summary Card**: Displays discovered asset counts and generated report file paths.

---

## 4. Installation & Prerequisites

### 1. Clone & Set Up Python Environment
Requires **Python 3.10+**:
```bash
git clone https://github.com/shadow-reaper69/recon-orchestrator.git
cd recon-orchestrator
pip install -r requirements.txt
```

### 2. Optional: Install Security Binaries
The pipeline **gracefully skips any stage whose tool is not installed**, logging a notification rather than failing.

To enable all four stages, install the tools:

| Tool | Installation Command | Official Resource |
|---|---|---|
| **Subfinder** | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | [GitHub](https://github.com/projectdiscovery/subfinder) |
| **httpx** | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` | [GitHub](https://github.com/projectdiscovery/httpx) |
| **Nmap** | Download installer for Windows/Linux/macOS | [nmap.org](https://nmap.org/download.html) |
| **Nuclei** | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | [GitHub](https://github.com/projectdiscovery/nuclei) |

---

## 5. Usage Guide

### Step 1: Define Your Scope
Create a scope text file (e.g. `scope.txt`) with one domain or CIDR per line:
```text
# Authorized Targets
example.com
lab.internal
192.168.1.0/24
```

### Step 2: Run the Pipeline
```bash
python -m recon.cli --scope scope.txt --i-have-authorization
```

### Advanced Usage Examples

**Skip specific tools:**
```bash
python -m recon.cli --scope scope.txt --i-have-authorization --skip nuclei --skip nmap
```

**Resume an interrupted run:**
```bash
python -m recon.cli --scope scope.txt --i-have-authorization --run-dir runs/example_com_20261120_134420Z --resume
```

**Custom rate limits & port ranges:**
```bash
python -m recon.cli --scope scope.txt --i-have-authorization --rate-limit 15 --top-ports 50 --nmap-timing -T2
```

---

## 6. Output Artifacts

Every scan generates an isolated, timestamped audit folder under `runs/<target>_<UTC_timestamp>/`:
```text
runs/example_com_20261120_134420Z/
├── raw/                      # Raw binary outputs (subfinder.txt, httpx.jsonl, nmap.xml, nuclei.jsonl)
├── parsed/                   # Clean, scope-filtered JSON files per stage
│   ├── subdomains.json
│   ├── http_services.json
│   ├── host_ports.json
│   └── findings.json
├── report/
│   ├── report.json           # Machine-readable report with metadata and limitations
│   └── report.md             # Human-readable Markdown summary with tables
└── run.log                   # Auditable execution log with timestamps
```

---

## 7. Running Tests

The test suite runs with `pytest` and uses synthetic test fixtures. **No external tools or network access are required**:
```bash
python -m pytest -v
```

Test coverage includes:
- Scope parsing (exact domain matches, subdomain hierarchy, CIDR network containment).
- Target validation (flag injection rejection, shell metacharacter rejection).
- Parsers (Subfinder line/JSON, httpx JSON-lines, safe Nmap XML parsing, Nuclei JSON-lines).
- Safe subprocess runner (execution security, timeout handling).

---

## 8. Limitations & Roadmap

### Limitations
- **Prototype Status**: Designed for educational asset-inventory research and portfolio demonstration; not an enterprise-scale vulnerability management system.
- **Unverified Findings**: All findings are direct tool outputs and require manual verification.
- **Rate-Limiting & Firewalls**: Conservative scanning parameters may still be blocked by aggressive cloud Web Application Firewalls (WAF).

### Roadmap
- [ ] Add DNS zone transfer and DNS record enumeration stage (`dnspython`).
- [ ] Add optional HTML report template with interactive visual charts.
- [ ] Add JSON-to-CSV converter for spreadsheet import.

---

## License
MIT License. Created for educational and authorised assessment purposes.
