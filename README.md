# SecurityIntelligenceBrief v4.1

My personally customised cybersecurity intelligence briefing, designed to keep me current on significant security developments, emerging threats, external exposure and relevant governance changes.

SecurityIntelligenceBrief is a no-LLM, no-cloud-resource-cost pipeline built with Python, GitHub Actions and Gmail SMTP.

The pipeline collects structured intelligence from official advisories, vulnerability databases, vendor research, threat-intelligence sources, standards and governance publications, law-enforcement reporting, breach metadata and a curated set of cybersecurity news providers.

It applies deterministic relevance scoring, deduplication, CVSS enrichment, exposure classification, sector filtering and source-confidence labelling before delivering a daily HTML and plain-text briefing.

The Executive Summary focuses on actionable Security Advisory and dark-web-related exposure intelligence, while retaining the broader technical, operational and CISO-level coverage required to understand the overall security landscape.

See the [changelog](https://github.com/Killeck/SecuriytIntelligenceBrief/blob/main/changelog.md) for the complete development history.

---
## Version 4.2

Version 4.2 focuses on code efficiency, maintainability and runtime performance.

### Changes

* Replaced the single large Python file with a modular package.
* Added parallel source collection with configurable worker count.
* Added reusable HTTP sessions, retries and backoff.
* Reduced duplicated collection and error-handling logic.
* Split report preparation, text rendering and HTML rendering.
* Added automated regression tests to both GitHub Actions workflows.
* Kept the existing execution command and report output compatible with v4.1.

See [OPTIMISATION.md](OPTIMISATION.md) for technical details.

---

## Core behaviour

* Runs automatically at **07:07 Europe/Oslo**.
* Uses the previous **72 hours on Mondays**.
* Uses the previous **36 hours Tuesday through Sunday**.
* Emails the report through Gmail SMTP.
* Uses no paid LLM, Azure resource, database or hosted application.
* Continues processing when an individual source fails.
* Suppresses report sections that contain no qualifying information.
* Collapses successful zero-result sources into one quiet summary line.
* Keeps failed sources visible under **Source Coverage** and **Source Warnings**.
* Separates verified exposure information from unconfirmed or secondary reporting.
* Does not connect directly to onion services, criminal forums, ransomware leak sites or stolen-data repositories.

## Report structure

### Executive Security Advisory Summary

1. Security Advisory Level
2. Enterprise DEFCON-style Cyber Threat Level
3. Priority Security Advisories
4. Dark Web and Exposure Highlights
5. Ransomware and Extortion Watch
6. Credential and Stealer Exposure
7. Relevant Cyber News
8. Zero-Day and CVSS 10.0
9. Customer and Sector Advisory Impact
10. Recommended Security Advisory Actions
11. Compliance, Standards and Governance Changes
12. Going Live Today or Within 14 Days

### Exposure intelligence sections

1. Ransomware and Extortion
2. Credential Exposure and Stealer Logs
3. Data Breaches and Leaks
4. Initial Access and Cybercrime Markets
5. Brand, Impersonation and Phishing
6. Dark Web and Criminal Ecosystem

### Technical and CISO intelligence sections

1. Active Exploitation and CISA KEV
2. Law-Enforcement and Criminal Ecosystem Reporting
3. Microsoft, Azure and Identity
4. Fortinet
5. HPE and Aruba
6. Other Vendor Security Advisories
7. Cloud and Supply-Chain Security
8. SOC and Detection Engineering
9. Threat Intelligence
10. Vulnerability Research
11. OT, Energy and Oil & Gas
12. Scandinavia and Europe
13. Norwegian Security Governance
14. Compliance
15. Standards
16. GRC
17. Upcoming Compliance, Standards and Governance
18. Source Coverage
19. Security Advisory and CISO Watch List

Empty sections are not displayed.


## Threat-level model

The report uses an internal DEFCON-style cyber-risk scale. It is not the official United States military DEFCON status.

| Level | Label | Colour | Typical trigger |
|---|---|---|---|
| DEFCON 1 | Critical | Red | Exploited or zero-day CVSS 10.0 with immediate material exposure |
| DEFCON 2 | High | Orange | Zero-day, CVSS 10.0, or ransomware-linked KEV |
| DEFCON 3 | Elevated | Amber | KEV, active exploitation, ransomware or nation-state activity |
| DEFCON 4 | Guarded | Blue | Relevant security developments without confirmed immediate exploitation |
| DEFCON 5 | Low | Green | No qualifying developments collected |

## Source hierarchy

### Authoritative vulnerability and exploitation sources

- CISA Known Exploited Vulnerabilities
- NIST National Vulnerability Database API
- Fortinet PSIRT
- HPE Security Bulletin Library
- Apple Security Releases
- CISA ICS Advisories

### Vendor, threat-research and technical sources

- Microsoft Security Blog
- AWS Security Blog
- Palo Alto Networks Unit 42
- Google Project Zero
- Google Security Blog
- CrowdStrike Blog
- Cisco Talos
- FortiGuard Labs Threat Research
- Okta Security
- Elastic Security Labs
- Splunk Security Blog
- The DFIR Report
- SigmaHQ Releases
- Dragos
- Claroty Team82
- Nozomi Networks Labs

### Compliance, standards and governance sources

- ENISA News
- NIST CSRC News
- PCI Security Standards Council
- ISACA News and Trends
- ISO News
- NSM Updates
- NSM Security Warnings
- Local upcoming-governance register

### Secondary cyber-news discovery sources

These sources provide one-line discovery links in the Executive Summary. They do not determine CVSS, KEV status, exploitation status, compliance conclusions or remediation actions.

- Reuters Cybersecurity
- SecurityWeek
- BleepingComputer
- The Record
- The Hacker News
- Cybersecurity Dive
- Cyber Security News
- Dark Reading
- BankInfoSecurity
- SC World
- Industrial Cyber

## Relevance profile

Relevant Cyber News is scored against the following priorities.

### Technology

- Microsoft Azure
- Entra ID
- Microsoft 365
- Defender
- Sentinel
- Active Directory
- Fortinet products
- HPE and Aruba
- SOC, SIEM, XDR, MDR and EDR
- Cloud and identity security
- Detection engineering and incident response

### Geography

- Norway
- Sweden
- Denmark
- Finland
- Iceland
- Scandinavia
- Nordics
- Europe
- European Union and EEA

### Customer sectors

- Oil and gas
- Offshore
- Energy and utilities
- Critical infrastructure
- OT and industrial environments
- Public sector and municipalities
- Healthcare
- Finance and insurance
- Retail and e-commerce
- Hospitality, hotels and travel
- Property, housing and construction
- Transport, rail and maritime
- Research and education
- Managed service providers
- Telecom and hosting providers

### High-impact modifiers

Extra relevance weight is applied to:

- Zero-days
- Active exploitation
- Ransomware
- Major breaches
- Supply-chain compromise
- Nation-state activity
- Remote code execution
- Authentication bypass

The Executive Summary defaults to a maximum of ten relevant cyber-news links and enforces per-publisher limits.

## SOC and Detection Engineering

The pipeline creates deterministic detection opportunities from the collected primary intelligence.

Current templates cover:

- Identity and token abuse
- Active exploitation
- Critical vulnerabilities
- Ransomware
- Cloud control-plane activity
- Software supply-chain compromise
- Nation-state activity
- OT and ICS behaviour
- General threat hunting

Each detection opportunity contains:

- Supporting development
- Suggested detection focus
- Recommended telemetry
- MITRE ATT&CK mapping
- Link to the supporting source

These are starting points for validation, not production-ready detection rules.

## Sector and Customer Impact

The Executive Summary produces up to five sector-impact statements based on the collected stories.

Supported sectors:

- Oil, Gas and Energy
- Retail and E-commerce
- Hospitality and Travel
- Public Sector and Municipalities
- Healthcare
- Finance and Insurance
- Research and Education
- Transport and Maritime
- Property, Housing and Construction
- Managed Services, Telecom and Hosting

## Compliance and standards monitoring

The report monitors:

- NSM updates
- Sikkerhetsloven
- NIS2
- DORA
- GDPR
- PCI DSS
- ISO/IEC 27001
- ISO 50001
- ISO 9001
- ISO 14001
- ISO/IEC 33000 series
- NIST CSF, RMF and SP 800 publications
- Certification and transition deadlines
- Governance, risk, audit and assurance developments

## Upcoming governance register

The file below stores confirmed effective dates or deadlines announced outside the normal 36/72-hour reporting window:

```text
config/upcoming_governance.json
```

Example:

```json
{
  "events": [
    {
      "enabled": true,
      "date": "2026-08-02",
      "title": "Confirmed regulatory milestone",
      "topic": "Applicable regulation",
      "source": "Official authority",
      "source_url": "https://official-source.example",
      "notes": "Practical effect and affected organisations."
    }
  ]
}
```

Only enabled events occurring today or within the configured 14-day horizon are included.

## Repository structure

```text
.
├── .github/
│   └── workflows/
│       ├── daily-security-brief.yml
│       └── test-security-brief.yml
├── config/
│   └── upcoming_governance.json
├── src/
│   └── send_combined_brief.py
├── CHANGELOG.md
├── README.md
├── VERSION
└── requirements.txt
```

## Requirements

- A private or public GitHub repository
- GitHub Actions enabled
- Python 3.12
- A Gmail account with two-step verification
- A Gmail App Password
- Optional free NVD API key

Python dependencies:

```text
beautifulsoup4
feedparser
python-dateutil
requests
```

## GitHub secrets

Create the following under:

```text
Settings → Secrets and variables → Actions
```

Required:

| Secret | Value |
|---|---|
| `GMAIL_USERNAME` | Full Gmail sender address |
| `GMAIL_APP_PASSWORD` | Gmail App Password |
| `EMAIL_TO` | Destination email address |

Optional:

| Secret | Purpose |
|---|---|
| `NVD_API_KEY` | Faster NVD enrichment and higher practical request capacity |

Do not store secret values in source files, workflow files or the README.

## Installation

1. Copy the v4.0 files into the repository.
2. Commit them to the default branch, normally `main`.
3. Confirm the three required GitHub secrets exist.
4. Optionally add `NVD_API_KEY`.
5. Disable previous scheduled briefing workflows.
6. Run the test workflow manually.
7. Leave only the v4.0 production workflow enabled for scheduled delivery.

Suggested commit message:

```text
Release Daily CISO Security Briefing v4.0
```

## Manual test

Open:

```text
Actions → Test Daily CISO Security Briefing v4.0 → Run workflow
```

Recommended first test:

```text
lookback_hours: 72
kev_lookback_days: 3
max_items: 50
executive_news_max: 10
```

The wider test window is intended to populate more sections. Production uses the automatic 36/72-hour logic.

## Automatic schedule

The production workflow runs daily at:

```text
07:07 Europe/Oslo
```

The Python application determines the reporting window:

```text
Monday: 72 hours
Tuesday–Sunday: 36 hours
```

The workflow can still be run manually through `workflow_dispatch`.

## Environment variables

| Variable | Default | Purpose |
|---|---:|---|
| `NEWS_LOOKBACK_HOURS` | `auto` | Uses 72 hours Monday and 36 hours otherwise |
| `KEV_LOOKBACK_DAYS` | `auto` | Derives the KEV window from the news window |
| `NEWS_MAX_ITEMS` | `40` | Maximum primary developments |
| `EXEC_NEWS_MAX_ITEMS` | `10` | Maximum relevant secondary-news links |
| `EXEC_NEWS_MIN_SCORE` | `24` | Minimum relevance score |
| `UPCOMING_GOVERNANCE_DAYS` | `14` | Future compliance and standards horizon |
| `NVD_MAX_CVES` | Key-dependent | Maximum individual NVD enrichment requests |
| `UPCOMING_GOVERNANCE_FILE` | `config/upcoming_governance.json` | Governance register location |

## Source Coverage

Source Coverage differentiates between:

- **Checked with findings:** source returned qualifying items.
- **Checked without findings:** source worked but had no relevant item inside the reporting window.
- **Failed:** source could not be downloaded or parsed.

Successful zero-result sources are collapsed into one summary line. Failures remain visible with error details.

## Security considerations

- Use a dedicated Gmail account for automated sending.
- Store credentials only in GitHub Actions secrets.
- Keep workflow permissions at `contents: read`.
- Review external-source HTML selectors when a source repeatedly returns no candidates.
- Treat all downloaded content as untrusted input.
- Do not execute downloaded content.
- Use the optional NVD API key only through repository secrets.
- Pin GitHub Actions to full commit hashes if stricter supply-chain control is required.
- Add dependency scanning, Dependabot and `pip-audit` for ongoing maintenance.

## Known limitations

- The pipeline does not use an LLM and therefore cannot perform deep semantic analysis.
- “Why it matters”, actions and detection guidance use deterministic templates.
- HTML-based sources may change layouts.
- Some pages are dynamically rendered and may return no parsable content.
- Secondary publications may repeat the same underlying story.
- Deduplication is title-, CVE- and URL-based rather than semantic.
- There is not yet persistent state across runs, so a story can repeat while it remains inside the reporting window.
- The upcoming governance register requires manual maintenance for events announced well before their effective dates.
- Source availability and robots or access controls can change.

## Maintenance priorities after v4.0

1. Add persistent state and cross-run deduplication.
2. Move source definitions and relevance rules into configuration files.
3. Add automated parser-health tests.
4. Add structured CERT-EU, Nkom and Nordic CERT sources where stable feeds are available.
5. Add report archiving without introducing paid infrastructure.
6. Pin dependencies with hashes and generate a machine-readable CycloneDX or SPDX SBOM.

## Licence and ownership

Add the repository licence and copyright notice appropriate for the owner.

For private proprietary use, a simple repository notice can state:

```text
Copyright © 2026 John-Helge Gantz. All rights reserved.
```
