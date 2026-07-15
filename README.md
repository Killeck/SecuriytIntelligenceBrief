# Daily Security Brief


A Python and GitHub Actions cybersecurity intelligence pipeline for Security
Advisors, Technical Account Managers, SOC advisory functions, CISOs and
customer-facing security teams.

Version 4.3 retains the broad CISO intelligence coverage introduced in v4.0,
including critical vulnerabilities, active exploitation, Microsoft, Fortinet,
HPE and Aruba, cloud and identity, SOC detection, OT and energy, Scandinavia,
compliance, standards and GRC.

The executive layer is refocused toward actionable Security Advisory and
external-exposure intelligence:

- Dark-web and criminal-ecosystem developments
- Ransomware and extortion activity
- Credential exposure and stealer logs
- Data breaches and leaks
- Initial-access brokers and cybercrime services
- Brand impersonation and phishing infrastructure
- Customer, supplier and sector exposure
- Priority vulnerability and vendor advisories
- SOC detection and response opportunities

The report presents two related levels:

- **Security Advisory Level:** immediate exposure and customer-advisory impact.
- **Enterprise Cyber Threat Level:** the retained DEFCON-style CISO view based
  on exploitation, ransomware, nation-state and vulnerability intelligence.

The pipeline uses public and authorised sources. It does **not** connect to
onion services, criminal forums, ransomware leak sites, stolen-data
repositories or illicit marketplaces.


## Version 5.0 email layout

Version 5.0 replaces the long-form HTML email with a compact, dark,
dashboard-style daily digest.

The email now begins with:

- Six headline metrics
- Executive TL;DR
- Critical vulnerability table
- Active exploitation and actor activity
- Dark-web and exposure cards
- Vendor mini-cards
- Standards, compliance and governance cards
- Recommended actions for the day

Long paragraphs are converted into one-line summaries, status pills and
short action statements. Full technical and CISO coverage remains available
below the dashboard in compact sections.

The renderer uses nested HTML tables and inline CSS for compatibility with
Gmail, Outlook and other restrictive email clients. No JavaScript, external
stylesheet or hosted dashboard is required.

## Core behaviour

- Runs automatically at **07:07 Europe/Oslo**.
- Uses the previous **72 hours on Mondays**.
- Uses the previous **36 hours Tuesday through Sunday**.
- Emails a formatted HTML and plain-text advisory through Gmail SMTP.
- Uses no LLM and no paid cloud infrastructure.
- Continues when individual sources fail.
- Suppresses empty report sections.
- Collapses successful zero-result sources into one quiet summary line.
- Keeps failed sources visible in Source Coverage and Source Warnings.
- Labels exposure claims by confidence rather than presenting all claims as
  confirmed incidents.

## Report structure

### Executive Security Advisory Overview

1. Security Advisory Level
2. Enterprise Cyber Threat Level
3. Priority Security Advisories
4. Dark Web and Exposure Highlights
5. Ransomware and Extortion Watch
6. Credential and Stealer Exposure
7. Relevant Cyber News
8. Zero-Day and CVSS 10.0
9. Customer and Sector Advisory Impact
10. Recommended Security Advisory Actions
11. Relevant Compliance and Governance Changes
12. Going Live Today or Within 14 Days

### Exposure intelligence sections

1. Ransomware and Extortion
2. Credential Exposure and Stealer Logs
3. Data Breaches and Leaks
4. Initial Access and Cybercrime Markets
5. Brand, Impersonation and Phishing
6. Dark Web and Criminal Ecosystem

### Technical and advisory sections

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
17. Source Coverage
18. Security Advisory and CISO Watch List

Empty sections are not displayed.

## Confidence model

Exposure signals are explicitly labelled.

| Label | Meaning |
|---|---|
| `Verified` | HIBP marks the breach dataset as verified |
| `Domain ownership verified` | Results were retrieved through an HIBP domain search after domain control was verified |
| `Primary or research source` | Reported by a vendor, government body, recognised research organisation or technical source |
| `Secondary reporting` | Reported by a news publication and not independently confirmed by this pipeline |
| `Unverified dataset` | HIBP lists the breach but does not mark it as verified |

A ransomware victim claim or dark-web reference is not treated as a confirmed
incident unless corroborated by the affected organisation, law enforcement or
another reliable source.

## Dark-web and exposure sources

### Have I Been Pwned public breach metadata

The pipeline queries the public HIBP breach catalogue and includes breach
records added inside the reporting window.

It extracts:

- Breach title and domain
- Date added
- Original breach date where available
- Verification status
- Account count
- Exposed data classes
- Malware or stealer-log classification
- Recommended security-advisory actions

Spam lists and retired breaches are excluded.

### Optional HIBP verified-domain monitoring

Organisation-specific domain monitoring is optional.

Configure:

```text
HIBP_API_KEY
MONITORED_DOMAINS
```

`MONITORED_DOMAINS` is a comma-separated list:

```text
example.com,example.org
```

The HIBP domain endpoint requires:

- An HIBP subscription key
- Verification that the subscriber controls the domain

The report deliberately does not include exposed email aliases. It reports
only:

- Number of affected aliases
- Number and names of associated breach datasets
- Domain-level response recommendations

Leave `HIBP_API_KEY` and `MONITORED_DOMAINS` unset to retain a zero-cost
deployment using public breach metadata only.

### Open-source criminal-ecosystem intelligence

Exposure signals are also derived from the existing primary and secondary
sources using deterministic keyword and relevance rules.

The pipeline looks for:

- Ransomware victim claims
- Extortion activity
- Data offered for sale
- Credential dumps
- Stealer logs
- Initial-access brokers
- Cybercrime forums and markets
- Malware-, ransomware- and phishing-as-a-service
- Bulletproof hosting
- Brand impersonation
- Typosquatting
- Adversary-in-the-middle phishing
- Criminal infrastructure disruption
- Sanctions and law-enforcement activity

### FBI Cyber News

FBI cybercrime news and press releases are filtered for:

- Ransomware
- Stolen access
- Infostealers
- Cybercrime markets
- Extortion
- Phishing
- Botnets
- Criminal-service disruption
- Sanctions and takedowns

## Optional monitored references

The report can increase the relevance of stories that mention selected
organisations, products or domains.

Configure comma-separated GitHub secrets:

```text
MONITORED_BRANDS
MONITORED_DOMAINS
```

Example:

```text
MONITORED_BRANDS=NetNordic,Customer Name,Important Supplier
MONITORED_DOMAINS=netnordic.com,customer.example
```

These values are included in the emailed advisory when a match is configured.
Use GitHub secrets rather than repository variables when customer names or
domains should not be visible to every repository collaborator.

## Security advisory level

The report uses a five-level advisory scale:

| Level | Meaning |
|---|---|
| Critical | Immediate material exposure or a critical verified signal |
| High | High-severity exposure, active exploitation or major credential risk |
| Elevated | Relevant ransomware, breach, nation-state or exposure activity |
| Guarded | Relevant developments without immediate confirmed exposure |
| Low | No qualifying developments or exposure signals |

The email subject uses the label rather than the previous DEFCON terminology.

## Source hierarchy

### Authoritative vulnerabilities and exploitation

- CISA Known Exploited Vulnerabilities
- NIST National Vulnerability Database
- Fortinet PSIRT
- HPE Security Bulletin Library
- Apple Security Releases
- CISA ICS Advisories

### Vendor, research and technical intelligence

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
- SigmaHQ
- Dragos
- Claroty Team82
- Nozomi Networks Labs

### Law-enforcement and criminal ecosystem

- FBI Cyber News
- CISA ransomware and cybercrime material found through configured sources
- Relevant official sanctions and disruption reporting discovered through
  Reuters, The Record and other selected publications

### Compliance, standards and governance

- ENISA
- NIST CSRC
- PCI Security Standards Council
- ISACA
- ISO News
- NSM Updates
- NSM Security Warnings
- Local upcoming-governance register

### Secondary discovery

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

Secondary discovery sources do not determine CVSS, KEV status, breach
verification or remediation priority on their own.

## Customer and sector relevance

The report continues to prioritise:

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

## Optimised architecture

Version 4.3 retains the modular package introduced in v4.2 and replaces the previous long-form HTML presentation with a compact dashboard renderer. The command used by GitHub Actions remains unchanged:

```text
python src/send_security_advisory.py
```

The entry point now delegates to focused modules:

- `app.py` — runtime settings, orchestration and bounded parallel collection.
- `collectors.py` — RSS, HTML, HIBP, CISA KEV and NVD adapters.
- `http_client.py` — thread-local connection pooling and transient-failure
  retries.
- `analysis.py` — classification, prioritisation, exposure and sector logic.
- `rendering.py` — shared report context plus separate plain-text and HTML renderers.
- `governance.py` — future compliance and standards milestones.
- `sources.py` — configured intelligence sources.
- `rules.py` — deterministic scoring and classification rules.
- `models.py` — shared data contracts.
- `delivery.py` — Gmail SMTP delivery.

Independent sources are fetched concurrently using a bounded worker pool. The
default is eight workers, configurable through `SOURCE_WORKERS`. Source
Coverage remains in its configured order even though requests execute in
parallel.

The HTTP layer creates one reusable session per worker thread, reducing repeated
TLS and connection setup. Transient HTTP 429 and 5xx responses receive bounded
retries with backoff and `Retry-After` support.

The previous report output was regression-compared against the modular
implementation using deterministic fixtures. Offline unit tests now run in both
GitHub Actions workflows before email delivery.

See `OPTIMISATION.md` for the detailed before-and-after design notes.

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
│   ├── security_brief/
│   │   ├── __init__.py
│   │   ├── analysis.py
│   │   ├── app.py
│   │   ├── collectors.py
│   │   ├── config.py
│   │   ├── delivery.py
│   │   ├── governance.py
│   │   ├── http_client.py
│   │   ├── models.py
│   │   ├── rendering.py
│   │   ├── rules.py
│   │   ├── sources.py
│   │   └── utils.py
│   └── send_security_advisory.py
├── tests/
│   └── test_smoke.py
├── CHANGELOG.md
├── OPTIMISATION.md
├── README.md
├── VERSION
└── requirements.txt
```

## Required GitHub secrets

Create under:

```text
Settings → Secrets and variables → Actions
```

| Secret | Required | Purpose |
|---|---|---|
| `GMAIL_USERNAME` | Yes | Gmail sender address |
| `GMAIL_APP_PASSWORD` | Yes | Gmail App Password |
| `EMAIL_TO` | Yes | Advisory recipient |
| `NVD_API_KEY` | No | Faster NVD enrichment |
| `HIBP_API_KEY` | No | Verified-domain HIBP monitoring |
| `MONITORED_DOMAINS` | No | Comma-separated customer or organisation domains |
| `MONITORED_BRANDS` | No | Comma-separated organisation or brand names |

Do not store these values in source files or workflow files.

## Installation

1. Copy the v4.3 repository files into the project.
2. Remove or disable the previous v4.0 workflows.
3. Confirm the three required Gmail secrets.
4. Add optional NVD and HIBP secrets where applicable.
5. Add monitored brands and domains only when required.
6. Commit to the default branch.
7. Run the test workflow.
8. Leave only the v4.3 production workflow enabled for scheduled delivery.

Suggested commit:

```text
Release Daily Security Brief v4.3
```

## Manual test

Open:

```text
Actions → Test Daily Security Brief v4.3
```

Recommended initial values:

```text
lookback_hours: 72
kev_lookback_days: 3
max_items: 50
discovery_max: 12
exposure_max: 25
```

The wider test window is intended to populate more exposure and technical
sections.

## Offline regression tests

Run the deterministic test suite without sending email:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The tests cover source failure isolation, ordered Source Coverage, public HIBP
mapping, exposure classification and the retained Security Advisory/CISO report
structure.

## Schedule

The production workflow runs at:

```text
07:07 Europe/Oslo
```

Automatic reporting window:

```text
Monday: 72 hours
Tuesday–Sunday: 36 hours
```

## Environment variables

| Variable | Default | Purpose |
|---|---:|---|
| `NEWS_LOOKBACK_HOURS` | `auto` | Automatic 36/72-hour window |
| `KEV_LOOKBACK_DAYS` | `auto` | KEV collection window |
| `NEWS_MAX_ITEMS` | `40` | Maximum primary advisories |
| `EXEC_NEWS_MAX_ITEMS` | `10` | Maximum discovery links |
| `EXPOSURE_MAX_ITEMS` | `20` | Maximum dark-web and exposure signals |
| `EXEC_NEWS_MIN_SCORE` | `24` | Minimum discovery relevance |
| `UPCOMING_GOVERNANCE_DAYS` | `14` | Governance horizon |
| `SOURCE_WORKERS` | `8` | Parallel source workers, bounded between 1 and 16 |
| `MONITORED_BRANDS` | Empty | Optional monitored organisation names |
| `MONITORED_DOMAINS` | Empty | Optional monitored domains |
| `HIBP_API_KEY` | Empty | Optional HIBP authenticated monitoring |
| `NVD_API_KEY` | Empty | Optional NVD request key |

## Privacy and handling controls

- Do not add personal email addresses to `MONITORED_DOMAINS`.
- Use only organisation-owned domains that the HIBP account is authorised to
  search.
- The report does not display HIBP email aliases.
- Do not forward exposure reports outside the authorised advisory or incident
  team without reviewing their contents.
- Treat dark-web claims as intelligence leads, not proof.
- Confirm exposure before contacting a named organisation or customer.
- Do not access or download stolen data to validate a claim.
- Do not contact threat actors.
- Follow legal, contractual and incident-response requirements.

## Known limitations

- No direct dark-web or onion-site collection.
- No LLM-based semantic analysis.
- Exposure classification uses deterministic rules.
- Ransomware claims may be false, duplicated or delayed.
- HIBP public metadata reflects when a breach was added, not necessarily when
  it occurred.
- HIBP verified-domain monitoring requires a subscription.
- HTML source layouts can change.
- No persistent cross-run state.
- Stories can repeat while they remain inside the reporting window.
- No customer asset inventory or CMDB integration.
- Brand monitoring detects textual references only; it does not perform DNS,
  certificate-transparency or logo-similarity monitoring.

## Contributions

This is a privately maintained proprietary project, External contributions
are not currently accepted.

Access to the repository does not grant permission to copy, modify,
redistribute or reuse the source code or associated materials.

## Licence and Ownership

Copyright © 2026 John-Helge Gantz. All rights reserved.

Daily Security Brief is proprietary software. The source code,
documentation, workflows, report templates and associated materials may not
be copied, modified, distributed, sublicensed or used to create derivative
works without prior written permission from the copyright owner.

Access to this repository does not grant any ownership rights or implied
licence.

See [LICENSE](LICENSE) for the complete terms.
