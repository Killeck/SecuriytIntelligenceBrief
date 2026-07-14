# Changelog

All notable changes to the **Daily CISO Security Briefing** are documented in
this file.

The project was developed through a series of working milestones before the
current working version. Versions before 4.0 below are reconstructed from those
milestones and repository changes; they were not all published as formal
releases.

## 4.1 - 2026-07-14

### Summary
Shifting focus, this has been the intent the whole way, however getting the basics in place was essential. The shift now transitions from CISO to Security advisory and Dark Web, without loosing the holistic data collection value and holistic security oversight. Renamed the project to **Daily Security Brief** and shifte the Executive Summary toward Security Advisory and dark-web exposure intelligence wihtout removing the broad CISOintelligence model established from 2.0 to 4.0. 

### Added/Changed

Security advisory and exposure layer

- Added an independent Security Advisory Level based on:
  - Verified or reported credential exposure.
  - Stealer-log and infostealer developments.
  - Ransomware and extortion reporting.
  - Data breaches and leaks.
  - Initial-access broker and cybercrime-market activity.
  - Brand impersonation and phishing infrastructure.
- Added exposure signal confidence labels:
  - Verified.
  - Domain ownership verified.
  - Primary or research source.
  - Secondary reporting.
  - Unverified dataset.
- Added exposure-focused Executive Summary elements:
  - Dark Web and Exposure Highlights.
  - Ransomware and Extortion Watch.
  - Credential and Stealer Exposure.
  - Customer and Sector Advisory Impact.
  - Recommended Security Advisory Actions.
- Added detailed exposure sections:
  - Ransomware and Extortion.
  - Credential Exposure and Stealer Logs.
  - Data Breaches and Leaks.
  - Initial Access and Cybercrime Markets.
  - Brand, Impersonation and Phishing.
  - Dark Web and Criminal Ecosystem.
- Added public Have I Been Pwned breach-catalogue monitoring.
- Added optional HIBP verified-domain monitoring through:
  - `HIBP_API_KEY`.
  - `MONITORED_DOMAINS`.
- Added optional relevance monitoring through:
  - `MONITORED_BRANDS`.
  - `MONITORED_DOMAINS`.
- Added FBI Cyber News for public law-enforcement and criminal-ecosystem
  reporting.
- Added privacy-preserving HIBP domain reporting that excludes individual email
  aliases from the briefing.

#### Retained CISO intelligence

### Changed

- Renamed the product from `Daily CISO Security Briefing` to
  `Daily Security Brief`.
- Changed the version from 4.0 to 4.1.
- Changed the executive emphasis from board-level CISO reporting alone to a
  combined customer-facing Security Advisory and CISO intelligence view.
- Changed the email subject to include:
  - Security Advisory Level.
  - Enterprise DEFCON-style Cyber Threat Level.
  - Product name and version.
- Changed workflow names to:
  - `Daily Security Brief v4.1`.
- Renamed workflow files to:
  - `.github/workflows/daily-security-brief.yml`.
- Renamed the Python entry point to:
  `src/send_security_advisory.py`.

### Security and handling

- Documented that the pipeline does not connect to:
  - Onion services.
  - Criminal forums.
  - Ransomware leak sites.
  - Stolen-data repositories.
  - Illicit marketplaces.
- Added a handling note requiring ransomware and dark-web victim claims to be
  treated as reported intelligence until corroborated.
- Added guidance not to download stolen data or contact threat actors.
- Added guidance to restrict exposure reports to authorised advisory,
  incident-response and customer teams.

### Known limitations

- Public reporting does not provide full direct dark-web visibility.
- HIBP domain monitoring requires an HIBP subscription and verified domain
  ownership.
- Exposure classification remains deterministic rather than LLM-based.
- Brand monitoring is textual and does not yet include certificate
  transparency, DNS or visual-logo similarity checks.

---

## 4.0 - 2026-07-14

### Added

- Added a versioned report title and email subject: "Daily CISO Security Briefing v4.0"
- Relevant Cyber News expanded with Reuters Cybersecurity, SecurityWeek, BleepingComputer, The Record, Dark Reading, BankInfoSecuriyt, SC World and Indstrial Cyber
- Per-publisher headline limits
- Sector an dCustomer Impact in the Exectuive summary
- SOC and Detection Engineering section
- Deterministic detection opportunities with telemetry and MITRE ATT&CK
- OT, Energy and Oil & Gas Section
- CISA ICS, Dragos, Claroty Team82 and Nozomi Networks Labs coverage
- The DFIR Report, SigmaHQ, Elastic Security Labs and Splunk Security Blog
- Scandinavia and Europe Sections
- Renamed Microsoft, Azure and Identity Section
- Versioned report Title and email subject
- Production and manual test workflows
- Consolidated README

### Retained
- DEFCON-style colour-coded threat level
- Automatic 36-hour and Mondya 72-hour reporting windows
- Zero-day and CVSS 10.0 Executive Summary Priority
- CISA KEV and NVD enrichment
- Compliance, Standards and GRC sections
- Fourteen-day governance Horizon
- Bordered report cards and horizontal separators
- Quiet handling of successful zero-result sources
- Non-fatal source collection failures
- Gmail SMTP delivery

---
## 3.0.0 — Relevant Cyber News milestone

### Summary

Added a compact secondary-news discovery layer to the Executive Summary while
keeping authoritative sources responsible for vulnerability status, compliance
conclusions and remediation guidance.

### Added

- Added a Relevant Cyber News block.
- Added initial secondary sources:
  - Cyber Security News.
  - The Hacker News.
  - Cybersecurity Dive.
- Added one-line, linked headlines instead of full cards.
- Added relevance scoring for:
  - Azure and Microsoft.
  - Fortinet.
  - HPE and Aruba.
  - SOC and security operations.
  - Identity.
  - Cloud.
  - Nordics.
  - Europe.
  - Energy, oil and gas.
  - Public and regulated sectors.
  - Retail, hospitality and property.
  - Service providers.
- Added high-impact scoring modifiers for:
  - Zero-day.
  - Active exploitation.
  - Ransomware.
  - Major breaches.
  - Supply-chain compromise.
  - Nation-state activity.
- Added near-duplicate headline detection.
- Added deduplication against primary-source report items.

### Changed

- Kept secondary publications out of risk-rating and remediation decisions.
- Limited the initial block to eight links.
- Limited each publisher to four links.

### Security

- Added an explicit discovery-only trust model for secondary publications.

---

## 2.3.0 — Quiet reporting milestone

### Summary

Reduced noise from empty sections and successful sources with no qualifying
content.

### Added

- Added compact zero-result source reporting.
- Added a single summary line for all successfully checked sources with no
  qualifying updates.

### Changed

- Suppressed empty detailed report sections.
- Shortened Executive Summary empty-state messages.
- Kept failed sources visible with full error information.
- Retained sources with actual findings in Source Coverage.

### Fixed

- Prevented reports from being dominated by repeated
  `No qualifying updates` messages.

---

## 2.2.0 — Visual card restoration and reliability fixes

### Added

- Restored bordered cards around each vulnerability and intelligence item.
- Retained rounded corners, padding and white background.
- Retained horizontal separators between cards.

### Fixed

- Restored the missing `math` import required by automatic KEV window
  calculation.
- Rebuilt the Step 8 package after the inherited import defect.
- Syntax-validated the corrected Python file before packaging.

---

## 2.1.0 — Source hardening milestone

### Summary

Improved the reliability and transparency of source collection after several
feeds returned misleading zero-result states or hard failures.

### Added

- Added Source Coverage diagnostics.
- Added separate source states for:
  - Successful collection with findings.
  - Successful collection without qualifying findings.
  - Failed source.
- Added NVD recent-CVE fallback coverage for:
  - Fortinet.
  - HPE and Aruba.
  - Microsoft Azure.
  - Entra ID.
  - Microsoft 365.
  - AWS.
  - Okta.
  - Google Cloud.
  - Kubernetes.
  - Cisco.
  - Palo Alto Networks.
  - Apple.
  - CrowdStrike.
- Added Google Security Blog alongside Google Project Zero.
- Added source-capacity reservation so lower-scored Compliance, Standards and
  GRC items were less likely to be displaced.

### Changed

- Removed the timeout-prone HPE Networking advisory page.
- Removed blocked Regjeringen.no search-result adapters.
- Removed restrictive NSM summary keyword filtering.
- Used:
  - NSM Updates.
  - NSM Security Warnings.
  - ENISA.
  - The local governance register.
  as the more dependable Norwegian and EEA governance coverage path.

### Fixed

- Fixed `KeyError: 'Standards and frameworks'`.
- Rebuilt the `WHY` and `ACTIONS` mappings.
- Added safe fallback lookups so an unknown category could not terminate a
  source.
- Fixed misleading `Checked` statuses that previously only proved the request
  had not thrown an exception.

### Known limitations

- HPE's support portal remained difficult to parse reliably.
- Regjeringen.no search pages rejected GitHub-hosted automated requests with
  HTTP 403.
- Zero results could still be legitimate when a source had published nothing
  during the 36/72-hour window.

---

## 2.0.0 — DEFCON and governance milestone

### Summary

Introduced risk-level presentation, automatic reporting windows, NVD CVSS
enrichment and forward-looking compliance and standards tracking.

### Added

#### DEFCON-style threat level

- Added a combined numeric, text and colour threat level:
  - DEFCON 1 — Critical — Red.
  - DEFCON 2 — High — Orange.
  - DEFCON 3 — Elevated — Amber.
  - DEFCON 4 — Guarded — Blue.
  - DEFCON 5 — Low — Green.
- Added the DEFCON value to the email subject.
- Documented that this was an internal cyber-risk scale, not the official
  military DEFCON status.

#### Automatic reporting windows

- Added Europe/Oslo local-time awareness.
- Added automatic windows:
  - Monday: previous 72 hours.
  - Tuesday through Sunday: previous 36 hours.
- Added automatic KEV lookback calculation based on the reporting window.

#### NVD enrichment

- Added NVD CVE API enrichment.
- Added:
  - CVSS score.
  - CVSS severity.
  - CVSS vector.
- Added priority escalation for:
  - CVSS 10.0.
  - CVSS 9.0 and above.
  - CVSS 8.0 and above.
- Added optional `NVD_API_KEY`.
- Added slower rate-limited operation without an NVD API key.

#### Executive Summary

- Added explicit Zero-Day and CVSS 10.0 reporting.
- Added major Compliance, Standards and GRC changes.
- Added Going Live Today or Within 14 Days.
- Ensured zero-day, CVSS 10.0 and KEV items were retained despite item limits.

#### Governance horizon

- Added `config/upcoming_governance.json`.
- Added support for manually maintained:
  - Effective dates.
  - Enforcement dates.
  - Deadlines.
  - Standards transitions.
  - Regulatory milestones.
- Added automatic detection of phrases such as:
  - `enters into force`.
  - `applies from`.
  - `deadline`.
  - `transition period`.
  - `trer i kraft`.
  - `gjelder fra`.
  - `frist`.
- Added monitoring topics:
  - NSM updates.
  - Sikkerhetsloven.
  - NIS2.
  - ISO/IEC 27001.
  - ISO 50001.
  - ISO 9001.
  - ISO 14001.
  - ISO/IEC 33000 series.

### Changed

- Changed the report title to include the governance horizon.
- Changed the item display to include zero-day status and CVSS data.
- Changed the final item selection to prioritise critical items.

### Fixed

- Added the missing `math` dependency after automatic KEV lookback introduced
  `math.ceil`.
- Corrected rendering issues introduced while replacing the report function.

---

## 1.1.0 — Vendor, compliance and GRC expansion

### Summary

Expanded the combined report beyond general vendor news and introduced
dedicated enterprise vendor and governance sections.

### Added

- Added a dedicated Fortinet section.
- Added:
  - Fortinet PSIRT.
  - FortiGuard Labs Threat Research.
- Added a dedicated HPE section.
- Added:
  - HPE Security Bulletin Library.
  - HPE Networking Security Advisories.
- Added dedicated:
  - Compliance.
  - Standards.
  - GRC.
- Added governance sources:
  - ENISA News.
  - NIST CSRC News.
  - PCI Security Standards Council.
  - ISACA News and Trends.
  - ISO News.
  - NSM Updates.
  - NSM Security Warnings.
- Added keyword classification for:
  - Regulatory and compliance.
  - Standards and frameworks.
  - Governance, risk and assurance.
- Added full-width horizontal separators below each item.
- Configured all report sections to appear, including empty-section messages.

### Changed

- Moved Microsoft into a dedicated report section.
- Routed Fortinet and HPE items into dedicated sections.
- Increased the test item allowance to support the larger section set.

### Known limitations

- HPE support pages could be dynamically rendered.
- Some governance sources could legitimately produce no updates inside the
  reporting window.
- HTML source layout changes could require selector maintenance.

---

## 1.0.0 — Combined briefing milestone

### Summary

Merged the CISA KEV report and general security-news collector into one
structured daily CISO briefing.

### Added

- Added one combined email instead of separate KEV and news emails.
- Added the following sections:
  - Executive Summary.
  - Immediate Actions.
  - Known Exploited Vulnerabilities.
  - Vendor Advisories.
  - Cloud and Identity.
  - Threat Intelligence.
  - Vulnerability Research.
  - Nordic Impact.
  - CISO Watch List.
  - Source Warnings.
- Added source isolation so one failed source did not stop the report.
- Added source grouping.
- Added item scoring and report prioritisation.
- Added CISA KEV records to the same report as vendor and threat news.
- Added:
  - Cisco Talos.
  - Fortinet PSIRT.
  - Apple Security Releases.
  - Okta Security.
  - NSM Security Warnings.

### Changed

- Replaced the unreliable Cisco Talos Blogger RSS endpoint with an HTML
  collector against the official Talos blog index.
- Changed CISA KEV from a standalone report to an integrated section.
- Increased the default test window to seven days to validate populated
  sections.

### Known limitations

- No persistent state.
- No CVSS enrichment.
- No MITRE ATT&CK generation.
- Deterministic summaries and actions.
- Some vendor pages depended on HTML scraping.

---

## 0.3.0 — General security-news collector

### Summary

Added non-CVE intelligence and threat-research sources after the KEV-only
report proved too narrow.

### Added

- Added initial primary and research sources:
  - Microsoft Security Blog.
  - AWS Security Blog.
  - Palo Alto Networks Unit 42.
  - Cisco Talos.
  - Google Project Zero.
- Added categories:
  - Active exploitation.
  - Ransomware.
  - Nation-state activity.
  - Identity security.
  - Supply-chain security.
  - Cloud security.
  - Threat intelligence.
- Added:
  - Overall threat level.
  - Top five developments.
  - Article priority.
  - Source-provided summary.
  - Why it matters.
  - Who is affected.
  - Recommended action.
  - CVE extraction.
  - Primary-source link.
- Added marketing suppression.
- Added source failure warnings without terminating the report.
- Added URL and title deduplication.
- Added HTML email output.

### Changed

- Used a 72-hour manual test window to increase the chance of populated output.
- Kept this collector separate from the KEV email during validation.

### Known limitations

- Did not fetch or analyse complete articles.
- Used publisher summaries.
- Did not include CVSS enrichment.
- Did not maintain persistent state.

---

## 0.2.0 — CISA KEV collector

### Summary

Added the first real security-intelligence source after Gmail transport was
validated.

### Added

- Added CISA Known Exploited Vulnerabilities JSON catalogue collection.
- Added configurable KEV lookback days.
- Added plain-text and HTML reports.
- Added for each KEV entry:
  - CVE.
  - Vendor.
  - Product.
  - Vulnerability name.
  - Date added.
  - CISA remediation deadline.
  - Known ransomware usage.
  - Description.
  - Required action.
  - NVD link.
  - CISA catalogue link.
- Added a manual GitHub Actions test workflow.
- Added source structure and validation.
- Used only the Python standard library for the initial KEV collector.

### Changed

- Used a 30-day test lookback to guarantee useful validation content.
- Reduced the intended production window to one or two days after testing.

### Known limitations

- Repeatedly sent the same KEV entries within the configured lookback.
- Did not yet maintain a state file.
- Covered only KEV-linked developments.
- Did not include broader vendor, ransomware, nation-state or compliance news.

---

## 0.1.0 — Gmail transport proof of concept

### Summary

Established the basic GitHub Actions and Gmail SMTP delivery path.

### Added

- Added a private GitHub repository structure.
- Added a Python SMTP test sender.
- Added Gmail STARTTLS delivery through:
  - `smtp.gmail.com`.
  - Port 587.
- Added GitHub Actions repository secrets:
  - `GMAIL_USERNAME`.
  - `GMAIL_APP_PASSWORD`.
  - `EMAIL_TO`.
- Added a manual GitHub Actions workflow.
- Added required environment-variable validation.
- Added SMTP authentication and transport error handling.
- Added a plain-text test email.

### Changed

- Updated GitHub Actions references from the incorrect singular namespace:
  - `action/checkout`.
  - `action/setup-python`.
  to:
  - `actions/checkout`.
  - `actions/setup-python`.
- Updated Actions versions to Node.js 24-compatible releases:
  - `actions/checkout@v7`.
  - `actions/setup-python@v6`.

### Fixed

- Fixed repository-not-found errors caused by the incorrect action namespace.
- Distinguished Node.js deprecation warnings from actual Python failures.
- Fixed Gmail authentication configuration using a Gmail App Password.
- Confirmed successful delivery from GitHub Actions through Gmail.

### Security

- Kept Gmail credentials in GitHub Actions secrets.
- Avoided storing secrets in the repository.
- Recommended a dedicated Gmail account for automation.
- Restricted initial workflow permissions to read-only repository contents.

---

## Pre-project design decision

Before implementation, the following architecture was selected:

```text
Official advisories, vendor feeds and selected news sources
                            ↓
                     Python collector
                            ↓
              Normalisation and deduplication
                            ↓
             Deterministic relevance scoring
                            ↓
                  HTML and text rendering
                            ↓
                       Gmail SMTP
                            ↓
                   Daily email briefing
```

The project deliberately avoided:

- Azure resources.
- Paid hosting.
- Paid databases.
- Paid LLM services.
- Persistent servers.
- Complex workflow platforms.

GitHub Actions, Python, public feeds and an existing Gmail account were chosen
to keep the operating cost effectively zero within normal GitHub usage limits.
