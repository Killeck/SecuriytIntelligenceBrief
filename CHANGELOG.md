<!--
Copyright © 2026 John-Helge Gantz. All rights reserved.
Proprietary software. See LICENSE.
-->

# Changelog

All notable changes to the **Daily Security Brief** are documented in this
file.

The project was developed through a series of working milestones before the
formal v4.0 release. Versions before 4.0 below are reconstructed from those
milestones and repository changes; they were not all published as formal
releases.

The format broadly follows [Keep a Changelog](https://keepachangelog.com/) and uses semantic-style versioning where practical.

---
## 5.3.0 - 2026-07-16
Security Intelligence Brief v5.3.0 review

## Implemented

- Neutral outbound subject: `Security Intelligence Brief`.
- Weighted threat and advisory levels based on evidence, impact, EPSS, CVSS, KEV and confidence.
- Zero-day references no longer imply confirmed exploitation.
- Generic country references and broad ransomware language no longer automatically escalate the report.
- Critical advisory status requires direct verified exposure or an exceptional corroborated enterprise condition.
- Added standards-compliant Date, Message-ID, Reply-To and automated-message headers.
- Kept the authenticated Gmail or Google Workspace account as the sender.
- Removed clickable Ransomware.live and unverified-claim URLs from email content.
- Reduced Ransomware.live to one discovery result and lowered its selection score.
- Removed the obsolete v5.0 suffix from the manual test workflow.
- Removed already completed cross-reference work from MAINTENANCE.md.
- Fixed a missing `Any` import and avoided BeautifulSoup URL warnings in `clean_text`.

## Deliverability assessment

Post-5.0 filtering changes were:

1. An alarmist subject containing `Critical Advisory` and `DEFCON`.
2. The addition of clickable Ransomware.live URLs in v5.2.
3. Increased security-domain and threat-related link density after the source expansion.
4. Missing explicit Date and Message-ID headers in the locally constructed message.


---
## 5.2.0 - 2026-07-16
Security Intelligence Source Expansion
This update adds the priority intelligence sources and enrichments identified for the Daily Security Brief.

### Added

#### Authoritative and primary intelligence
- Microsoft Security Response Center Security Update Guide API
  - Expands current MSRC releases into one item per CVE.
  - Preserves Microsoft as the authoritative source.
  - Marks active exploitation only when the MSRC threat data explicitly reports it.
- CERT-EU Security Advisories RSS
- Google Threat Intelligence RSS
- Rapid7 Vulnerability Research
- Shadowserver Foundation news and research

#### Vulnerability prioritisation

- FIRST EPSS batch enrichment
  - Queries up to 200 unique CVEs by default.
  - Adds probability and percentile context to `why`.
  - Adjusts prioritisation score without setting `exploited` or `kev`.
  - Configure with `EPSS_MAX_CVES`; accepted range is 1–1000.

#### Ransomware discovery

- Ransomware.live public aggregation API
  - Remains in the secondary discovery and exposure path.
  - Every record is labelled `Unverified claim`.
  - Does not set KEV, CVSS, zero-day or confirmed exploitation state.
  - Uses `RANSOMWARE_LIVE_API_KEY` only when supplied.
  - Does not connect directly to onion services, criminal forums, leak sites or stolen-data repositories.

---
## 5.1.0 - 2026-07-15

### Added
- clickable links fixed by title and anchor_id
- Multi row display for vendors

### Changed
- Calculation error adjustment between Vendor Alerts and Vendor Updates

### Removed
- five-card limit form vendor groups

---
## 5.0.0 — 2026-07-15

### Summary

Promoted the dashboard-style daily email redesign to the first major v5
release and completed the repository ownership, version-management and
governance structure.

### Added

- Proprietary `LICENSE`.
- Repository `NOTICE`.
- `THIRD_PARTY_NOTICES.md`.
- README contribution policy.
- Ownership notice in both HTML and plain-text reports.
- Regression test confirming runtime version consistency.

### Changed

- Made `VERSION` the single source of truth for Python runtime versioning.
- Removed the hard-coded release number from workflow names and README current
  release text.
- Added workflow steps that load `VERSION` into `GITHUB_ENV`.
- Retained explicit historical release numbers in this changelog.
- Classified the compact dashboard redesign as version 5.0.

### Retained

- Modular v4.2 architecture.
- Dashboard email layout.
- Daily GitHub Actions execution.
- Parallel source collection.
- Dark-web and exposure intelligence.
- Full Security Advisory and CISO coverage.

---

## 4.3.0 — 2026-07-15

### Summary

Replaced the long-form HTML presentation with a compact, email-safe dashboard
that follows the Daily Security Brief visual mock-up while retaining the full
v4.2 collection, analysis and CISO intelligence model.

### Added

- Six headline metric cards for:
  - Overall threat level
  - Active exploitation
  - Zero-days
  - Dark-web and exposure signals
  - Vendor alerts
  - Governance changes
- Executive Summary in TL;DR format.
- Critical vulnerability table with severity, vendor, CVE, CVSS, exploit
  status and one-line summary.
- Compact active exploitation and threat-activity rows.
- Dark-web and exposure mini-cards with confidence and action.
- Vendor update mini-cards.
- Standards, compliance and governance mini-cards.
- Recommended Actions Today checklist cards.
- Compact relevant-news and sector-impact panels.
- Email-client-compatible dark theme using nested tables and inline CSS.

### Changed

- Replaced long advisory cards and repeated paragraphs with concise TL;DR rows.
- Kept technical, SOC, OT, regional, compliance, standards and GRC coverage in
  compact detail sections below the dashboard.
- Updated workflow and package version to 4.3.

### Retained

- All v4.2 collectors and source coverage.
- Security Advisory Level and Enterprise DEFCON-style threat level.
- CISA KEV and NVD enrichment.
- Dark-web and HIBP exposure monitoring.
- Daily 07:07 Europe/Oslo delivery.
- Plain-text fallback email.
- Parallel source collection and regression tests.

---

## 4.2.0 — 2026-07-14

### Summary

Refactored the v4.1 monolithic application into a modular, testable package and
reduced practical pipeline runtime through bounded parallel collection,
connection reuse and transient-failure retries. Report content, scoring and
source coverage remain compatible with v4.1.

### Added

- Added the `security_brief` package with focused modules for:
  - Runtime orchestration.
  - Source collection.
  - HTTP connection management.
  - Deterministic analysis.
  - Report rendering.
  - Governance milestones.
  - Data models.
  - Static source configuration.
  - Classification and relevance rules.
  - SMTP delivery.
- Added bounded concurrent collection of independent primary and discovery
  sources.
- Added `SOURCE_WORKERS`, defaulting to eight and bounded between one and
  sixteen.
- Added a thread-local HTTP client with:
  - Connection pooling.
  - Two bounded retries.
  - Backoff.
  - HTTP 429 and transient 5xx handling.
  - `Retry-After` support.
- Added offline `unittest` regression coverage for:
  - Parallel source failure isolation.
  - Stable Source Coverage ordering.
  - HIBP public breach mapping.
  - Exposure classification.
  - Retained Security Advisory and CISO report sections.
- Added an automatic regression-test step to both GitHub Actions workflows.
- Added typed runtime settings, pipeline state and shared report-context containers.
- Added generic fetch-task and fetch-outcome models for consistent source
  health reporting.

### Changed

- Reduced `src/send_security_advisory.py` to a seven-line compatibility entry
  point.
- Replaced repeated source-level `try/except` blocks with one reusable
  collection function.
- Moved static source definitions out of execution logic.
- Moved deterministic scoring and classification rules into a dedicated module.
- Split the previous combined 900-line report renderer into context building,
  plain-text rendering, HTML rendering and a small compatibility wrapper.
- Resolved environment settings once at startup rather than repeatedly during
  orchestration.
- Cached repeated integer and comma-separated environment parsing.
- Deduplicated primary intelligence before NVD enrichment to preserve API
  capacity.
- Kept public exposure intelligence separate from primary advisory scoring.
- Preserved configured source order in Source Coverage while fetching
  concurrently.
- Updated production and test workflow names to v4.2.

### Compatibility

- Retained the existing command:
  `python src/send_security_advisory.py`.
- Retained existing required and optional GitHub secrets.
- Retained report titles, sections, scoring logic, HTML and plain-text output.
- Regression-compared deterministic v4.1 and v4.2 rendering with identical
  fixtures.

### Fixed

- Removed the main 6,000-line maintenance bottleneck.
- Removed repeated TLS and HTTP connection setup for sequential requests made by
  the same worker.
- Centralised source failure formatting and health-record creation.
- Prevented one failed concurrent task from cancelling other source
  collections.

### Known limitations

- The report renderer and large deterministic rule tables remain substantial
  modules by design.
- HTML source adapters still require maintenance when publishers change page
  structure.
- Parallel collection improves elapsed runtime but remains dependent on source
  response times and rate limits.

## 4.1.0 — 2026-07-14

### Summary

Renamed the product to **Daily Security Brief** and shifted the Executive
Summary toward Security Advisory and dark-web exposure intelligence without
removing the broad CISO intelligence model established in v4.0.

### Added

#### Security advisory and exposure layer

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

- Retained the full v4.0 detailed source and report coverage.
- Retained the DEFCON-style Enterprise Cyber Threat Level.
- Displayed both:
  - Security Advisory Level.
  - Enterprise Cyber Threat Level.
- Restored Relevant Cyber News in the Executive Summary.
- Retained:
  - CISA KEV.
  - NVD CVSS enrichment.
  - Zero-day and CVSS 10.0 prioritisation.
  - Microsoft, Azure and Identity.
  - Fortinet.
  - HPE and Aruba.
  - Cloud and supply-chain security.
  - SOC and Detection Engineering.
  - Threat Intelligence.
  - Vulnerability Research.
  - OT, Energy and Oil & Gas.
  - Scandinavia and Europe.
  - Norwegian Security Governance.
  - Compliance.
  - Standards.
  - GRC.
  - Sector and customer impact.
  - Upcoming governance deadlines.
  - Source coverage and diagnostics.
- Renamed the final monitoring section to:
  `Security Advisory and CISO Watch List`.

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
  - `Test Daily Security Brief v4.1`.
- Renamed workflow files to:
  - `.github/workflows/daily-security-brief.yml`.
  - `.github/workflows/test-security-brief.yml`.
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

### Documentation

- Added a module-level architecture and processing-flow description.
- Added docstrings to all 71 top-level classes and functions.
- Added section comments for source adapters, classification rules, exposure
  taxonomies, SOC templates, date parsing and NVD coverage.
- Added targeted inline comments around automatic reporting windows, source
  isolation, scoring, HIBP privacy handling, deduplication, NVD enrichment,
  threat-level calculation, report rendering and email delivery.
- Confirmed that the executable Python AST is unchanged when comments and
  docstrings are excluded.

### Known limitations

- Public reporting does not provide full direct dark-web visibility.
- HIBP domain monitoring requires an HIBP subscription and verified domain
  ownership.
- Exposure classification remains deterministic rather than LLM-based.
- Brand monitoring is textual and does not yet include certificate
  transparency, DNS or visual-logo similarity checks.

## 4.0.0 — 2026-07-14

### Summary

Consolidated the complete briefing pipeline into the first formal, operational
release. Version 4.0 combines authoritative vulnerability intelligence,
vendor and threat-research coverage, executive cyber-news discovery, sector
impact analysis, SOC detection guidance, OT and energy coverage, governance
tracking, automated scheduling and Gmail delivery.

### Added

#### Executive Summary

- Added a versioned report title and email subject:
  `Daily CISO Security Briefing v4.0`.
- Added the following ordered Executive Summary elements:
  - DEFCON-style overall threat level.
  - Top five primary developments.
  - Relevant Cyber News.
  - Zero-Day and CVSS 10.0 summary.
  - Sector and Customer Impact.
  - Compliance, Standards and Governance Changes.
  - Going Live Today or Within 14 Days.
  - Immediate Actions.
- Added a clear disclaimer that secondary-news links are for discovery, while
  vendor, government and standards sources remain authoritative.
- Increased the default Relevant Cyber News allowance to ten links.

#### Relevant Cyber News

- Expanded secondary-source discovery to include:
  - Reuters Cybersecurity.
  - SecurityWeek.
  - BleepingComputer.
  - The Record.
  - The Hacker News.
  - Cybersecurity Dive.
  - Cyber Security News.
  - Dark Reading.
  - BankInfoSecurity.
  - SC World.
  - Industrial Cyber.
- Added per-publisher limits to prevent one source dominating the briefing.
- Added title-similarity deduplication across publishers.
- Added filtering for:
  - Sponsored content.
  - Webinars.
  - Podcasts.
  - Newsletters.
  - Awards.
  - Funding announcements.
  - Buyer guides.
  - Generic tool lists.
  - Weekly recap articles.
- Added relevance scoring for:
  - Azure and Microsoft.
  - Fortinet.
  - HPE and Aruba.
  - SOC, SIEM, MDR, XDR and EDR.
  - Cloud and identity.
  - Scandinavia and Europe.
  - Oil and gas.
  - Energy and critical infrastructure.
  - Public sector.
  - Healthcare.
  - Finance.
  - Retail.
  - Hospitality.
  - Property and housing.
  - Transport and maritime.
  - Research and education.
  - Managed service providers, telecom and hosting.

#### Sector and Customer Impact

- Added deterministic sector-impact statements in the Executive Summary.
- Added support for:
  - Oil, Gas and Energy.
  - Retail and E-commerce.
  - Hospitality and Travel.
  - Public Sector and Municipalities.
  - Healthcare.
  - Finance and Insurance.
  - Research and Education.
  - Transport and Maritime.
  - Property, Housing and Construction.
  - Managed Services, Telecom and Hosting.
- Limited the section to the five most relevant sector impacts.

#### SOC and Detection Engineering

- Added a dedicated SOC and Detection Engineering section.
- Added source coverage from:
  - The DFIR Report.
  - SigmaHQ releases.
  - Elastic Security Labs.
  - Splunk Security Blog.
- Added deterministic detection opportunities for:
  - Identity and token abuse.
  - Active exploitation.
  - Critical vulnerabilities.
  - Ransomware.
  - Cloud control-plane activity.
  - Software supply-chain compromise.
  - Nation-state activity.
  - OT and ICS behaviours.
  - General threat hunting.
- Added suggested:
  - Detection focus.
  - Data sources.
  - MITRE ATT&CK mappings.
  - Supporting source links.
- Retained the requirement that generated guidance is a starting point for
  analyst validation, not a production-ready detection rule.

#### OT, Energy and Oil & Gas

- Added a dedicated OT, Energy and Oil & Gas section.
- Added source coverage from:
  - CISA ICS Advisories.
  - Dragos.
  - Claroty Team82.
  - Nozomi Networks Labs.
  - Industrial Cyber.
- Added relevance weighting for:
  - Offshore environments.
  - Energy systems.
  - Utilities.
  - Pipelines.
  - Industrial control systems.
  - SCADA.
  - OT remote access.
  - Critical infrastructure.

#### Scandinavia and Europe

- Added a dedicated Scandinavia and Europe section.
- Added regional routing for:
  - Norway.
  - Sweden.
  - Denmark.
  - Finland.
  - Iceland.
  - Nordic and Scandinavian developments.
  - EU and EEA developments.
  - ENISA.
  - CERT-EU references found in collected material.
  - NIS2.
  - DORA.
  - NSM.
  - Sikkerhetsloven.
- Added regional headline selection from both primary and secondary sources.

#### Source and section structure

- Renamed `Microsoft` to `Microsoft, Azure and Identity`.
- Renamed `HPE` to `HPE and Aruba`.
- Added the final detailed report order:
  - Known Exploited Vulnerabilities.
  - Microsoft, Azure and Identity.
  - Fortinet.
  - HPE and Aruba.
  - Other Vendor Advisories.
  - Cloud and Identity.
  - SOC and Detection Engineering.
  - Threat Intelligence.
  - Vulnerability Research.
  - OT, Energy and Oil & Gas.
  - Scandinavia and Europe.
  - Norwegian Security Governance.
  - Compliance.
  - Standards.
  - GRC.
  - Upcoming Compliance, Standards and Governance.
  - Source Coverage.
  - CISO Watch List.

#### Workflows and packaging

- Added a production workflow:
  `.github/workflows/daily-security-brief.yml`.
- Added a manual test workflow:
  `.github/workflows/test-security-brief.yml`.
- Added a production schedule at 07:07 Europe/Oslo.
- Added workflow concurrency control to prevent overlapping scheduled runs.
- Added configurable manual-test inputs.
- Added a `VERSION` file.
- Added a consolidated `README.md`.
- Added this expanded `CHANGELOG.md`.
- Added a SHA-256 checksum for the release archive.

### Changed

- Increased the GitHub Actions timeout to 30 minutes to accommodate the larger
  source set and NVD throttling.
- Changed the default secondary-news maximum from eight to ten.
- Changed the source hierarchy to explicitly separate:
  - Authoritative vulnerability and exploitation sources.
  - Vendor and technical research.
  - Governance and standards.
  - Secondary discovery sources.
- Changed final item selection to reserve report capacity for populated
  sections before filling the remaining allowance by score.
- Changed empty-section handling so sections without qualifying content are
  suppressed.
- Changed successful zero-result source reporting to a single compact summary
  line.
- Changed the email subject to include:
  - DEFCON value.
  - Product name.
  - Version.
  - Number of primary developments.

### Fixed

- Corrected section routing for HPE and Aruba.
- Corrected healthcare-sector keyword matching to reduce false positives from
  the word `hospitality`.
- Preserved bordered vulnerability and intelligence cards after the v4.0
  renderer consolidation.
- Preserved full-width horizontal separators below each item.
- Preserved non-fatal source failures and visible source diagnostics.

### Security

- Retained least-privilege GitHub Actions permissions:
  `contents: read`.
- Retained Gmail and NVD secrets exclusively through GitHub Actions secrets.
- Documented the trust boundary between authoritative and secondary sources.
- Documented source content as untrusted input.
- Documented recommended future controls:
  - Full commit-hash pinning for GitHub Actions.
  - Dependency hash pinning.
  - Dependabot.
  - `pip-audit`.
  - Machine-readable CycloneDX or SPDX SBOM generation.

### Known limitations

- No LLM-based semantic analysis.
- Deterministic summaries, actions and detection guidance.
- HTML source adapters may break when sites change layout.
- Some dynamically rendered pages may return no parsable content.
- No persistent state across runs.
- Stories may repeat while they remain inside the reporting window.
- The future governance event register requires manual maintenance.
- X.com is not included because stable automated access requires a paid API or
  unreliable scraping.

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
