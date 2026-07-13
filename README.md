# SecuriytIntelligenceBrief V.3.0

My own personal customised Security and Intelligence Brief. Designed to keep me in the "now" situation of security happenings and information

## Defcon Labling
Value | Label | Colour
---|---|---
DEFCON 1 | Critical | Red
DEFCON 2 | High | Orange
DEFCON 3 | Elevated | Amber
DEFCON 4 | Guarded | Blue
DEFCON 5 | Low | Green
---
### Reporting window

The workflow now uses Europe/Oslo local time:

Monday: previous 72 hours
Tuesday–Sunday: previous 36 hours

For manual tests, set lookback_hours to auto.

### Executive Summary

It now explicitly includes:

Zero-day vulnerabilities
CVSS 10.0 vulnerabilities
Major compliance changes
Major standards changes
Major GRC changes
Norwegian security-governance changes
Requirements or standards taking effect today or during the coming 14 days

### Governance monitoring

The report explicitly tracks:

NSM updates and warnings
Sikkerhetsloven
NIS2
ISO/IEC 27001
ISO 50001
ISO 9001
ISO 14001
ISO/IEC 33000 series

A dedicated Norwegian Security Governance section has also been added.

### NVD enrichment

The collector now queries NVD for CVSS data and displays:

CVSS score
Severity
CVSS vector
Zero-day indication
KEV status
Known exploitation
Ransomware usage

--- 

## Key External services and data sources: 
- Gmail SMTP
- CISA Known Exploited Vulnerabilities catalogue
- NIST National Vulnerability Database API
- Microsoft Security Blog
- AWS Security Blog
- Palo Alto Networks Unit 42
- Google Project Zero
- CrowdStrike
- Cisco Talos
- Fortinet PSIRT
- FortiGuard Labs
- HPE Security Bulletin Library
- HPE Networking Security Advisories
- Apple Security Releases
- Okta Security
- ENISA
- NIST CSRC
- PCI Security Standards Council
- ISACA
- Norwegian National Security Authority (NSM)
- Norwegian Government information services
- International Organization for Standardization (ISO)
