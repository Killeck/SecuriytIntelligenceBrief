# Copyright © 2026 John-Helge Gantz. All rights reserved.
#
# Proprietary and confidential.
# Unauthorised use, copying, modification or distribution is prohibited.
# See the LICENSE file at the repository root for complete terms.

"""Deterministic relevance, classification and advisory rules."""

from __future__ import annotations

RELEVANCE_RULES = (
    (
        "Dark Web/Exposure",
        (
            "dark web",
            "darknet",
            "ransomware",
            "extortion",
            "stealer log",
            "infostealer",
            "credential dump",
            "data breach",
            "data leak",
            "initial access broker",
            "cybercrime forum",
            "phishing-as-a-service",
            "brand impersonation",
            "stolen data",
        ),
        44,
    ),
    (
        "Azure/Microsoft",
        (
            "azure",
            "microsoft 365",
            "office 365",
            "entra",
            "defender",
            "sentinel",
            "active directory",
            "sharepoint",
            "exchange online",
            "windows server",
            "microsoft",
        ),
        40,
    ),
    (
        "Fortinet",
        (
            "fortinet",
            "fortigate",
            "fortios",
            "fortimanager",
            "fortianalyzer",
            "forticlient",
            "fortiedr",
            "fortisiem",
            "fortiweb",
            "fortimail",
            "fortinac",
            "fortiauthenticator",
            "fortisandbox",
        ),
        42,
    ),
    (
        "HPE/Aruba",
        (
            "hewlett packard enterprise",
            "hpe ",
            "hpe aruba",
            "aruba networks",
            "aruba central",
            "arubaos",
            "proliant",
            "oneview",
        ),
        38,
    ),
    (
        "SOC/Security Operations",
        (
            "security operations",
            "soc ",
            " siem",
            "xdr",
            "mdr",
            "edr",
            "detection engineering",
            "threat hunting",
            "incident response",
            "security monitoring",
            "log management",
            "soar",
        ),
        28,
    ),
    (
        "Identity",
        (
            "identity security",
            "authentication",
            "mfa",
            "oauth",
            "token theft",
            "session theft",
            "phishing-as-a-service",
            "aitm",
            "credential",
            "privileged access",
            "kerberos",
        ),
        24,
    ),
    (
        "Cloud",
        (
            "cloud security",
            "aws",
            "google cloud",
            "kubernetes",
            "container",
            "docker",
            "terraform",
            "cloud-native",
            "saas",
        ),
        22,
    ),
    (
        "Nordics",
        (
            "norway",
            "norwegian",
            "sweden",
            "swedish",
            "denmark",
            "danish",
            "finland",
            "finnish",
            "nordic",
            "scandinavia",
            "scandinavian",
            "iceland",
        ),
        30,
    ),
    (
        "Europe",
        (
            "europe",
            "european",
            "european union",
            " eu ",
            "eea",
            "enisa",
            "nis2",
            "dora",
            "gdpr",
        ),
        22,
    ),
    (
        "Energy/Oil & Gas",
        (
            "oil and gas",
            "oil & gas",
            "offshore",
            "energy sector",
            "power grid",
            "utility",
            "utilities",
            "electricity",
            "pipeline",
            "industrial control",
            "operational technology",
            " ot ",
            "ics",
            "scada",
            "critical infrastructure",
        ),
        32,
    ),
    (
        "Public/Regulated",
        (
            "government",
            "public sector",
            "municipality",
            "municipal",
            "healthcare",
            "hospital",
            "finance",
            "banking",
            "insurance",
            "education",
            "university",
            "research",
            "transport",
            "rail",
            "airport",
            "maritime",
            "shipping",
        ),
        22,
    ),
    (
        "Retail/Hospitality/Property",
        (
            "retail",
            "retailer",
            "point of sale",
            "pos system",
            "e-commerce",
            "webshop",
            "hospitality",
            "hotel",
            "travel",
            "restaurant",
            "property",
            "real estate",
            "housing",
            "construction",
        ),
        24,
    ),
    (
        "Service Providers",
        (
            "managed service provider",
            "msp",
            "managed security",
            "telecom",
            "network provider",
            "hosting provider",
            "data center",
            "datacenter",
        ),
        20,
    ),
    (
        "High Impact",
        (
            "zero-day",
            "zero day",
            "actively exploited",
            "exploited in the wild",
            "ransomware",
            "data breach",
            "supply chain",
            "nation-state",
            "state-sponsored",
            "critical vulnerability",
            "remote code execution",
            "authentication bypass",
        ),
        18,
    ),
)

EXECUTIVE_NEWS_EXCLUDE = (
    "webinar",
    "sponsored",
    "advertorial",
    "partner content",
    "weekly recap",
    "newsletter",
    "podcast",
    "award",
    "funding round",
    "market report",
    "buyers guide",
    "best tools",
    "top 10 tools",
    "penetration testing framework",
)

EXPOSURE_SIGNAL_RULES = (
    (
        "Ransomware and Extortion",
        (
            "ransomware",
            "extortion",
            "double extortion",
            "data extortion",
            "leak site",
            "victim claim",
            "claimed responsibility",
            "ransom demand",
            "encryptor",
        ),
        "High",
        42,
        (
            "Validate whether the organisation, supplier or sector is exposed; "
            "review remote access, identity, EDR, backup and incident-response "
            "readiness."
        ),
    ),
    (
        "Credential Exposure and Stealer Logs",
        (
            "stealer log",
            "infostealer",
            "information stealer",
            "credential dump",
            "stolen credentials",
            "password dump",
            "session cookie",
            "session token",
            "access token",
            "browser credentials",
            "malware log",
            "combo list",
        ),
        "High",
        40,
        (
            "Identify affected identities, reset passwords, revoke active "
            "sessions and tokens, review MFA methods and investigate endpoint "
            "or browser compromise."
        ),
    ),
    (
        "Data Breaches and Leaks",
        (
            "data breach",
            "database leak",
            "data leak",
            "stolen data",
            "records exposed",
            "customer data",
            "employee data",
            "source code leak",
            "dumped online",
            "offered for sale",
            "data theft",
        ),
        "Elevated",
        34,
        (
            "Confirm scope and authenticity, identify affected data subjects, "
            "activate legal and privacy assessment, and prepare notification "
            "and credential-protection actions."
        ),
    ),
    (
        "Initial Access and Cybercrime Markets",
        (
            "initial access broker",
            "selling access",
            "network access for sale",
            "access broker",
            "cybercrime forum",
            "dark web marketplace",
            "underground forum",
            "malware-as-a-service",
            "ransomware-as-a-service",
            "phishing-as-a-service",
            "bulletproof hosting",
            "crypter",
            "loader service",
        ),
        "Elevated",
        32,
        (
            "Review exposed services, privileged remote access, stale accounts "
            "and third-party connectivity; hunt for access-establishment "
            "activity before payload deployment."
        ),
    ),
    (
        "Brand, Impersonation and Phishing",
        (
            "impersonation",
            "spoofing",
            "spoofed",
            "typosquat",
            "lookalike domain",
            "phishing domain",
            "fake login",
            "brand abuse",
            "fraudulent website",
            "adversary-in-the-middle",
            "aitm",
        ),
        "Elevated",
        30,
        (
            "Validate the infrastructure, submit takedown requests where "
            "appropriate, notify affected users and strengthen email, DNS and "
            "identity protections."
        ),
    ),
    (
        "Dark Web and Criminal Ecosystem",
        (
            "dark web",
            "darknet",
            "cybercrime ecosystem",
            "criminal marketplace",
            "forum administrator",
            "marketplace operator",
            "law enforcement operation",
            "takedown",
            "sanctioned",
            "sanctions",
            "cryptomixer",
            "money laundering",
        ),
        "Guarded",
        24,
        (
            "Assess whether the disrupted infrastructure, actors or services "
            "overlap with current investigations, IOCs, suppliers or customer "
            "exposure."
        ),
    ),
)

EXPOSURE_SECTION_ORDER = (
    "Ransomware and Extortion",
    "Credential Exposure and Stealer Logs",
    "Data Breaches and Leaks",
    "Initial Access and Cybercrime Markets",
    "Brand, Impersonation and Phishing",
    "Dark Web and Criminal Ecosystem",
)

SENSITIVE_DATA_CLASSES = {
    "Passwords",
    "Password hints",
    "Authentication tokens",
    "Session cookies",
    "Credit cards",
    "Bank account numbers",
    "Government issued IDs",
    "National identification numbers",
    "Social security numbers",
    "Private messages",
    "Source code",
}

SECTOR_IMPACT_RULES = (
    (
        "Oil, Gas and Energy",
        (
            "oil and gas",
            "oil & gas",
            "offshore",
            "energy sector",
            "utility",
            "utilities",
            "power grid",
            "electricity",
            "pipeline",
            "industrial control",
            "operational technology",
            "scada",
            "critical infrastructure",
        ),
        (
            "Review OT exposure, remote vendor access, operational continuity "
            "and supplier dependencies."
        ),
        35,
    ),
    (
        "Retail and E-commerce",
        (
            "retail",
            "retailer",
            "point of sale",
            "pos system",
            "payment card",
            "e-commerce",
            "ecommerce",
            "webshop",
            "merchant",
        ),
        (
            "Assess payment, identity, outsourced IT and distributed endpoint "
            "exposure."
        ),
        28,
    ),
    (
        "Hospitality and Travel",
        (
            "hospitality",
            "hotel",
            "travel",
            "booking",
            "restaurant",
            "airline",
            "tourism",
            "guest data",
        ),
        (
            "Review payment systems, guest data, third-party booking services "
            "and identity controls."
        ),
        28,
    ),
    (
        "Public Sector and Municipalities",
        (
            "public sector",
            "government",
            "municipality",
            "municipal",
            "local authority",
            "public administration",
        ),
        (
            "Assess service continuity, citizen data, supplier access and "
            "regulatory reporting obligations."
        ),
        26,
    ),
    (
        "Healthcare",
        (
            "healthcare",
            " hospital ",
            "patient",
            "medical",
            "health service",
            "clinical",
        ),
        (
            "Review patient-data exposure, clinical availability and "
            "third-party technology dependencies."
        ),
        27,
    ),
    (
        "Finance and Insurance",
        (
            "bank",
            "banking",
            "finance",
            "financial",
            "insurance",
            "payment",
            "fintech",
            "dora",
        ),
        (
            "Assess identity, fraud, payment, resilience and regulatory "
            "reporting impact."
        ),
        27,
    ),
    (
        "Research and Education",
        (
            "research",
            "university",
            "college",
            "education",
            "school",
            "academic",
        ),
        (
            "Review identity sprawl, research-data exposure, open networks and "
            "third-party collaboration risks."
        ),
        22,
    ),
    (
        "Transport and Maritime",
        (
            "transport",
            "rail",
            "railway",
            "airport",
            "aviation",
            "maritime",
            "shipping",
            "port",
            "logistics",
        ),
        (
            "Assess operational availability, remote access, OT integration and "
            "supply-chain dependencies."
        ),
        26,
    ),
    (
        "Property, Housing and Construction",
        (
            "property",
            "real estate",
            "housing",
            "construction",
            "building management",
            "smart building",
        ),
        (
            "Review shared-service dependencies, building systems, tenant data "
            "and supplier access."
        ),
        22,
    ),
    (
        "Managed Services, Telecom and Hosting",
        (
            "managed service provider",
            "msp",
            "managed security",
            "telecom",
            "network provider",
            "hosting provider",
            "data center",
            "datacenter",
        ),
        (
            "Assess multi-tenant blast radius, privileged access, remote "
            "management and downstream customer exposure."
        ),
        30,
    ),
)

DETECTION_TEMPLATES = {
    "Identity security": (
        "Detect abnormal sign-ins, OAuth consent, token use, session reuse and "
        "privileged role changes.",
        (
            "Entra SigninLogs, AuditLogs, service-principal sign-ins, identity "
            "provider logs and endpoint telemetry"
        ),
        "T1078 Valid Accounts; T1528 Steal Application Access Token",
    ),
    "Active exploitation": (
        "Monitor internet-facing services for exploit chains, unexpected child "
        "processes, web shells, new accounts and configuration changes.",
        (
            "WAF, firewall, VPN, web server, EDR, process creation and "
            "authentication logs"
        ),
        "T1190 Exploit Public-Facing Application; T1505.003 Web Shell",
    ),
    "Critical vulnerability": (
        "Correlate vulnerable asset exposure with exploit attempts, process "
        "anomalies and post-exploitation activity.",
        (
            "Vulnerability inventory, external exposure, WAF, EDR, NDR and "
            "system logs"
        ),
        "T1190 Exploit Public-Facing Application",
    ),
    "Ransomware": (
        "Detect rapid credential access, lateral movement, security-control "
        "tampering, mass file modification and backup interference.",
        (
            "EDR, Windows security events, identity logs, file telemetry, "
            "backup and hypervisor logs"
        ),
        (
            "T1486 Data Encrypted for Impact; T1562.001 Impair Defenses; "
            "T1021 Remote Services"
        ),
    ),
    "Cloud security": (
        "Monitor anomalous role assignments, access-key creation, policy "
        "changes, public exposure and unusual control-plane access.",
        (
            "Azure Activity Logs, AWS CloudTrail, Google Cloud Audit Logs and "
            "cloud posture telemetry"
        ),
        "T1098 Account Manipulation; T1078 Valid Accounts",
    ),
    "Supply-chain security": (
        "Detect unexpected build changes, dependency additions, workflow "
        "modification, secret access and unsigned artefacts.",
        (
            "GitHub/GitLab audit logs, CI/CD logs, package-manager logs, secret "
            "stores and artefact registries"
        ),
        "T1195 Supply Chain Compromise",
    ),
    "Nation-state activity": (
        "Map published infrastructure and techniques to telemetry, then hunt "
        "for rare destinations, long-lived access and credential abuse.",
        "DNS, proxy, NDR, EDR, identity, email and cloud logs",
        "T1583 Acquire Infrastructure; T1071 Application Layer Protocol",
    ),
    "OT and ICS security": (
        "Monitor new remote sessions, engineering-tool use, controller changes "
        "and unexpected industrial-protocol activity.",
        (
            "OT network monitoring, jump-host logs, VPN, engineering "
            "workstations, historians and controller audit trails"
        ),
        "T0886 Remote Services; T0831 Manipulation of Control",
    ),
    "Threat intelligence": (
        "Translate published IOCs and TTPs into targeted searches and validate "
        "coverage across endpoint, network, identity and cloud telemetry.",
        "SIEM, EDR, NDR, DNS, proxy, email and cloud logs",
        "Use source-specific MITRE ATT&CK mappings",
    ),
    "General security": (
        "Review the linked research for concrete IOCs, behaviours and logging "
        "requirements, then create a targeted hunt.",
        "Relevant SIEM, endpoint, network, identity and cloud telemetry",
        "Use source-specific MITRE ATT&CK mappings",
    ),
}

REGIONAL_TERMS = (
    "norway",
    "norwegian",
    "sweden",
    "swedish",
    "denmark",
    "danish",
    "finland",
    "finnish",
    "iceland",
    "nordic",
    "scandinavia",
    "scandinavian",
    "europe",
    "european",
    "european union",
    " eu ",
    "eea",
    "enisa",
    "nis2",
    "dora",
    "nsm",
    "nkom",
    "cert-eu",
    "sikkerhetsloven",
)

CATEGORY_RULES = (
    (
        "Active exploitation",
        (
            "actively exploited",
            "exploited in the wild",
            "under active exploitation",
            "zero-day",
            "0-day",
            "nulldag",
            "utnyttes aktivt",
        ),
        45,
    ),
    (
        "Ransomware",
        (
            "ransomware",
            "extortion",
            "encryptor",
            "løsepengevirus",
            "utpressing",
            "wiper",
            "destructive",
        ),
        35,
    ),
    (
        "Nation-state activity",
        (
            "nation-state",
            "state-sponsored",
            "apt",
            "espionage",
            "north korea",
            "russia",
            "china",
            "iran",
            "statlig",
            "etterretning",
        ),
        28,
    ),
    (
        "Identity security",
        (
            "entra",
            "active directory",
            "okta",
            "identity",
            "oauth",
            "mfa",
            "authentication",
            "token",
            "credential",
            "kerberos",
            "session",
            "phishing-resistant",
            "identitet",
            "pålogging",
        ),
        23,
    ),
    (
        "Regulatory and compliance",
        (
            "nis2",
            "dora",
            "gdpr",
            "regulation",
            "regulatory",
            "directive",
            "implementing act",
            "compliance",
            "legal requirement",
            "mandatory requirement",
            "reporting deadline",
            "pci dss",
            "data protection authority",
            "tilsyn",
            "forskrift",
            "regelverk",
            "etterlevelse",
        ),
        24,
    ),
    (
        "Standards and frameworks",
        (
            "cybersecurity standard",
            "security standard",
            "standardisation",
            "standardization",
            "framework",
            "guideline",
            "specification",
            "certification scheme",
            "nist csf",
            "nist rmf",
            "sp 800-",
            "iso/iec",
            "iso 27001",
            "cmmc",
            "post-quantum standard",
            "control baseline",
            "standarder",
            "rammeverk",
            "retningslinje",
            "sertifiseringsordning",
        ),
        22,
    ),
    (
        "Governance risk and assurance",
        (
            "cyber governance",
            "security governance",
            "risk management",
            "enterprise risk",
            "third-party risk",
            "supplier risk",
            "assurance",
            "internal audit",
            "cyber maturity",
            "board oversight",
            "security policy",
            "control effectiveness",
            "risk assessment",
            "resilience governance",
            "styring",
            "risikostyring",
            "revisjon",
            "modenhet",
        ),
        20,
    ),
    (
        "Supply-chain security",
        (
            "supply chain",
            "npm",
            "pypi",
            "dependency",
            "package",
            "github actions",
            "build pipeline",
            "software supply",
            "leverandørkjede",
        ),
        28,
    ),
    (
        "Cloud security",
        (
            "azure",
            "aws",
            "google cloud",
            "cloud",
            "kubernetes",
            "container",
            "docker",
            "terraform",
            "cloudflare",
            "sky",
        ),
        18,
    ),
    (
        "OT and ICS security",
        (
            "operational technology",
            "industrial control",
            "ics",
            "scada",
            "plc",
            "energy sector",
            "critical infrastructure",
            "kritisk infrastruktur",
            "kraft",
        ),
        24,
    ),
    (
        "Threat intelligence",
        (
            "malware",
            "campaign",
            "threat actor",
            "phishing",
            "botnet",
            "backdoor",
            "infostealer",
            "initial access",
            "loader",
            "trojan",
            "malicious",
            "skadevare",
            "trusselaktør",
        ),
        18,
    ),
    (
        "Critical vulnerability",
        (
            "critical vulnerability",
            "critical severity",
            "authentication bypass",
            "remote code execution",
            "command injection",
            "kritisk sårbarhet",
            "fjernkjøring",
        ),
        30,
    ),
)

WHY = {
    "Active exploitation": (
        "The source indicates real-world exploitation or a materially shortened "
        "window for exposure assessment and remediation."
    ),
    "Ransomware": (
        "The development may affect current initial-access, extortion, "
        "containment, or recovery assumptions."
    ),
    "Nation-state activity": (
        "The activity may indicate espionage or disruptive targeting relevant "
        "to exposed sectors, regions, and technologies."
    ),
    "Identity security": (
        "Identity compromise can provide direct access to cloud, email, "
        "administrative, and business systems."
    ),
    "Regulatory and compliance": (
        "The development may change legal duties, reporting expectations, "
        "audit scope, implementation timelines, or evidence requirements."
    ),
    "Standards and frameworks": (
        "Changes to standards, frameworks, and certification guidance can "
        "alter control baselines, assurance expectations, and implementation "
        "priorities."
    ),
    "Governance risk and assurance": (
        "The development may affect executive accountability, risk treatment, "
        "control assurance, auditability, or third-party governance."
    ),
    "Supply-chain security": (
        "A compromised package, build process, or supplier can propagate access "
        "across many downstream organisations."
    ),
    "Cloud security": (
        "Cloud control-plane and workload identity weaknesses can create broad "
        "access with limited traditional network visibility."
    ),
    "OT and ICS security": (
        "Operational technology incidents can affect safety, availability, "
        "production, and critical services beyond normal IT impact."
    ),
    "Threat intelligence": (
        "The report may provide current attacker behaviours, infrastructure, "
        "malware characteristics, or detection opportunities."
    ),
    "Critical vulnerability": (
        "The issue may enable high-impact compromise and should be assessed "
        "against exposed and business-critical systems."
    ),
    "Vendor advisory": (
        "The vendor has published security information that may require "
        "exposure assessment, patching, mitigation, or monitoring."
    ),
    "Security update": (
        "The release may close vulnerabilities affecting supported endpoints "
        "or services and should be assessed against deployment status."
    ),
    "Nordic warning": (
        "The warning has direct regional relevance and may reflect local "
        "prioritisation by a national security authority."
    ),
    "General security": (
        "The development may affect security architecture, operations, or "
        "risk decisions where the named technology or threat is relevant."
    ),
}

ACTIONS = {
    "Active exploitation": (
        "Identify exposure, verify patches or mitigations, review public-facing "
        "assets, and hunt for the published behaviours or indicators."
    ),
    "Ransomware": (
        "Review initial-access controls, ingest relevant indicators, verify "
        "protected backups, and confirm containment paths."
    ),
    "Nation-state activity": (
        "Assess sector and geographic relevance, then map published indicators "
        "and techniques to existing controls and detections."
    ),
    "Identity security": (
        "Review sign-ins and token use, enforce phishing-resistant MFA where "
        "possible, and revoke suspicious sessions or credentials."
    ),
    "Regulatory and compliance": (
        "Identify affected entities and deadlines, map the change to current "
        "controls and evidence, and assign legal or compliance ownership."
    ),
    "Standards and frameworks": (
        "Compare the update with current control mappings, identify material "
        "gaps, and plan adoption where it improves assurance or compliance."
    ),
    "Governance risk and assurance": (
        "Review governance ownership, risk records, assurance evidence, and "
        "board or audit reporting for any required changes."
    ),
    "Supply-chain security": (
        "Check dependency and supplier exposure, verify package provenance, "
        "review build logs, and rotate secrets where compromise is plausible."
    ),
    "Cloud security": (
        "Review workload identities, public exposure, privileged roles, and "
        "control-plane logs relevant to the report."
    ),
    "OT and ICS security": (
        "Identify affected products and sites, coordinate with operations, and "
        "apply vendor mitigations through the approved OT change process."
    ),
    "Threat intelligence": (
        "Read the primary report, extract applicable IOCs and TTPs, validate "
        "detection coverage, and run a targeted threat hunt."
    ),
    "Critical vulnerability": (
        "Confirm affected versions, prioritise internet-facing and privileged "
        "systems, and apply the vendor fix or mitigation."
    ),
    "Vendor advisory": (
        "Determine whether the product is deployed, confirm affected versions, "
        "and assign remediation or monitoring actions."
    ),
    "Security update": (
        "Confirm supported versions and deployment status, then prioritise "
        "devices with elevated exposure or sensitive access."
    ),
    "Nordic warning": (
        "Assess applicability to Nordic operations and follow the authority's "
        "recommended mitigation or monitoring guidance."
    ),
    "General security": (
        "Review the primary source, determine local relevance, and assign an "
        "owner where control changes or investigation are warranted."
    ),
}

NORWEGIAN_MONTHS = {
    "januar": "January",
    "februar": "February",
    "mars": "March",
    "april": "April",
    "mai": "May",
    "juni": "June",
    "juli": "July",
    "august": "August",
    "september": "September",
    "oktober": "October",
    "november": "November",
    "desember": "December",
}

DATE_PATTERNS = (
    r"\b\d{4}-\d{2}-\d{2}\b",
    (
        r"\b(?:January|February|March|April|May|June|July|August|"
        r"September|October|November|December)\s+\d{1,2},?\s+\d{4}\b"
    ),
    (
        r"\b\d{1,2}\s+(?:January|February|March|April|May|June|July|"
        r"August|September|October|November|December)\s+\d{4}\b"
    ),
    (
        r"\b\d{1,2}\s+(?:januar|februar|mars|april|mai|juni|juli|"
        r"august|september|oktober|november|desember)\s+\d{4}\b"
    ),
)

NVD_RECENT_COVERAGE = (
    {
        "vendor": "Fortinet",
        "section": "Fortinet",
        "terms": (
            "fortinet",
            "fortios",
            "fortigate",
            "fortimanager",
            "fortianalyzer",
            "forticlient",
            "fortiweb",
            "fortimail",
            "fortisandbox",
            "fortinac",
        ),
    },
    {
        "vendor": "HPE",
        "section": "HPE and Aruba",
        "terms": (
            "hewlett packard enterprise",
            "hpe ",
            "hpe aruba",
            "aruba networks",
            "aruba central",
            "arubaos",
            "proliant",
            "oneview",
        ),
    },
    {
        "vendor": "Microsoft / cloud identity",
        "section": "Microsoft, Azure and Identity",
        "terms": (
            "microsoft azure",
            "azure ",
            "microsoft entra",
            "entra id",
            "microsoft 365",
            "office 365",
            "active directory",
            "amazon web services",
            "aws ",
            "okta",
            "google cloud",
            "kubernetes",
        ),
    },
    {
        "vendor": "Other priority vendors",
        "section": "Other Vendor Advisories",
        "terms": (
            "cisco ",
            "palo alto networks",
            "pan-os",
            "apple ",
            "macos",
            "ios ",
            "crowdstrike",
        ),
    },
)
