from __future__ import annotations

import calendar
import html
import json
import math
import os
import re
import smtplib
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from email.message import EmailMessage
from typing import Any, Iterable
from urllib.parse import quote, urljoin
from urllib.request import Request, urlopen

import feedparser
import requests
from bs4 import BeautifulSoup, Tag
from dateutil import parser as date_parser


BRIEF_NAME = "Daily Security Brief"
BRIEF_VERSION = "4.1"

USER_AGENT = (
    f"daily-security-brief/{BRIEF_VERSION} "
    "(GitHub Actions; security news aggregation)"
)

CISA_KEV_FEED = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CISA_KEV_CATALOGUE = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HIBP_BREACHES_API = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_BREACHED_DOMAIN_API = (
    "https://haveibeenpwned.com/api/v3/breachedDomain"
)
HIBP_PWNED_WEBSITES = "https://haveibeenpwned.com/PwnedWebsites"
HIBP_DASHBOARD = "https://haveibeenpwned.com/Dashboard"
OSLO_TIMEZONE = ZoneInfo("Europe/Oslo")
UPCOMING_GOVERNANCE_FILE = Path(
    os.getenv(
        "UPCOMING_GOVERNANCE_FILE",
        "config/upcoming_governance.json",
    )
)

MONITORED_GOVERNANCE_TOPICS = (
    "NSM updates",
    "Sikkerhetsloven",
    "NIS2",
    "ISO/IEC 27001",
    "ISO 50001",
    "ISO 9001",
    "ISO 14001",
    "ISO/IEC 33000 series",
)

DEFCON_LEVELS = {
    1: {
        "label": "Critical",
        "colour": "#B71C1C",
        "text_colour": "#FFFFFF",
    },
    2: {
        "label": "High",
        "colour": "#E65100",
        "text_colour": "#FFFFFF",
    },
    3: {
        "label": "Elevated",
        "colour": "#F9A825",
        "text_colour": "#111111",
    },
    4: {
        "label": "Guarded",
        "colour": "#1565C0",
        "text_colour": "#FFFFFF",
    },
    5: {
        "label": "Low",
        "colour": "#2E7D32",
        "text_colour": "#FFFFFF",
    },
}

ZERO_DAY_TERMS = (
    "zero-day",
    "zero day",
    "0-day",
    "0day",
    "nulldag",
)

EFFECTIVE_DATE_TERMS = (
    "effective",
    "takes effect",
    "enters into force",
    "entry into force",
    "applies from",
    "applicable from",
    "enforcement begins",
    "enforced from",
    "deadline",
    "go live",
    "goes live",
    "transition period",
    "compliance date",
    "implementation date",
    "trer i kraft",
    "ikrafttredelse",
    "gjelder fra",
    "håndheves fra",
    "frist",
    "overgangsperiode",
)

GOVERNANCE_SECTIONS = {
    "Norwegian Security Governance",
    "Compliance",
    "Standards",
    "GRC",
    "Scandinavia and Europe",
}


@dataclass(frozen=True)
class Source:
    name: str
    vendor: str
    url: str
    source_type: str
    base_score: int
    section: str
    selectors: tuple[str, ...] = ()
    include_patterns: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    max_candidates: int = 25
    locale: str = "en"
    topic_keywords: tuple[str, ...] = ()


@dataclass
class Item:
    title: str
    summary: str
    link: str
    published: datetime
    source: str
    vendor: str
    section: str
    category: str
    score: int
    cves: list[str] = field(default_factory=list)
    exploited: bool = False
    kev: bool = False
    ransomware: bool = False
    zero_day: bool = False
    cvss_score: float | None = None
    cvss_severity: str = "Not available"
    cvss_vector: str = ""
    affected: str = ""
    action: str = ""
    why: str = ""


@dataclass
class NewsLink:
    title: str
    link: str
    source: str
    published: datetime
    score: int
    tags: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class ExposureSignal:
    title: str
    signal_type: str
    source: str
    link: str
    observed: datetime
    confidence: str
    severity: str
    score: int
    summary: str
    affected: str
    action: str
    organisation: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class SectorImpact:
    sector: str
    headline: str
    implication: str
    source: str
    link: str
    score: int


@dataclass
class DetectionOpportunity:
    title: str
    detection: str
    data_sources: str
    mitre: str
    source: str
    link: str
    score: int


EXECUTIVE_NEWS_RSS = (
    {
        "name": "Cyber Security News",
        "url": "https://cybersecuritynews.com/feed/",
        "base_score": 4,
    },
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "base_score": 8,
    },
    {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "base_score": 11,
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "base_score": 12,
    },
)

EXECUTIVE_NEWS_HTML = (
    {
        "name": "Reuters Cybersecurity",
        "url": "https://www.reuters.com/technology/cybersecurity/",
        "base_score": 14,
        "selectors": (
            "main a[href*='/technology/']",
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        "include": ("reuters.com",),
        "exclude": (
            "/video/",
            "/pictures/",
            "/graphics/",
            "/legal/",
        ),
    },
    {
        "name": "The Record",
        "url": "https://therecord.media/",
        "base_score": 12,
        "selectors": (
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        "include": ("therecord.media",),
        "exclude": (
            "/tag/",
            "/author/",
            "/category/",
        ),
    },
    {
        "name": "Cybersecurity Dive",
        "url": "https://www.cybersecuritydive.com/",
        "base_score": 10,
        "selectors": (
            "main h2 a[href]",
            "main h3 a[href]",
            "h2 a[href]",
            "h3 a[href]",
        ),
        "include": ("cybersecuritydive.com",),
        "exclude": (
            "/press-release/",
            "/library/",
            "/events/",
            "resources.industrydive.com",
            "sponsored",
        ),
    },
    {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/",
        "base_score": 8,
        "selectors": (
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        "include": ("darkreading.com",),
        "exclude": (
            "/webinars/",
            "/resources/",
            "/whitepapers/",
            "sponsored",
            "partner",
        ),
    },
    {
        "name": "BankInfoSecurity",
        "url": "https://www.bankinfosecurity.com/",
        "base_score": 9,
        "selectors": (
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        "include": ("bankinfosecurity.com",),
        "exclude": (
            "/webinars/",
            "/whitepapers/",
            "/events/",
            "/interviews/",
        ),
    },
    {
        "name": "SC World",
        "url": "https://www.scworld.com/",
        "base_score": 6,
        "selectors": (
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        "include": ("scworld.com",),
        "exclude": (
            "/resource/",
            "/events/",
            "/sponsored/",
        ),
    },
    {
        "name": "Industrial Cyber",
        "url": "https://industrialcyber.co/",
        "base_score": 12,
        "selectors": (
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        "include": ("industrialcyber.co",),
        "exclude": (
            "/events/",
            "/webinars/",
            "/sponsored/",
        ),
    },
)

EXECUTIVE_NEWS_SOURCE_LIMITS = {
    "Reuters Cybersecurity": 2,
    "SecurityWeek": 2,
    "BleepingComputer": 2,
    "The Record": 2,
    "The Hacker News": 2,
    "Cybersecurity Dive": 1,
    "Cyber Security News": 1,
    "Dark Reading": 1,
    "BankInfoSecurity": 1,
    "SC World": 1,
    "Industrial Cyber": 2,
}


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


RSS_SOURCES = (
    Source(
        name="Microsoft Security Blog",
        vendor="Microsoft",
        url="https://www.microsoft.com/en-us/security/blog/feed/",
        source_type="rss",
        base_score=30,
        section="Microsoft",
    ),
    Source(
        name="AWS Security Blog",
        vendor="AWS",
        url="https://aws.amazon.com/blogs/security/feed/",
        source_type="rss",
        base_score=18,
        section="Cloud and Identity",
    ),
    Source(
        name="Palo Alto Unit 42",
        vendor="Palo Alto Networks",
        url="https://unit42.paloaltonetworks.com/feed/",
        source_type="rss",
        base_score=28,
        section="Threat Intelligence",
    ),
    Source(
        name="Google Project Zero",
        vendor="Google",
        url=(
            "https://googleprojectzero.blogspot.com/feeds/posts/"
            "default?alt=rss"
        ),
        source_type="rss",
        base_score=24,
        section="Vulnerability Research",
    ),

    Source(
        name="Google Security Blog",
        vendor="Google",
        url=(
            "https://security.googleblog.com/feeds/posts/"
            "default?alt=rss"
        ),
        source_type="rss",
        base_score=26,
        section="Vulnerability Research",
    ),
    Source(
        name="CrowdStrike Blog",
        vendor="CrowdStrike",
        url="https://www.crowdstrike.com/en-us/blog/feed/",
        source_type="rss",
        base_score=24,
        section="Threat Intelligence",
    ),
    Source(
        name="The DFIR Report",
        vendor="The DFIR Report",
        url="https://thedfirreport.com/feed/",
        source_type="rss",
        base_score=30,
        section="SOC and Detection Engineering",
    ),
    Source(
        name="SigmaHQ Releases",
        vendor="SigmaHQ",
        url="https://github.com/SigmaHQ/sigma/releases.atom",
        source_type="rss",
        base_score=22,
        section="SOC and Detection Engineering",
    ),
)

HTML_SOURCES = (
    Source(
        name="Cisco Talos",
        vendor="Cisco",
        url="https://blog.talosintelligence.com/",
        source_type="html",
        base_score=28,
        section="Threat Intelligence",
        selectors=(
            "h2 a[href]",
            "h3 a[href]",
        ),
        include_patterns=("blog.talosintelligence.com",),
        exclude_patterns=(
            "/search/",
            "/p/",
            "/feeds/",
            "threat-source-newsletter",
        ),
        max_candidates=30,
    ),
    Source(
        name="Fortinet PSIRT",
        vendor="Fortinet",
        url="https://www.fortiguard.com/psirt",
        source_type="html",
        base_score=40,
        section="Fortinet",
        selectors=(
            "a[href*='/psirt/FG-IR-']",
            "a[href*='/psirt/fg-ir-']",
        ),
        include_patterns=("/psirt/",),
        max_candidates=40,
    ),
    Source(
        name="FortiGuard Labs Threat Research",
        vendor="Fortinet",
        url="https://www.fortinet.com/blog/threat-research",
        source_type="html",
        base_score=32,
        section="Fortinet",
        selectors=(
            "h2 a[href]",
            "h3 a[href]",
        ),
        include_patterns=("/blog/threat-research/",),
        exclude_patterns=(
            "/blog/threat-research$",
            "customer-success",
            "webinar",
        ),
        max_candidates=35,
    ),
    Source(
        name="HPE Security Bulletin Library",
        vendor="HPE",
        url=(
            "https://support.hpe.com/connect/s/"
            "securitybulletinlibrary?language=en_US"
        ),
        source_type="html",
        base_score=38,
        section="HPE",
        selectors=(
            "a[href*='docDisplay'][href*='hpesb']",
            "a[href*='docDisplay'][href*='HPESB']",
            "article a[href]",
            "table a[href]",
        ),
        include_patterns=("hpesb",),
        max_candidates=45,
    ),
    Source(
        name="Apple Security Releases",
        vendor="Apple",
        url="https://support.apple.com/en-us/100100",
        source_type="html",
        base_score=30,
        section="Other Vendor Advisories",
        selectors=(
            "table a[href]",
            "h2 a[href]",
            "h3 a[href]",
        ),
        include_patterns=("support.apple.com",),
        exclude_patterns=(
            "/guide/",
            "/contact",
            "/en-us/HT",
        ),
        max_candidates=35,
    ),
    Source(
        name="Okta Security",
        vendor="Okta",
        url="https://sec.okta.com/articles/",
        source_type="html",
        base_score=30,
        section="Cloud and Identity",
        selectors=(
            "h2 a[href]",
            "h3 a[href]",
            "article a[href]",
        ),
        include_patterns=("sec.okta.com/articles/",),
        exclude_patterns=("/articles/$",),
        max_candidates=25,
    ),
    Source(
        name="ENISA News",
        vendor="ENISA",
        url="https://www.enisa.europa.eu/news",
        source_type="html",
        base_score=32,
        section="Compliance",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        include_patterns=("enisa.europa.eu",),
        exclude_patterns=(
            "/events/",
            "/about-enisa/",
            "/topics/",
            "/publications/",
            "vacancies",
        ),
        max_candidates=45,
    ),
    Source(
        name="NIST CSRC News",
        vendor="NIST",
        url="https://csrc.nist.gov/News",
        source_type="html",
        base_score=30,
        section="Standards",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
            ".news-item a[href]",
        ),
        include_patterns=("csrc.nist.gov",),
        exclude_patterns=(
            "/events/",
            "/projects/",
            "/publications/",
            "#",
        ),
        max_candidates=40,
    ),
    Source(
        name="PCI Security Standards Council",
        vendor="PCI SSC",
        url="https://blog.pcisecuritystandards.org/",
        source_type="html",
        base_score=30,
        section="Compliance",
        selectors=(
            "article h2 a[href]",
            "article h3 a[href]",
            "h2 a[href]",
            "h3 a[href]",
        ),
        include_patterns=("pcisecuritystandards.org",),
        exclude_patterns=(
            "/tag/",
            "/author/",
            "/category/",
        ),
        max_candidates=35,
    ),
    Source(
        name="ISACA News and Trends",
        vendor="ISACA",
        url="https://www.isaca.org/resources/news-and-trends",
        source_type="html",
        base_score=24,
        section="GRC",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        include_patterns=("isaca.org",),
        exclude_patterns=(
            "/credentialing/",
            "/training-and-events/",
            "/membership/",
            "/career-centre/",
        ),
        max_candidates=35,
    ),

    Source(
        name="NSM Updates",
        vendor="NSM Norway",
        url="https://nsm.no/aktuelt/",
        source_type="html",
        base_score=40,
        section="Norwegian Security Governance",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
            "main a[href]",
        ),
        include_patterns=("nsm.no/",),
        exclude_patterns=(
            "#",
            "kontakt",
            "personvern",
            "tilgjengelighet",
        ),
        max_candidates=50,
        locale="no",
    ),
    Source(
        name="ISO News",
        vendor="ISO",
        url="https://www.iso.org/news.html",
        source_type="html",
        base_score=35,
        section="Standards",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
            ".news-item a[href]",
        ),
        include_patterns=("iso.org",),
        exclude_patterns=(
            "/store.html",
            "/members.html",
            "/events.html",
            "privacy",
            "terms",
        ),
        max_candidates=55,
        topic_keywords=(
            "iso/iec 27001",
            "iso 27001",
            "iso 50001",
            "iso 9001",
            "iso 14001",
            "iso/iec 330",
            "iso 33000",
            "management system standard",
            "information security management",
            "quality management",
            "environmental management",
            "energy management",
            "process assessment",
        ),
    ),
    Source(
        name="Elastic Security Labs",
        vendor="Elastic",
        url="https://www.elastic.co/security-labs",
        source_type="html",
        base_score=28,
        section="SOC and Detection Engineering",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        include_patterns=("elastic.co/security-labs",),
        exclude_patterns=(
            "/about/",
            "/careers/",
            "/contact/",
        ),
        max_candidates=35,
    ),
    Source(
        name="Splunk Security Blog",
        vendor="Splunk",
        url="https://www.splunk.com/en_us/blog/security.html",
        source_type="html",
        base_score=25,
        section="SOC and Detection Engineering",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        include_patterns=("splunk.com",),
        exclude_patterns=(
            "/events/",
            "/conf",
            "/customer-stories/",
            "webinar",
        ),
        max_candidates=35,
    ),
    Source(
        name="CISA ICS Advisories",
        vendor="CISA",
        url="https://www.cisa.gov/news-events/ics-advisories",
        source_type="html",
        base_score=42,
        section="OT, Energy and Oil & Gas",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
            "main a[href*='/news-events/ics-advisories/']",
        ),
        include_patterns=("/news-events/ics-advisories/",),
        exclude_patterns=(
            "/ics-advisories$",
            "#",
        ),
        max_candidates=60,
    ),
    Source(
        name="Dragos",
        vendor="Dragos",
        url="https://www.dragos.com/blog/",
        source_type="html",
        base_score=34,
        section="OT, Energy and Oil & Gas",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        include_patterns=("dragos.com/blog",),
        exclude_patterns=(
            "/events/",
            "/resources/",
            "webinar",
        ),
        max_candidates=40,
    ),
    Source(
        name="Claroty Team82",
        vendor="Claroty",
        url="https://claroty.com/team82/research",
        source_type="html",
        base_score=34,
        section="OT, Energy and Oil & Gas",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        include_patterns=("claroty.com",),
        exclude_patterns=(
            "/events/",
            "/webinars/",
            "/resources/",
        ),
        max_candidates=40,
    ),
    Source(
        name="Nozomi Networks Labs",
        vendor="Nozomi Networks",
        url="https://www.nozominetworks.com/blog",
        source_type="html",
        base_score=32,
        section="OT, Energy and Oil & Gas",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
        ),
        include_patterns=("nozominetworks.com/blog",),
        exclude_patterns=(
            "/events/",
            "/webinars/",
            "/resources/",
        ),
        max_candidates=40,
    ),
    Source(
        name="FBI Cyber News",
        vendor="FBI",
        url="https://www.fbi.gov/investigate/cyber/news",
        source_type="html",
        base_score=30,
        section="Dark Web and Criminal Ecosystem",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
            "main a[href*='/news/press-releases/']",
            "main a[href*='/news/stories/']",
        ),
        include_patterns=("fbi.gov/",),
        exclude_patterns=(
            "/wanted/",
            "/contact-us/",
            "/services/",
            "/history/",
        ),
        topic_keywords=(
            "ransomware",
            "cybercrime",
            "cybercriminal",
            "dark web",
            "stolen access",
            "selling access",
            "initial access",
            "infostealer",
            "stealer",
            "phishing",
            "malware",
            "botnet",
            "extortion",
            "data breach",
            "hacking group",
            "marketplace",
            "stolen credentials",
            "access token",
            "sanction",
            "takedown",
        ),
        max_candidates=60,
    ),
    Source(
        name="NSM Security Warnings",
        vendor="NSM Norway",
        url=(
            "https://nsm.no/fagomrader/digital-sikkerhet/"
            "nasjonalt-cybersikkerhetssenter/varsler-fra-nsm/"
        ),
        source_type="html",
        base_score=38,
        section="Nordic Impact",
        selectors=(
            "main a[href]",
            "article a[href]",
            "h2 a[href]",
            "h3 a[href]",
        ),
        include_patterns=("nsm.no/",),
        exclude_patterns=(
            "#",
            "/2026/",
            "/2025/",
            "/2024/",
            "/2023/",
            "/2022/",
            "/2021/",
            "/2020/",
            "/2019/",
            "/2018/",
            "kontakt",
            "personvern",
            "tilgjengelighet",
        ),
        max_candidates=45,
        locale="no",
    ),
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


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value.strip()


def integer_setting(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"{name} must be an integer.") from error

    if not minimum <= value <= maximum:
        raise RuntimeError(
            f"{name} must be between {minimum} and {maximum}."
        )

    return value


def reporting_window_hours() -> int:
    raw = os.getenv("NEWS_LOOKBACK_HOURS", "auto").strip().lower()

    if raw in {"", "auto", "automatic"}:
        local_now = datetime.now(OSLO_TIMEZONE)
        return 72 if local_now.weekday() == 0 else 36

    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(
            "NEWS_LOOKBACK_HOURS must be 'auto' or an integer."
        ) from error

    if value < 1 or value > 720:
        raise RuntimeError(
            "NEWS_LOOKBACK_HOURS must be between 1 and 720."
        )

    return value


def kev_lookback_days(lookback_hours: int) -> int:
    raw = os.getenv("KEV_LOOKBACK_DAYS", "auto").strip().lower()

    if raw in {"", "auto", "automatic"}:
        return max(1, math.ceil(lookback_hours / 24))

    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(
            "KEV_LOOKBACK_DAYS must be 'auto' or an integer."
        ) from error

    if value < 1 or value > 365:
        raise RuntimeError(
            "KEV_LOOKBACK_DAYS must be between 1 and 365."
        )

    return value


def clean_text(value: Any) -> str:
    if value is None:
        return ""

    soup = BeautifulSoup(str(value), "html.parser")
    return re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()


def absolute_url(base: str, href: str) -> str:
    return urljoin(base, href.strip())


def extract_cves(text: str) -> list[str]:
    return sorted(
        {
            match.upper()
            for match in re.findall(
                r"\bCVE-\d{4}-\d{4,7}\b",
                text,
                flags=re.IGNORECASE,
            )
        }
    )


def parse_date_text(text: str) -> datetime | None:
    normalised = clean_text(text)

    for norwegian, english in NORWEGIAN_MONTHS.items():
        normalised = re.sub(
            rf"\b{norwegian}\b",
            english,
            normalised,
            flags=re.IGNORECASE,
        )

    for pattern in DATE_PATTERNS:
        match = re.search(pattern, normalised, flags=re.IGNORECASE)
        if not match:
            continue

        try:
            parsed = date_parser.parse(
                match.group(0),
                fuzzy=False,
                dayfirst=True,
            )
            return parsed.replace(tzinfo=timezone.utc)
        except (ValueError, OverflowError):
            continue

    return None


def parse_all_dates(text: str) -> list[date]:
    normalised = clean_text(text)

    for norwegian, english in NORWEGIAN_MONTHS.items():
        normalised = re.sub(
            rf"\b{norwegian}\b",
            english,
            normalised,
            flags=re.IGNORECASE,
        )

    parsed_dates: set[date] = set()

    for pattern in DATE_PATTERNS:
        for match in re.finditer(
            pattern,
            normalised,
            flags=re.IGNORECASE,
        ):
            try:
                parsed = date_parser.parse(
                    match.group(0),
                    fuzzy=False,
                    dayfirst=True,
                )
                parsed_dates.add(parsed.date())
            except (ValueError, OverflowError):
                continue

    return sorted(parsed_dates)


def date_has_effective_context(text: str) -> bool:
    lowered = clean_text(text).lower()
    return any(term in lowered for term in EFFECTIVE_DATE_TERMS)


def feed_entry_time(entry: Any) -> datetime | None:
    for key in ("published_parsed", "updated_parsed", "created_parsed"):
        parsed = entry.get(key)
        if parsed:
            return datetime.fromtimestamp(
                calendar.timegm(parsed),
                tz=timezone.utc,
            )

    for key in ("published", "updated", "created"):
        raw = entry.get(key)
        if raw:
            try:
                parsed = date_parser.parse(str(raw))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except (ValueError, OverflowError):
                pass

    return None


def classify(text: str, source: Source) -> tuple[str, int]:
    lowered = text.lower()

    for category, keywords, weight in CATEGORY_RULES:
        if any(keyword in lowered for keyword in keywords):
            return category, weight

    if source.section in {
        "Fortinet",
        "HPE",
        "HPE and Aruba",
        "Other Vendor Advisories",
    }:
        if source.vendor == "Apple":
            return "Security update", 15
        return "Vendor advisory", 15

    if source.section == "Norwegian Security Governance":
        return "Governance risk and assurance", 22

    if source.section == "Nordic Impact":
        return "Nordic warning", 18

    if source.section == "Compliance":
        return "Regulatory and compliance", 18

    if source.section == "Standards":
        return "Standards and frameworks", 18

    if source.section == "GRC":
        return "Governance risk and assurance", 16

    return "General security", 0


def route_section(category: str, source: Source) -> str:
    if source.vendor == "Fortinet":
        return "Fortinet"

    if source.vendor == "HPE":
        return "HPE and Aruba"

    if source.vendor == "Microsoft":
        return "Microsoft, Azure and Identity"

    if source.section == "SOC and Detection Engineering":
        return "SOC and Detection Engineering"

    if source.section == "OT, Energy and Oil & Gas":
        return "OT, Energy and Oil & Gas"

    if category == "Regulatory and compliance":
        return "Compliance"

    if category == "Standards and frameworks":
        return "Standards"

    if source.section == "Norwegian Security Governance":
        return "Norwegian Security Governance"

    if source.section == "Nordic Impact":
        return "Scandinavia and Europe"

    if category == "Governance risk and assurance":
        return "GRC"

    return source.section


def suppress_marketing(text: str) -> bool:
    lowered = text.lower()

    marketing_terms = (
        "webinar",
        "conference",
        "event registration",
        "award",
        "gartner",
        "forrester",
        "customer story",
        "partner of the year",
        "magic quadrant",
        "frost radar",
        "sponsored",
        "podcast",
    )

    return any(term in lowered for term in marketing_terms)


def build_item(
    *,
    source: Source,
    title: str,
    summary: str,
    link: str,
    published: datetime,
    cutoff: datetime,
) -> Item | None:
    title = clean_text(title)
    summary = clean_text(summary)

    if not title or not link or published < cutoff:
        return None

    combined = f"{title} {summary}"

    if source.topic_keywords and not any(
        keyword.lower() in combined.lower()
        for keyword in source.topic_keywords
    ):
        return None

    if suppress_marketing(combined):
        return None

    category, weight = classify(combined, source)
    cves = extract_cves(combined)

    score = source.base_score + weight

    age = datetime.now(timezone.utc) - published
    if age <= timedelta(hours=24):
        score += 12
    elif age <= timedelta(hours=48):
        score += 7

    if cves:
        score += 10

    if "critical" in combined.lower() or "kritisk" in combined.lower():
        score += 10

    lowered_combined = combined.lower()
    zero_day = any(term in lowered_combined for term in ZERO_DAY_TERMS)
    exploited = category == "Active exploitation" or zero_day
    ransomware = category == "Ransomware"

    if zero_day:
        score += 35

    affected = (
        f"Organisations using {source.vendor} products or services, or "
        "matching the affected technology, sector, and attack surface "
        "described by the primary source."
    )

    return Item(
        title=title,
        summary=summary or "No source summary was available.",
        link=link,
        published=published,
        source=source.name,
        vendor=source.vendor,
        section=route_section(category, source),
        category=category,
        score=score,
        cves=cves,
        exploited=exploited,
        ransomware=ransomware,
        zero_day=zero_day,
        affected=affected,
        action=ACTIONS.get(category, ACTIONS["General security"]),
        why=WHY.get(category, WHY["General security"]),
    )


def fetch_rss(source: Source, cutoff: datetime) -> list[Item]:
    request = Request(
        source.url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/rss+xml, application/atom+xml, "
                "application/xml, text/xml, */*"
            ),
        },
    )

    with urlopen(request, timeout=45) as response:
        payload = response.read()

    feed = feedparser.parse(payload)

    if not feed.entries:
        details = clean_text(getattr(feed, "bozo_exception", ""))
        raise RuntimeError(
            "Feed returned no entries"
            + (f": {details}" if details else "")
        )

    items: list[Item] = []

    for entry in feed.entries:
        published = feed_entry_time(entry)
        if published is None:
            continue

        item = build_item(
            source=source,
            title=entry.get("title", ""),
            summary=(
                entry.get("summary")
                or entry.get("description")
                or entry.get("subtitle")
                or ""
            ),
            link=str(entry.get("link", "")).strip(),
            published=published,
            cutoff=cutoff,
        )

        if item:
            items.append(item)

    return items


def candidate_container(node: Tag) -> Tag:
    current = node

    for _ in range(5):
        parent = current.parent
        if not isinstance(parent, Tag):
            break

        text_length = len(clean_text(parent.get_text(" ", strip=True)))

        if parent.name in {"article", "li", "tr", "section"}:
            return parent

        if 40 <= text_length <= 2500:
            current = parent
        else:
            break

    return current


def extract_page_metadata(url: str) -> tuple[datetime | None, str]:
    response = requests.get(
        url,
        timeout=30,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    date_values: list[str] = []

    for selector in (
        "meta[property='article:published_time']",
        "meta[name='date']",
        "meta[name='pubdate']",
        "meta[itemprop='datePublished']",
        "time[datetime]",
    ):
        for element in soup.select(selector):
            if element.name == "meta":
                value = element.get("content", "")
            else:
                value = element.get("datetime", "")

            if value:
                date_values.append(str(value))

    for value in date_values:
        try:
            parsed = date_parser.parse(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return (
                parsed.astimezone(timezone.utc),
                extract_meta_summary(soup),
            )
        except (ValueError, OverflowError):
            continue

    return parse_date_text(soup.get_text(" ", strip=True)), extract_meta_summary(
        soup
    )


def extract_meta_summary(soup: BeautifulSoup) -> str:
    for selector in (
        "meta[name='description']",
        "meta[property='og:description']",
        "meta[name='twitter:description']",
    ):
        element = soup.select_one(selector)
        if element and element.get("content"):
            return clean_text(element.get("content"))

    paragraph = soup.select_one("article p, main p")
    return clean_text(paragraph.get_text(" ", strip=True)) if paragraph else ""


def link_allowed(source: Source, link: str) -> bool:
    lowered = link.lower()

    if source.include_patterns and not any(
        pattern.lower() in lowered for pattern in source.include_patterns
    ):
        return False

    if any(pattern.lower() in lowered for pattern in source.exclude_patterns):
        return False

    return True


def fetch_html(source: Source, cutoff: datetime) -> list[Item]:
    response = requests.get(
        source.url,
        timeout=45,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    candidates: list[tuple[str, str, str, datetime | None]] = []
    seen_links: set[str] = set()

    for selector in source.selectors:
        for node in soup.select(selector):
            if not isinstance(node, Tag):
                continue

            anchor = node if node.name == "a" else node.find("a", href=True)
            if not isinstance(anchor, Tag):
                continue

            href = str(anchor.get("href", "")).strip()
            if not href:
                continue

            link = absolute_url(source.url, href)
            if link in seen_links or not link_allowed(source, link):
                continue

            title = clean_text(anchor.get_text(" ", strip=True))
            if len(title) < 8:
                continue

            container = candidate_container(anchor)
            container_text = clean_text(container.get_text(" ", strip=True))
            published = parse_date_text(container_text)

            summary = ""
            for paragraph in container.find_all("p", limit=3):
                candidate = clean_text(paragraph.get_text(" ", strip=True))
                if candidate and candidate != title:
                    summary = candidate
                    break

            candidates.append((title, summary, link, published))
            seen_links.add(link)

            if len(candidates) >= source.max_candidates:
                break

        if len(candidates) >= source.max_candidates:
            break

    items: list[Item] = []

    for title, summary, link, published in candidates:
        if published is None or not summary:
            try:
                detail_date, detail_summary = extract_page_metadata(link)
                published = published or detail_date
                summary = summary or detail_summary
                time.sleep(0.15)
            except requests.RequestException as error:
                print(
                    f"WARNING: detail fetch failed for {link}: {error}",
                    file=sys.stderr,
                )

        if published is None:
            continue

        item = build_item(
            source=source,
            title=title,
            summary=summary,
            link=link,
            published=published,
            cutoff=cutoff,
        )

        if item:
            items.append(item)

    return items


def executive_news_relevance(
    title: str,
    summary: str,
    base_score: int,
) -> tuple[int, list[str]]:
    combined = f" {clean_text(title)} {clean_text(summary)} ".lower()

    if any(term in combined for term in EXECUTIVE_NEWS_EXCLUDE):
        return -100, []

    score = base_score
    tags: list[str] = []

    for tag, terms, weight in RELEVANCE_RULES:
        if any(term in combined for term in terms):
            score += weight
            tags.append(tag)

    if extract_cves(combined):
        score += 8

    return score, tags


def build_news_link(
    *,
    source: str,
    base_score: int,
    title: str,
    summary: str,
    link: str,
    published: datetime,
    cutoff: datetime,
) -> NewsLink | None:
    title = clean_text(title)
    summary = clean_text(summary)

    if not title or not link or published < cutoff:
        return None

    score, tags = executive_news_relevance(
        title,
        summary,
        base_score,
    )

    minimum_score = integer_setting(
        "EXEC_NEWS_MIN_SCORE",
        default=24,
        minimum=0,
        maximum=200,
    )

    if score < minimum_score:
        return None

    return NewsLink(
        title=title,
        link=link,
        source=source,
        published=published,
        score=score,
        tags=tags[:4],
        summary=summary,
    )


def fetch_executive_news_rss(
    source: dict[str, Any],
    cutoff: datetime,
) -> list[NewsLink]:
    request = Request(
        source["url"],
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/rss+xml, application/atom+xml, "
                "application/xml, text/xml, */*"
            ),
        },
    )

    with urlopen(request, timeout=45) as response:
        payload = response.read()

    feed = feedparser.parse(payload)

    if not feed.entries:
        details = clean_text(getattr(feed, "bozo_exception", ""))
        raise RuntimeError(
            "Feed returned no entries"
            + (f": {details}" if details else "")
        )

    links: list[NewsLink] = []

    for entry in feed.entries:
        published = feed_entry_time(entry)

        if published is None:
            continue

        news_link = build_news_link(
            source=source["name"],
            base_score=source["base_score"],
            title=entry.get("title", ""),
            summary=(
                entry.get("summary")
                or entry.get("description")
                or entry.get("subtitle")
                or ""
            ),
            link=str(entry.get("link", "")).strip(),
            published=published,
            cutoff=cutoff,
        )

        if news_link:
            links.append(news_link)

    return links


def fetch_executive_news_html(
    source: dict[str, Any],
    cutoff: datetime,
) -> list[NewsLink]:
    response = requests.get(
        source["url"],
        timeout=45,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    links: list[NewsLink] = []
    seen: set[str] = set()

    for selector in source["selectors"]:
        for node in soup.select(selector):
            if not isinstance(node, Tag):
                continue

            anchor = node if node.name == "a" else node.find("a", href=True)

            if not isinstance(anchor, Tag):
                continue

            href = str(anchor.get("href", "")).strip()
            title = clean_text(anchor.get_text(" ", strip=True))

            if not href or len(title) < 12:
                continue

            link = absolute_url(source["url"], href)
            lowered = link.lower()

            if link in seen:
                continue

            if source.get("include") and not any(
                value.lower() in lowered
                for value in source["include"]
            ):
                continue

            if any(
                value.lower() in lowered
                for value in source.get("exclude", ())
            ):
                continue

            container = candidate_container(anchor)
            container_text = clean_text(
                container.get_text(" ", strip=True)
            )
            published = parse_date_text(container_text)
            summary = ""

            for paragraph in container.find_all("p", limit=3):
                candidate = clean_text(
                    paragraph.get_text(" ", strip=True)
                )
                if candidate and candidate != title:
                    summary = candidate
                    break

            if published is None:
                try:
                    detail_date, detail_summary = extract_page_metadata(link)
                    published = detail_date
                    summary = summary or detail_summary
                    time.sleep(0.1)
                except requests.RequestException:
                    continue

            if published is None:
                continue

            news_link = build_news_link(
                source=source["name"],
                base_score=source["base_score"],
                title=title,
                summary=summary,
                link=link,
                published=published,
                cutoff=cutoff,
            )

            if news_link:
                links.append(news_link)

            seen.add(link)

    return links


def news_title_tokens(title: str) -> set[str]:
    ignored = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "that",
        "this",
        "after",
        "into",
        "over",
        "new",
        "cyber",
        "security",
        "attack",
        "attacks",
        "hackers",
    }

    return {
        token
        for token in re.findall(r"[a-z0-9]+", title.lower())
        if len(token) > 2 and token not in ignored
    }


def news_similarity(first: str, second: str) -> float:
    first_tokens = news_title_tokens(first)
    second_tokens = news_title_tokens(second)

    if not first_tokens or not second_tokens:
        return 0.0

    return len(first_tokens & second_tokens) / len(
        first_tokens | second_tokens
    )


def select_executive_news(
    links: list[NewsLink],
    primary_items: list[Item],
    max_items: int,
) -> list[NewsLink]:
    ordered = sorted(
        links,
        key=lambda item: (item.score, item.published),
        reverse=True,
    )

    selected: list[NewsLink] = []
    source_counts: dict[str, int] = {}
    primary_titles = [item.title for item in primary_items]
    primary_cves = {
        cve
        for item in primary_items
        for cve in item.cves
    }

    for news_link in ordered:
        news_cves = set(extract_cves(news_link.title))

        if news_cves and news_cves <= primary_cves:
            continue

        if any(
            news_similarity(news_link.title, title) >= 0.68
            for title in primary_titles
        ):
            continue

        if any(
            news_similarity(news_link.title, existing.title) >= 0.68
            for existing in selected
        ):
            continue

        source_limit = EXECUTIVE_NEWS_SOURCE_LIMITS.get(
            news_link.source,
            2,
        )

        if source_counts.get(news_link.source, 0) >= source_limit:
            continue

        selected.append(news_link)
        source_counts[news_link.source] = (
            source_counts.get(news_link.source, 0) + 1
        )

        if len(selected) >= max_items:
            break

    return selected


def build_sector_impacts(
    items: list[Item],
    news_links: list[NewsLink],
    max_items: int = 5,
) -> list[SectorImpact]:
    candidates: list[SectorImpact] = []

    story_records = [
        (
            item.title,
            item.summary,
            item.source,
            item.link,
            item.score,
        )
        for item in items
    ]
    story_records.extend(
        (
            link.title,
            link.summary,
            link.source,
            link.link,
            link.score,
        )
        for link in news_links
    )

    for sector, keywords, implication, weight in SECTOR_IMPACT_RULES:
        best: SectorImpact | None = None

        for title, summary, source, link, score in story_records:
            combined = f" {title} {summary} ".lower()

            if not any(keyword in combined for keyword in keywords):
                continue

            candidate = SectorImpact(
                sector=sector,
                headline=title,
                implication=implication,
                source=source,
                link=link,
                score=score + weight,
            )

            if best is None or candidate.score > best.score:
                best = candidate

        if best is not None:
            candidates.append(best)

    candidates.sort(key=lambda item: item.score, reverse=True)
    return candidates[:max_items]


def build_detection_opportunities(
    items: list[Item],
    max_items: int = 6,
) -> list[DetectionOpportunity]:
    selected: list[DetectionOpportunity] = []
    used_categories: set[str] = set()

    ordered = sorted(
        items,
        key=lambda item: (item.score, item.published),
        reverse=True,
    )

    for item in ordered:
        category = item.category

        if item.section == "OT, Energy and Oil & Gas":
            category = "OT and ICS security"
        elif (
            item.section == "SOC and Detection Engineering"
            and category == "General security"
        ):
            category = "Threat intelligence"

        if category in used_categories:
            continue

        template = DETECTION_TEMPLATES.get(category)

        if template is None:
            continue

        detection, data_sources, mitre = template
        selected.append(
            DetectionOpportunity(
                title=item.title,
                detection=detection,
                data_sources=data_sources,
                mitre=mitre,
                source=item.source,
                link=item.link,
                score=item.score,
            )
        )
        used_categories.add(category)

        if len(selected) >= max_items:
            break

    return selected


def build_regional_links(
    items: list[Item],
    news_links: list[NewsLink],
    max_items: int = 8,
) -> list[NewsLink]:
    candidates: list[NewsLink] = []

    for item in items:
        combined = f" {item.title} {item.summary} ".lower()

        if (
            item.section
            in {
                "Norwegian Security Governance",
                "Scandinavia and Europe",
                "Compliance",
            }
            or any(term in combined for term in REGIONAL_TERMS)
        ):
            candidates.append(
                NewsLink(
                    title=item.title,
                    link=item.link,
                    source=item.source,
                    published=item.published,
                    score=item.score + 20,
                    tags=["Scandinavia/Europe"],
                    summary=item.summary,
                )
            )

    for news_link in news_links:
        combined = f" {news_link.title} {news_link.summary} ".lower()

        if (
            any(
                tag in {"Nordics", "Europe"}
                for tag in news_link.tags
            )
            or any(term in combined for term in REGIONAL_TERMS)
        ):
            candidates.append(news_link)

    ordered = sorted(
        candidates,
        key=lambda item: (item.score, item.published),
        reverse=True,
    )

    selected: list[NewsLink] = []

    for candidate in ordered:
        if any(
            news_similarity(candidate.title, existing.title) >= 0.68
            for existing in selected
        ):
            continue

        selected.append(candidate)

        if len(selected) >= max_items:
            break

    return selected


def csv_setting(name: str) -> tuple[str, ...]:
    raw = os.getenv(name, "")
    values: list[str] = []
    seen: set[str] = set()

    for part in raw.split(","):
        value = clean_text(part)

        if not value:
            continue

        lowered = value.lower()

        if lowered in seen:
            continue

        values.append(value)
        seen.add(lowered)

    return tuple(values)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def exposure_severity_rank(severity: str) -> int:
    return {
        "Critical": 4,
        "High": 3,
        "Elevated": 2,
        "Guarded": 1,
        "Low": 0,
    }.get(severity, 1)


def clean_html_text(value: str) -> str:
    if not value:
        return ""

    return clean_text(
        BeautifulSoup(value, "html.parser").get_text(" ", strip=True)
    )


def fetch_hibp_breaches(cutoff: datetime) -> list[ExposureSignal]:
    response = requests.get(
        HIBP_BREACHES_API,
        timeout=45,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )
    response.raise_for_status()

    payload = response.json()

    if not isinstance(payload, list):
        raise RuntimeError("HIBP breach response was not a list")

    signals: list[ExposureSignal] = []

    for entry in payload:
        if not isinstance(entry, dict):
            continue

        if entry.get("IsSpamList") or entry.get("IsRetired"):
            continue

        raw_added = clean_text(entry.get("AddedDate"))

        if not raw_added:
            continue

        try:
            observed = ensure_utc(date_parser.parse(raw_added))
        except (ValueError, TypeError, OverflowError):
            continue

        if observed < cutoff:
            continue

        name = clean_text(entry.get("Name"))
        title = clean_text(entry.get("Title")) or name or "Unknown breach"
        domain = clean_text(entry.get("Domain")) or "Domain not stated"
        description = clean_html_text(
            str(entry.get("Description") or "")
        )
        data_classes = [
            clean_text(value)
            for value in entry.get("DataClasses", [])
            if clean_text(value)
        ]
        class_set = set(data_classes)
        pwn_count = entry.get("PwnCount")

        try:
            affected_count = int(pwn_count or 0)
        except (TypeError, ValueError):
            affected_count = 0

        is_stealer = bool(entry.get("IsStealerLog"))
        is_malware = bool(entry.get("IsMalware"))
        sensitive = bool(class_set & SENSITIVE_DATA_CLASSES)

        if is_stealer or is_malware or sensitive:
            signal_type = "Credential Exposure and Stealer Logs"
            severity = "High"
            score = 82
            action = (
                "Identify potentially affected identities, force password "
                "resets where applicable, revoke sessions and tokens, and "
                "investigate endpoint or browser compromise."
            )
        else:
            signal_type = "Data Breaches and Leaks"
            severity = "Elevated" if affected_count >= 100000 else "Guarded"
            score = 68 if severity == "Elevated" else 54
            action = (
                "Assess organisational and supplier exposure, identify "
                "affected identities or data classes, and activate privacy, "
                "legal and notification workflows where applicable."
            )

        confidence = (
            "Verified"
            if bool(entry.get("IsVerified"))
            else "Unverified dataset"
        )

        count_text = (
            f"{affected_count:,} accounts"
            if affected_count
            else "Account count not stated"
        )
        classes_text = (
            ", ".join(data_classes)
            if data_classes
            else "Data classes not stated"
        )
        breach_date = clean_text(entry.get("BreachDate"))

        summary_parts = [
            description or f"HIBP added breach metadata for {title}.",
            f"Breach date: {breach_date or 'not stated'}.",
        ]

        link = HIBP_PWNED_WEBSITES
        if name:
            link += f"#{quote(name, safe='')}"

        signals.append(
            ExposureSignal(
                title=f"New breach exposure: {title}",
                signal_type=signal_type,
                source="Have I Been Pwned",
                link=link,
                observed=observed,
                confidence=confidence,
                severity=severity,
                score=score,
                summary=" ".join(summary_parts),
                affected=(
                    f"{domain}; {count_text}; exposed data: {classes_text}."
                ),
                action=action,
                organisation=domain,
                tags=[
                    "HIBP",
                    "Stealer log" if is_stealer else "",
                    "Malware-sourced" if is_malware else "",
                ],
            )
        )

    return signals


def fetch_hibp_domain_exposure(
    domains: tuple[str, ...],
    api_key: str,
) -> list[ExposureSignal]:
    if not domains or not api_key:
        return []

    signals: list[ExposureSignal] = []

    for domain in domains:
        url = (
            f"{HIBP_BREACHED_DOMAIN_API}/"
            f"{quote(domain, safe='')}"
        )
        response = requests.get(
            url,
            timeout=45,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json",
                "hibp-api-key": api_key,
            },
        )

        if response.status_code == 404:
            time.sleep(1.7)
            continue

        response.raise_for_status()
        payload = response.json()

        if not isinstance(payload, dict):
            raise RuntimeError(
                f"HIBP domain response for {domain} was not an object"
            )

        breach_names = sorted(
            {
                clean_text(breach)
                for breaches in payload.values()
                if isinstance(breaches, list)
                for breach in breaches
                if clean_text(breach)
            }
        )
        affected_aliases = len(payload)

        if affected_aliases == 0:
            time.sleep(1.7)
            continue

        displayed_breaches = ", ".join(breach_names[:12])
        if len(breach_names) > 12:
            displayed_breaches += (
                f", plus {len(breach_names) - 12} additional breach(es)"
            )

        signals.append(
            ExposureSignal(
                title=f"Verified-domain breach exposure: {domain}",
                signal_type="Credential Exposure and Stealer Logs",
                source="Have I Been Pwned Domain Search",
                link=HIBP_DASHBOARD,
                observed=datetime.now(timezone.utc),
                confidence="Domain ownership verified",
                severity="High",
                score=95,
                summary=(
                    f"{affected_aliases} email alias(es) on the verified "
                    f"domain were associated with {len(breach_names)} "
                    "breach dataset(s). Individual aliases are deliberately "
                    "not included in this report."
                ),
                affected=(
                    f"Verified domain {domain}; breach datasets: "
                    f"{displayed_breaches or 'not stated'}."
                ),
                action=(
                    "Review affected identities in the HIBP dashboard, "
                    "validate current employment and account status, reset "
                    "reused credentials, revoke sessions, strengthen MFA, and "
                    "increase phishing and account-takeover monitoring."
                ),
                organisation=domain,
                tags=["HIBP", "Verified domain", "Credential exposure"],
            )
        )
        time.sleep(1.7)

    return signals


def matched_monitored_references(
    combined: str,
    monitored_brands: tuple[str, ...],
    monitored_domains: tuple[str, ...],
) -> list[str]:
    lowered = combined.lower()
    matches: list[str] = []

    for value in monitored_brands + monitored_domains:
        if value.lower() in lowered:
            matches.append(value)

    return matches


def build_open_source_exposure_signals(
    items: list[Item],
    news_links: list[NewsLink],
    monitored_brands: tuple[str, ...],
    monitored_domains: tuple[str, ...],
    max_items: int = 18,
) -> list[ExposureSignal]:
    records = [
        (
            item.title,
            item.summary,
            item.source,
            item.link,
            item.published,
            item.score,
            "Primary or research source",
        )
        for item in items
    ]
    records.extend(
        (
            link.title,
            link.summary,
            link.source,
            link.link,
            link.published,
            link.score,
            "Secondary reporting",
        )
        for link in news_links
    )

    signals: list[ExposureSignal] = []

    for (
        title,
        summary,
        source,
        link,
        observed,
        base_score,
        confidence,
    ) in records:
        combined = f" {title} {summary} "
        lowered = combined.lower()
        matches = matched_monitored_references(
            combined,
            monitored_brands,
            monitored_domains,
        )

        matched_rule = None

        for (
            signal_type,
            keywords,
            default_severity,
            weight,
            action,
        ) in EXPOSURE_SIGNAL_RULES:
            keyword_hits = sum(
                1 for keyword in keywords if keyword in lowered
            )

            if keyword_hits == 0:
                continue

            candidate_score = base_score + weight + min(
                keyword_hits * 4,
                16,
            )

            if matches:
                candidate_score += 35

            if (
                matched_rule is None
                or candidate_score > matched_rule[0]
            ):
                matched_rule = (
                    candidate_score,
                    signal_type,
                    default_severity,
                    action,
                )

        if matched_rule is None:
            continue

        score, signal_type, severity, action = matched_rule

        if score >= 115:
            severity = "Critical"
        elif score >= 90 and severity in {"Guarded", "Elevated"}:
            severity = "High"

        affected = (
            "Potential monitored reference: "
            + ", ".join(matches)
            + "."
            if matches
            else (
                "Organisations, suppliers and sectors matching the reported "
                "victim profile, technology or attack method."
            )
        )

        signals.append(
            ExposureSignal(
                title=title,
                signal_type=signal_type,
                source=source,
                link=link,
                observed=ensure_utc(observed),
                confidence=confidence,
                severity=severity,
                score=score,
                summary=truncate(summary or title, 700),
                affected=affected,
                action=action,
                organisation=", ".join(matches),
                tags=[signal_type] + matches,
            )
        )

    return signals[:max_items * 3]


def deduplicate_exposure_signals(
    signals: list[ExposureSignal],
    max_items: int,
) -> list[ExposureSignal]:
    ordered = sorted(
        signals,
        key=lambda signal: (
            exposure_severity_rank(signal.severity),
            signal.score,
            signal.observed,
        ),
        reverse=True,
    )

    selected: list[ExposureSignal] = []
    seen_links: set[str] = set()

    for signal in ordered:
        if signal.link and signal.link in seen_links:
            continue

        if any(
            news_similarity(signal.title, existing.title) >= 0.68
            for existing in selected
        ):
            continue

        selected.append(signal)

        if signal.link:
            seen_links.add(signal.link)

        if len(selected) >= max_items:
            break

    return selected


def group_exposure_signals(
    signals: list[ExposureSignal],
) -> dict[str, list[ExposureSignal]]:
    grouped = {
        section: []
        for section in EXPOSURE_SECTION_ORDER
    }

    for signal in signals:
        grouped.setdefault(signal.signal_type, []).append(signal)

    return grouped


def advisory_status(
    items: list[Item],
    exposure_signals: list[ExposureSignal],
) -> dict[str, Any]:
    base = defcon_status(items)
    level = int(base["level"])

    if any(
        signal.severity == "Critical"
        for signal in exposure_signals
    ):
        level = min(level, 1)
    elif any(
        signal.severity == "High"
        for signal in exposure_signals
    ):
        level = min(level, 2)
    elif any(
        signal.severity == "Elevated"
        for signal in exposure_signals
    ):
        level = min(level, 3)

    definition = DEFCON_LEVELS[level]

    return {
        "level": level,
        "label": definition["label"],
        "colour": definition["colour"],
        "text_colour": definition["text_colour"],
        "display": definition["label"],
    }


def advisory_actions(
    items: list[Item],
    signals: list[ExposureSignal],
) -> list[str]:
    actions: list[str] = []

    signal_types = {signal.signal_type for signal in signals}

    if "Credential Exposure and Stealer Logs" in signal_types:
        actions.append(
            "Review exposed identities, force targeted credential resets, "
            "revoke active sessions and tokens, and investigate source "
            "endpoints for infostealer activity."
        )

    if "Ransomware and Extortion" in signal_types:
        actions.append(
            "Validate reported victim and supplier claims, review remote "
            "access and privileged identity exposure, and confirm recovery "
            "and extortion-response readiness."
        )

    if "Brand, Impersonation and Phishing" in signal_types:
        actions.append(
            "Validate suspected impersonation infrastructure, start takedown "
            "and blocking workflows, and notify users or customers where "
            "fraudulent interaction is plausible."
        )

    if "Data Breaches and Leaks" in signal_types:
        actions.append(
            "Assess breach relevance to monitored organisations and suppliers, "
            "identify affected data classes, and trigger privacy, legal and "
            "customer-notification assessment where required."
        )

    for action in immediate_actions(items):
        if action not in actions:
            actions.append(action)

    return actions[:5]


def fetch_kev(lookback_days: int) -> list[Item]:
    request = Request(
        CISA_KEV_FEED,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )

    with urlopen(request, timeout=45) as response:
        catalogue = json.load(response)

    cutoff_date = datetime.now(timezone.utc).date() - timedelta(
        days=lookback_days - 1
    )

    items: list[Item] = []

    for entry in catalogue.get("vulnerabilities", []):
        raw_date = str(entry.get("dateAdded", "")).strip()
        if not raw_date:
            continue

        try:
            added = date.fromisoformat(raw_date)
        except ValueError:
            continue

        if added < cutoff_date:
            continue

        cve = clean_text(entry.get("cveID"))
        vendor = clean_text(entry.get("vendorProject")) or "Unknown vendor"
        product = clean_text(entry.get("product")) or "Unknown product"
        title = clean_text(entry.get("vulnerabilityName"))
        description = clean_text(entry.get("shortDescription"))
        required_action = clean_text(entry.get("requiredAction"))
        ransomware_value = clean_text(
            entry.get("knownRansomwareCampaignUse")
        ).lower()
        ransomware = ransomware_value == "known"

        published = datetime.combine(
            added,
            datetime.min.time(),
            tzinfo=timezone.utc,
        )

        action = required_action or (
            "Apply the vendor remediation or mitigation and investigate "
            "potential compromise."
        )

        due_date = clean_text(entry.get("dueDate"))
        summary = description

        if due_date:
            summary += f" CISA remediation due date: {due_date}."

        items.append(
            Item(
                title=f"{cve} — {title}",
                summary=summary,
                link=(
                    f"https://nvd.nist.gov/vuln/detail/{cve}"
                    if cve
                    else CISA_KEV_CATALOGUE
                ),
                published=published,
                source="CISA KEV",
                vendor=vendor,
                section="Known Exploited Vulnerabilities",
                category=(
                    "Ransomware" if ransomware else "Active exploitation"
                ),
                score=115 if ransomware else 105,
                cves=[cve] if cve else [],
                exploited=True,
                kev=True,
                ransomware=ransomware,
                affected=(
                    f"Organisations operating {vendor} {product} in affected "
                    "versions or configurations."
                ),
                action=action,
                why=(
                    "CISA has added this vulnerability to the Known Exploited "
                    "Vulnerabilities catalogue, confirming real-world "
                    "exploitation."
                ),
            )
        )

    return items


def select_cvss_metric(cve_record: dict[str, Any]) -> tuple[
    float | None,
    str,
    str,
]:
    metrics = cve_record.get("metrics", {})

    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        candidates = metrics.get(metric_name, [])

        if not candidates:
            continue

        selected = next(
            (
                metric
                for metric in candidates
                if metric.get("type") == "Primary"
            ),
            candidates[0],
        )
        data = selected.get("cvssData", {})
        score = data.get("baseScore")
        severity = (
            data.get("baseSeverity")
            or selected.get("baseSeverity")
            or "Not available"
        )
        vector = data.get("vectorString", "")

        try:
            numeric_score = float(score)
        except (TypeError, ValueError):
            numeric_score = None

        return numeric_score, str(severity), str(vector)

    return None, "Not available", ""


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


def english_nvd_description(cve_record: dict[str, Any]) -> str:
    descriptions = cve_record.get("descriptions", [])

    for description in descriptions:
        if description.get("lang") == "en":
            return clean_text(description.get("value"))

    if descriptions:
        return clean_text(descriptions[0].get("value"))

    return ""


def nvd_coverage_match(
    description: str,
) -> tuple[str, str] | None:
    lowered = description.lower()

    for coverage in NVD_RECENT_COVERAGE:
        if any(term in lowered for term in coverage["terms"]):
            return coverage["vendor"], coverage["section"]

    return None


def fetch_recent_nvd_coverage(
    cutoff: datetime,
) -> list[Item]:
    end = datetime.now(timezone.utc)
    api_key = os.getenv("NVD_API_KEY", "").strip()

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(
        NVD_CVE_API,
        params={
            "pubStartDate": cutoff.isoformat(timespec="milliseconds").replace(
                "+00:00",
                "Z",
            ),
            "pubEndDate": end.isoformat(timespec="milliseconds").replace(
                "+00:00",
                "Z",
            ),
            "resultsPerPage": 2000,
        },
        headers=headers,
        timeout=90,
    )
    response.raise_for_status()

    payload = response.json()
    items: list[Item] = []

    for vulnerability in payload.get("vulnerabilities", []):
        cve_record = vulnerability.get("cve", {})
        cve_id = clean_text(cve_record.get("id"))
        description = english_nvd_description(cve_record)

        if not cve_id or not description:
            continue

        coverage = nvd_coverage_match(description)
        if coverage is None:
            continue

        vendor, section = coverage

        published_raw = cve_record.get("published")

        try:
            published = date_parser.parse(str(published_raw))
            if published.tzinfo is None:
                published = published.replace(tzinfo=timezone.utc)
            published = published.astimezone(timezone.utc)
        except (ValueError, TypeError, OverflowError):
            continue

        cvss_score, cvss_severity, cvss_vector = select_cvss_metric(
            cve_record
        )

        category = (
            "Critical vulnerability"
            if cvss_score is not None and cvss_score >= 8.0
            else "Vendor advisory"
        )

        base_score = 38

        if cvss_score == 10.0:
            base_score += 50
        elif cvss_score is not None and cvss_score >= 9.0:
            base_score += 30
        elif cvss_score is not None and cvss_score >= 8.0:
            base_score += 18

        items.append(
            Item(
                title=f"{cve_id} — {vendor}",
                summary=description,
                link=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published=published,
                source="NVD Recent CVEs",
                vendor=vendor,
                section=section,
                category=category,
                score=base_score,
                cves=[cve_id],
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                cvss_vector=cvss_vector,
                affected=(
                    f"Organisations using affected {vendor} products or "
                    "services described in the NVD record."
                ),
                action=ACTIONS.get(
                    category,
                    ACTIONS["General security"],
                ),
                why=WHY.get(
                    category,
                    WHY["General security"],
                ),
            )
        )

    return items


def enrich_nvd(
    items: list[Item],
    warnings: list[str],
) -> None:
    cve_to_items: dict[str, list[Item]] = {}

    for item in items:
        for cve in item.cves:
            cve_to_items.setdefault(cve, []).append(item)

    if not cve_to_items:
        return

    api_key = os.getenv("NVD_API_KEY", "").strip()
    default_limit = 40 if api_key else 12
    max_cves = integer_setting(
        "NVD_MAX_CVES",
        default=default_limit,
        minimum=1,
        maximum=100,
    )

    cves = sorted(cve_to_items)[:max_cves]

    if len(cve_to_items) > max_cves:
        warnings.append(
            f"NVD enrichment limited to {max_cves} of "
            f"{len(cve_to_items)} CVEs. Add a free NVD_API_KEY or raise "
            "NVD_MAX_CVES to enrich more records."
        )

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    if api_key:
        headers["apiKey"] = api_key

    pause = 0.75 if api_key else 6.2

    for index, cve in enumerate(cves):
        try:
            response = requests.get(
                NVD_CVE_API,
                params={"cveId": cve},
                headers=headers,
                timeout=45,
            )
            response.raise_for_status()
            payload = response.json()
            vulnerabilities = payload.get("vulnerabilities", [])

            if not vulnerabilities:
                continue

            score, severity, vector = select_cvss_metric(
                vulnerabilities[0].get("cve", {})
            )

            for item in cve_to_items[cve]:
                if score is not None and (
                    item.cvss_score is None or score > item.cvss_score
                ):
                    item.cvss_score = score
                    item.cvss_severity = severity
                    item.cvss_vector = vector

                    if score == 10.0:
                        item.score += 40
                    elif score >= 9.0:
                        item.score += 20
                    elif score >= 8.0:
                        item.score += 10

        except Exception as error:
            warnings.append(
                f"NVD {cve}: {type(error).__name__}: {error}"
            )

        if index < len(cves) - 1:
            time.sleep(pause)


def load_configured_governance_events(
    today: date,
    days_ahead: int,
    warnings: list[str],
) -> list[dict[str, str]]:
    if not UPCOMING_GOVERNANCE_FILE.exists():
        warnings.append(
            f"Upcoming governance file not found: "
            f"{UPCOMING_GOVERNANCE_FILE}"
        )
        return []

    try:
        payload = json.loads(
            UPCOMING_GOVERNANCE_FILE.read_text(encoding="utf-8")
        )
    except Exception as error:
        warnings.append(
            f"Upcoming governance file: "
            f"{type(error).__name__}: {error}"
        )
        return []

    end_date = today + timedelta(days=days_ahead)
    events: list[dict[str, str]] = []

    for event in payload.get("events", []):
        if event.get("enabled", True) is False:
            continue

        raw_date = str(event.get("date", "")).strip()

        try:
            event_date = date.fromisoformat(raw_date)
        except ValueError:
            warnings.append(
                f"Invalid upcoming governance date: {raw_date}"
            )
            continue

        if not today <= event_date <= end_date:
            continue

        events.append(
            {
                "date": event_date.isoformat(),
                "title": clean_text(event.get("title")),
                "topic": clean_text(event.get("topic")),
                "source": clean_text(event.get("source")),
                "source_url": clean_text(event.get("source_url")),
                "notes": clean_text(event.get("notes")),
                "origin": "Configured event register",
            }
        )

    return events


def detect_governance_go_live_events(
    items: list[Item],
    today: date,
    days_ahead: int,
) -> list[dict[str, str]]:
    end_date = today + timedelta(days=days_ahead)
    events: list[dict[str, str]] = []

    for item in items:
        if item.section not in GOVERNANCE_SECTIONS:
            continue

        combined = f"{item.title}. {item.summary}"

        if not date_has_effective_context(combined):
            continue

        for event_date in parse_all_dates(combined):
            if not today <= event_date <= end_date:
                continue

            events.append(
                {
                    "date": event_date.isoformat(),
                    "title": item.title,
                    "topic": item.category,
                    "source": item.source,
                    "source_url": item.link,
                    "notes": truncate(item.summary, 320),
                    "origin": "Detected in current source item",
                }
            )

    return events


def deduplicate_governance_events(
    events: list[dict[str, str]],
) -> list[dict[str, str]]:
    unique: dict[tuple[str, str], dict[str, str]] = {}

    for event in events:
        key = (
            event.get("date", ""),
            event.get("title", "").lower(),
        )
        unique[key] = event

    return sorted(
        unique.values(),
        key=lambda event: (
            event.get("date", ""),
            event.get("title", ""),
        ),
    )


def select_final_items(
    items: list[Item],
    max_items: int,
) -> list[Item]:
    ordered = sorted(
        items,
        key=lambda item: (item.score, item.published),
        reverse=True,
    )

    mandatory = [
        item
        for item in ordered
        if item.zero_day
        or item.cvss_score == 10.0
        or item.kev
    ]

    section_order = (
        "Known Exploited Vulnerabilities",
        "Dark Web and Criminal Ecosystem",
        "Microsoft, Azure and Identity",
        "Fortinet",
        "HPE and Aruba",
        "Other Vendor Advisories",
        "Cloud and Identity",
        "SOC and Detection Engineering",
        "Threat Intelligence",
        "Vulnerability Research",
        "OT, Energy and Oil & Gas",
        "Scandinavia and Europe",
        "Norwegian Security Governance",
        "Compliance",
        "Standards",
        "GRC",
    )

    section_floor: list[Item] = []

    for section in section_order:
        section_items = [
            item for item in ordered if item.section == section
        ]
        section_floor.extend(section_items[:2])

    selected: list[Item] = []
    seen: set[str] = set()

    for item in mandatory + section_floor + ordered:
        key = (
            "|".join(item.cves)
            if item.cves
            else item.link.lower().rstrip("/")
        )

        if key in seen:
            continue

        if len(selected) >= max_items and item not in mandatory:
            continue

        selected.append(item)
        seen.add(key)

    selected.sort(
        key=lambda item: (item.score, item.published),
        reverse=True,
    )

    return selected


def deduplicate(items: Iterable[Item]) -> list[Item]:
    unique: dict[str, Item] = {}

    for item in items:
        key = item.link.lower().rstrip("/")

        if item.cves:
            key = "|".join(item.cves)

        existing = unique.get(key)

        if existing is None or item.score > existing.score:
            unique[key] = item

    return list(unique.values())


def priority(item: Item) -> str:
    if item.cvss_score == 10.0 or item.zero_day:
        return "Critical"
    if item.kev or item.score >= 95:
        return "Critical"
    if item.score >= 70:
        return "High"
    if item.score >= 45:
        return "Medium"
    return "Monitor"


def defcon_status(items: list[Item]) -> dict[str, Any]:
    if any(
        item.cvss_score == 10.0
        and (item.zero_day or item.exploited or item.kev)
        for item in items
    ):
        level = 1
    elif any(
        item.zero_day
        or item.cvss_score == 10.0
        or (item.kev and item.ransomware)
        for item in items
    ):
        level = 2
    elif any(
        item.kev
        or item.exploited
        or item.ransomware
        or item.category == "Nation-state activity"
        for item in items
    ):
        level = 3
    elif items:
        level = 4
    else:
        level = 5

    status = dict(DEFCON_LEVELS[level])
    status["level"] = level
    status["display"] = (
        f"DEFCON {level} — {status['label']}"
    )
    return status


def immediate_actions(items: list[Item]) -> list[str]:
    actions: list[str] = []

    if any(item.zero_day or item.cvss_score == 10.0 for item in items):
        actions.append(
            "Immediately validate exposure to all zero-day and CVSS 10.0 "
            "vulnerabilities and assign named remediation owners."
        )

    if any(item.kev for item in items):
        actions.append(
            "Validate exposure to all newly added KEV entries and assign "
            "remediation owners today."
        )

    if any(item.category == "Identity security" for item in items):
        actions.append(
            "Review high-risk sign-ins, token use, MFA gaps, and privileged "
            "identity activity relevant to today's reporting."
        )

    if any(item.category == "Ransomware" for item in items):
        actions.append(
            "Validate ransomware containment paths and protected recovery "
            "copies against the reported access techniques."
        )

    if any(item.section in {"Fortinet", "HPE and Aruba", "Other Vendor Advisories"} for item in items):
        actions.append(
            "Check the vendor advisory section against deployed products and "
            "current patch or firmware levels."
        )

    if any(item.section in {"Scandinavia and Europe", "Norwegian Security Governance"} for item in items):
        actions.append(
            "Assess the NSM warning against Norwegian operations and customer "
            "environments."
        )

    if any(item.section == "Compliance" for item in items):
        actions.append(
            "Review new compliance obligations, affected entities, deadlines, "
            "and evidence requirements."
        )

    if any(item.section == "Standards" for item in items):
        actions.append(
            "Assess whether standards or framework updates require control "
            "mapping or implementation changes."
        )

    if any(item.section == "GRC" for item in items):
        actions.append(
            "Review governance ownership, risk treatment, and assurance "
            "reporting affected by today's GRC developments."
        )

    defaults = (
        "Confirm internet-facing security appliances and identity systems are "
        "covered by accelerated vulnerability triage.",
        "Ensure threat-intelligence reports are converted into concrete hunts "
        "or detection validation rather than read-only awareness.",
        "Review supplier and software dependency exposure for newly reported "
        "supply-chain activity.",
    )

    for action in defaults:
        if len(actions) >= 3:
            break
        actions.append(action)

    return actions[:3]


def truncate(value: str, limit: int) -> str:
    value = clean_text(value)
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def render_item_text(item: Item, number: int) -> list[str]:
    cves = ", ".join(item.cves) or "None identified"
    cvss = (
        f"{item.cvss_score:.1f} {item.cvss_severity}"
        if item.cvss_score is not None
        else "Not available"
    )

    return [
        "",
        f"{number}. {item.title}",
        "-" * 72,
        f"Source: {item.source}",
        f"Published: {item.published.strftime('%Y-%m-%d %H:%M UTC')}",
        f"Category: {item.category}",
        f"Risk: {priority(item)}",
        f"CVEs: {cves}",
        f"CVSS: {cvss}",
        f"Zero-day: {'Yes' if item.zero_day else 'No explicit indication'}",
        f"Known exploitation: {'Yes' if item.exploited else 'Not stated'}",
        f"CISA KEV: {'Yes' if item.kev else 'No'}",
        f"Known ransomware use: {'Yes' if item.ransomware else 'Not stated'}",
        "",
        f"Summary: {truncate(item.summary, 850)}",
        "",
        f"Why it matters: {item.why}",
        "",
        f"Who is affected: {item.affected}",
        "",
        f"Recommended action: {item.action}",
        "",
        f"Primary source: {item.link}",
    ]


def render_item_html(item: Item) -> str:
    cves = ", ".join(item.cves) or "None identified"
    cvss = (
        f"{item.cvss_score:.1f} {item.cvss_severity}"
        if item.cvss_score is not None
        else "Not available"
    )

    return f"""
    <article style="
        border:1px solid #d0d7de;
        border-radius:8px;
        padding:18px;
        margin:0;
        background:#ffffff;
    ">
      <h3 style="margin-top:0">{html.escape(item.title)}</h3>

      <table style="border-collapse:collapse">
        <tr>
          <td style="padding:2px 16px 2px 0"><strong>Source</strong></td>
          <td>{html.escape(item.source)}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0"><strong>Published</strong></td>
          <td>{item.published.strftime("%Y-%m-%d %H:%M UTC")}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0"><strong>Category</strong></td>
          <td>{html.escape(item.category)}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0"><strong>Risk</strong></td>
          <td>{priority(item)}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0"><strong>CVEs</strong></td>
          <td>{html.escape(cves)}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0"><strong>CVSS</strong></td>
          <td>{html.escape(cvss)}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0"><strong>Zero-day</strong></td>
          <td>{"Yes" if item.zero_day else "No explicit indication"}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0">
            <strong>Known exploitation</strong>
          </td>
          <td>{"Yes" if item.exploited else "Not stated"}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0"><strong>CISA KEV</strong></td>
          <td>{"Yes" if item.kev else "No"}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0">
            <strong>Ransomware use</strong>
          </td>
          <td>{"Yes" if item.ransomware else "Not stated"}</td>
        </tr>
      </table>

      <h4>Summary</h4>
      <p>{html.escape(truncate(item.summary, 850))}</p>

      <h4>Why it matters</h4>
      <p>{html.escape(item.why)}</p>

      <h4>Who is affected</h4>
      <p>{html.escape(item.affected)}</p>

      <h4>Recommended action</h4>
      <p>{html.escape(item.action)}</p>

      <p>
        <a href="{html.escape(item.link, quote=True)}">Open primary source</a>
      </p>
    </article>
    <hr style="
        border:0;
        border-top:1px solid #b8bec5;
        margin:24px 0 28px 0;
        width:100%;
    ">
    """


def render_exposure_text(
    signal: ExposureSignal,
    number: int,
) -> list[str]:
    return [
        "",
        f"{number}. [{signal.severity}] {signal.title}",
        f"   Signal type: {signal.signal_type}",
        f"   Source: {signal.source}",
        (
            "   Observed: "
            f"{signal.observed.strftime('%Y-%m-%d %H:%M UTC')}"
        ),
        f"   Confidence: {signal.confidence}",
        f"   Summary: {signal.summary}",
        f"   Potentially affected: {signal.affected}",
        f"   Advisory action: {signal.action}",
        f"   Link: {signal.link}",
    ]


def render_exposure_html(signal: ExposureSignal) -> str:
    return f"""
    <article style="
        border:1px solid #7d4e9e;
        border-radius:8px;
        padding:18px;
        margin:0;
        background:#ffffff;
    ">
      <h3 style="margin-top:0">{html.escape(signal.title)}</h3>

      <table style="border-collapse:collapse">
        <tr>
          <td style="padding:2px 16px 2px 0">
            <strong>Signal type</strong>
          </td>
          <td>{html.escape(signal.signal_type)}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0">
            <strong>Source</strong>
          </td>
          <td>{html.escape(signal.source)}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0">
            <strong>Observed</strong>
          </td>
          <td>{signal.observed.strftime("%Y-%m-%d %H:%M UTC")}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0">
            <strong>Confidence</strong>
          </td>
          <td>{html.escape(signal.confidence)}</td>
        </tr>
        <tr>
          <td style="padding:2px 16px 2px 0">
            <strong>Severity</strong>
          </td>
          <td>{html.escape(signal.severity)}</td>
        </tr>
      </table>

      <h4>Exposure summary</h4>
      <p>{html.escape(truncate(signal.summary, 850))}</p>

      <h4>Potentially affected</h4>
      <p>{html.escape(signal.affected)}</p>

      <h4>Security advisory action</h4>
      <p>{html.escape(signal.action)}</p>

      <p>
        <a href="{html.escape(signal.link, quote=True)}">
          Open supporting source
        </a>
      </p>
    </article>
    <hr style="
        border:0;
        border-top:1px solid #b8bec5;
        margin:24px 0 28px 0;
        width:100%;
    ">
    """


def render_report(
    items: list[Item],
    warnings: list[str],
    lookback_hours: int,
    upcoming_events: list[dict[str, str]],
    upcoming_days: int,
    source_health: list[dict[str, Any]],
    executive_news: list[NewsLink],
    sector_impacts: list[SectorImpact],
    detection_opportunities: list[DetectionOpportunity],
    regional_links: list[NewsLink],
    exposure_signals: list[ExposureSignal],
    monitored_brands: tuple[str, ...],
    monitored_domains: tuple[str, ...],
) -> tuple[str, str]:
    status = advisory_status(items, exposure_signals)
    enterprise_status = defcon_status(items)
    actions = advisory_actions(items, exposure_signals)
    exposure_grouped = group_exposure_signals(exposure_signals)

    critical_special = [
        item
        for item in items
        if item.zero_day or item.cvss_score == 10.0
    ]
    top_advisories = items[:5]
    top_exposure = exposure_signals[:5]
    major_governance = [
        item
        for item in items
        if item.section in GOVERNANCE_SECTIONS
        and item.category
        in {
            "Regulatory and compliance",
            "Standards and frameworks",
            "Governance risk and assurance",
            "Nordic warning",
        }
    ]

    primary_section_order = (
        "Known Exploited Vulnerabilities",
        "Dark Web and Criminal Ecosystem",
        "Microsoft, Azure and Identity",
        "Fortinet",
        "HPE and Aruba",
        "Other Vendor Advisories",
        "Cloud and Identity",
        "SOC and Detection Engineering",
        "Threat Intelligence",
        "Vulnerability Research",
        "OT, Energy and Oil & Gas",
        "Scandinavia and Europe",
        "Norwegian Security Governance",
        "Compliance",
        "Standards",
        "GRC",
    )

    section_titles = {
        "Known Exploited Vulnerabilities": (
            "Active Exploitation and CISA KEV"
        ),
        "Dark Web and Criminal Ecosystem": (
            "Law-Enforcement and Criminal Ecosystem Reporting"
        ),
        "Other Vendor Advisories": "Other Vendor Security Advisories",
        "Cloud and Identity": "Cloud and Supply-Chain Security",
    }

    grouped: dict[str, list[Item]] = {
        section: [] for section in primary_section_order
    }

    for item in items:
        grouped.setdefault(item.section, []).append(item)

    monitored_topics = ", ".join(MONITORED_GOVERNANCE_TOPICS)
    monitored_references = monitored_brands + monitored_domains
    report_title = f"{BRIEF_NAME} v{BRIEF_VERSION}"

    text = [
        report_title,
        "=" * len(report_title),
        "",
        f"Reporting window: previous {lookback_hours} hours",
        f"Security advisory level: {status['display']}",
        (
            "Enterprise cyber threat level: "
            f"{enterprise_status['display']}"
        ),
        f"Primary security developments: {len(items)}",
        f"Exposure and dark-web signals: {len(exposure_signals)}",
        f"Relevant discovery links: {len(executive_news)}",
        "",
        "Security Advisory Overview",
        "--------------------------",
        "",
        "Priority Security Advisories",
    ]

    if top_advisories:
        for index, item in enumerate(top_advisories, start=1):
            text.append(
                f"{index}. [{priority(item)}] {item.title} "
                f"— {item.source}: {item.link}"
            )
    else:
        text.append("No qualifying primary advisories were collected.")

    if top_exposure:
        text.extend(["", "Dark Web and Exposure Highlights"])

        for signal in top_exposure:
            text.append(
                f"- [{signal.severity}/{signal.confidence}] "
                f"{signal.title} — {signal.source}: {signal.link}"
            )

    ransomware_watch = exposure_grouped.get(
        "Ransomware and Extortion",
        [],
    )[:3]
    if ransomware_watch:
        text.extend(["", "Ransomware and Extortion Watch"])
        for signal in ransomware_watch:
            text.append(
                f"- [{signal.confidence}] {signal.title} "
                f"— {signal.source}: {signal.link}"
            )

    credential_watch = exposure_grouped.get(
        "Credential Exposure and Stealer Logs",
        [],
    )[:3]
    if credential_watch:
        text.extend(["", "Credential and Stealer Exposure"])
        for signal in credential_watch:
            text.append(
                f"- [{signal.confidence}] {signal.title} "
                f"— {signal.source}: {signal.link}"
            )

    if executive_news:
        text.extend(
            [
                "",
                "Relevant Cyber News",
                (
                    "One-line discovery links filtered for technology, "
                    "geography, customer-sector and exposure relevance."
                ),
            ]
        )
        for news_link in executive_news:
            tag_text = (
                f"[{', '.join(news_link.tags)}] "
                if news_link.tags
                else ""
            )
            text.append(
                f"- {tag_text}{news_link.title} "
                f"— {news_link.source}: {news_link.link}"
            )

    text.extend(["", "Zero-Day and CVSS 10.0"])

    if critical_special:
        for item in critical_special:
            markers = []
            if item.zero_day:
                markers.append("Zero-Day")
            if item.cvss_score == 10.0:
                markers.append("CVSS 10.0")
            text.append(
                f"- {', '.join(markers)}: {item.title} "
                f"— {item.source}: {item.link}"
            )
    else:
        text.append("None identified in the reporting window.")

    if sector_impacts:
        text.extend(["", "Customer and Sector Advisory Impact"])
        for impact in sector_impacts:
            text.append(
                f"- {impact.sector}: {impact.implication} "
                f"Trigger: {impact.headline} — {impact.source}: {impact.link}"
            )

    if monitored_references:
        text.extend(
            [
                "",
                (
                    "Monitored references: "
                    + ", ".join(monitored_references)
                ),
            ]
        )

    text.extend(["", "Recommended Security Advisory Actions"])
    for action in actions:
        text.append(f"- {action}")

    if major_governance:
        text.extend(
            [
                "",
                "Relevant Compliance and Governance Changes",
            ]
        )
        for item in major_governance:
            text.append(
                f"- [{item.section}] {item.title} "
                f"— {item.source}: {item.link}"
            )

    if upcoming_events:
        text.extend(
            [
                "",
                f"Going Live Today or Within {upcoming_days} Days",
            ]
        )
        for event in upcoming_events:
            text.append(
                f"- {event['date']}: {event['title']} "
                f"({event.get('topic') or event.get('source')})"
            )

    for exposure_section in EXPOSURE_SECTION_ORDER:
        section_signals = exposure_grouped.get(
            exposure_section,
            [],
        )
        if not section_signals:
            continue

        text.extend(
            [
                "",
                exposure_section,
                "=" * len(exposure_section),
            ]
        )

        for number, signal in enumerate(section_signals, start=1):
            text.extend(render_exposure_text(signal, number))

    for section in primary_section_order:
        section_items = grouped.get(section, [])
        display_title = section_titles.get(section, section)

        if section == "SOC and Detection Engineering":
            if not section_items and not detection_opportunities:
                continue

            text.extend(
                [
                    "",
                    display_title,
                    "=" * len(display_title),
                ]
            )

            for opportunity in detection_opportunities:
                text.extend(
                    [
                        f"- Detection opportunity: {opportunity.title}",
                        f"  Detection: {opportunity.detection}",
                        f"  Data sources: {opportunity.data_sources}",
                        f"  MITRE ATT&CK: {opportunity.mitre}",
                        f"  Source: {opportunity.source}: {opportunity.link}",
                    ]
                )

            for number, item in enumerate(section_items, start=1):
                text.extend(render_item_text(item, number))

            continue

        if section == "Scandinavia and Europe":
            if not section_items and not regional_links:
                continue

            text.extend(
                [
                    "",
                    display_title,
                    "=" * len(display_title),
                ]
            )

            for regional_link in regional_links:
                text.append(
                    f"- {regional_link.title} — "
                    f"{regional_link.source}: {regional_link.link}"
                )

            for number, item in enumerate(section_items, start=1):
                text.extend(render_item_text(item, number))

            continue

        if not section_items:
            continue

        text.extend(
            [
                "",
                display_title,
                "=" * len(display_title),
            ]
        )

        for number, item in enumerate(section_items, start=1):
            text.extend(render_item_text(item, number))

    if upcoming_events:
        text.extend(
            [
                "",
                "Upcoming Compliance, Standards and Governance",
                "---------------------------------------------",
            ]
        )
        for event in upcoming_events:
            text.extend(
                [
                    f"- Date: {event['date']}",
                    f"  Event: {event['title']}",
                    f"  Topic: {event.get('topic') or 'Not specified'}",
                    f"  Source: {event.get('source') or 'Not specified'}",
                    f"  Notes: {event.get('notes') or 'None'}",
                    f"  Link: {event.get('source_url') or 'Not supplied'}",
                ]
            )

    active_sources = [
        health
        for health in source_health
        if health["status"] == "OK" and health["items"] > 0
    ]
    failed_sources = [
        health
        for health in source_health
        if health["status"] != "OK"
    ]
    quiet_source_count = sum(
        1
        for health in source_health
        if health["status"] == "OK" and health["items"] == 0
    )

    if active_sources or failed_sources or quiet_source_count:
        text.extend(["", "Source Coverage", "---------------"])

    for health in active_sources:
        text.append(
            f"- {health['source']}: {health['items']} qualifying item(s)."
        )

    if quiet_source_count:
        text.append(
            f"- {quiet_source_count} additional source(s) checked with "
            "no qualifying updates."
        )

    for health in failed_sources:
        text.append(
            f"- {health['source']}: FAILED — {health['detail']}"
        )

    text.extend(
        [
            "",
            "Security Advisory and CISO Watch List",
            "-------------------------------------",
            "- New credential and stealer-log exposure affecting monitored domains.",
            "- Ransomware victim claims involving customers, suppliers or key sectors.",
            "- New access-broker activity targeting remote access and cloud identity.",
            "- Data leaks containing credentials, tokens, source code or customer data.",
            "- Brand impersonation, typosquatting and adversary-in-the-middle phishing.",
            "- New CISA KEV additions and confirmation of active exploitation.",
            "- Microsoft identity, Azure and Microsoft 365 attack activity.",
            "- Fortinet, HPE and Aruba advisories affecting customer estates.",
            "- OT, energy, oil and gas, and critical-infrastructure targeting.",
            "- Scandinavian and European cybercrime or law-enforcement developments.",
            "- Material NIS2, Sikkerhetsloven, DORA and standards deadlines.",
        ]
    )

    text.extend(
        [
            "",
            "Handling Note",
            "-------------",
            (
                "Dark-web and criminal-ecosystem claims may be incomplete, "
                "misleading or intentionally false. Treat victim claims as "
                "reported intelligence until corroborated by the affected "
                "organisation, law enforcement or another reliable source."
            ),
        ]
    )

    if warnings:
        text.extend(["", "Source Warnings", "---------------"])
        text.extend(f"- {warning}" for warning in warnings)

    top_advisories_html = (
        "".join(
            f"<li><strong>{priority(item)}:</strong> "
            f'<a href="{html.escape(item.link, quote=True)}">'
            f"{html.escape(item.title)}</a> "
            f"<em>— {html.escape(item.source)}</em></li>"
            for item in top_advisories
        )
        or "<li>No qualifying primary advisories were collected.</li>"
    )

    top_exposure_html = "".join(
        (
            "<li style='margin-bottom:7px'>"
            f"<strong>{html.escape(signal.severity)} / "
            f"{html.escape(signal.confidence)}:</strong> "
            f'<a href="{html.escape(signal.link, quote=True)}">'
            f"{html.escape(signal.title)}</a> "
            f"<em>— {html.escape(signal.source)}</em></li>"
        )
        for signal in top_exposure
    )

    ransomware_html = "".join(
        (
            "<li style='margin-bottom:7px'>"
            f"<strong>{html.escape(signal.confidence)}:</strong> "
            f'<a href="{html.escape(signal.link, quote=True)}">'
            f"{html.escape(signal.title)}</a> "
            f"<em>— {html.escape(signal.source)}</em></li>"
        )
        for signal in ransomware_watch
    )

    credential_html = "".join(
        (
            "<li style='margin-bottom:7px'>"
            f"<strong>{html.escape(signal.confidence)}:</strong> "
            f'<a href="{html.escape(signal.link, quote=True)}">'
            f"{html.escape(signal.title)}</a> "
            f"<em>— {html.escape(signal.source)}</em></li>"
        )
        for signal in credential_watch
    )

    executive_news_html = "".join(
        (
            "<li style='margin-bottom:7px'>"
            + (
                "<strong>["
                + html.escape(", ".join(news_link.tags))
                + "]</strong> "
                if news_link.tags
                else ""
            )
            + f'<a href="{html.escape(news_link.link, quote=True)}">'
            + html.escape(news_link.title)
            + "</a>"
            + " <em>— "
            + html.escape(news_link.source)
            + "</em></li>"
        )
        for news_link in executive_news
    )

    special_html = (
        "".join(
            "<li>"
            + html.escape(
                " / ".join(
                    marker
                    for marker in (
                        "Zero-Day" if item.zero_day else "",
                        "CVSS 10.0" if item.cvss_score == 10.0 else "",
                    )
                    if marker
                )
            )
            + ": "
            + f'<a href="{html.escape(item.link, quote=True)}">'
            + html.escape(item.title)
            + "</a>"
            + " <em>— "
            + html.escape(item.source)
            + "</em></li>"
            for item in critical_special
        )
        or "<li>None identified in the reporting window.</li>"
    )

    sector_html = "".join(
        (
            "<li style='margin-bottom:8px'>"
            f"<strong>{html.escape(impact.sector)}:</strong> "
            f"{html.escape(impact.implication)} "
            f'<a href="{html.escape(impact.link, quote=True)}">'
            f"{html.escape(impact.headline)}</a> "
            f"<em>— {html.escape(impact.source)}</em>"
            "</li>"
        )
        for impact in sector_impacts
    )

    actions_html = "".join(
        f"<li>{html.escape(action)}</li>" for action in actions
    )

    governance_html = "".join(
        f"<li><strong>{html.escape(item.section)}:</strong> "
        f'<a href="{html.escape(item.link, quote=True)}">'
        f"{html.escape(item.title)}</a> "
        f"<em>— {html.escape(item.source)}</em></li>"
        for item in major_governance
    )

    upcoming_html = "".join(
        f"<li><strong>{html.escape(event['date'])}:</strong> "
        f"{html.escape(event['title'])}"
        + (
            f" — {html.escape(event.get('topic', ''))}"
            if event.get("topic")
            else ""
        )
        + (
            f' [<a href="{html.escape(event.get("source_url", ""), quote=True)}">'
            "source</a>]"
            if event.get("source_url")
            else ""
        )
        + "</li>"
        for event in upcoming_events
    )

    exposure_sections_html: list[str] = []

    for exposure_section in EXPOSURE_SECTION_ORDER:
        section_signals = exposure_grouped.get(
            exposure_section,
            [],
        )
        if not section_signals:
            continue

        exposure_sections_html.append(
            f"<h2 style='margin-top:32px'>"
            f"{html.escape(exposure_section)}</h2>"
        )
        exposure_sections_html.extend(
            render_exposure_html(signal)
            for signal in section_signals
        )

    detection_html = "".join(
        f"""
        <article style="
            border:1px solid #d0d7de;
            border-radius:8px;
            padding:16px;
            margin:0;
            background:#ffffff;
        ">
          <h3 style="margin-top:0">
            {html.escape(opportunity.title)}
          </h3>
          <p><strong>Detection opportunity:</strong>
             {html.escape(opportunity.detection)}</p>
          <p><strong>Data sources:</strong>
             {html.escape(opportunity.data_sources)}</p>
          <p><strong>MITRE ATT&amp;CK:</strong>
             {html.escape(opportunity.mitre)}</p>
          <p>
            <a href="{html.escape(opportunity.link, quote=True)}">
              Open supporting source
            </a>
            <em>— {html.escape(opportunity.source)}</em>
          </p>
        </article>
        <hr style="
            border:0;
            border-top:1px solid #b8bec5;
            margin:24px 0 28px 0;
            width:100%;
        ">
        """
        for opportunity in detection_opportunities
    )

    regional_html = "".join(
        (
            "<li style='margin-bottom:7px'>"
            f'<a href="{html.escape(link.link, quote=True)}">'
            f"{html.escape(link.title)}</a> "
            f"<em>— {html.escape(link.source)}</em></li>"
        )
        for link in regional_links
    )

    primary_sections_html: list[str] = []

    for section in primary_section_order:
        section_items = grouped.get(section, [])
        display_title = section_titles.get(section, section)

        if section == "SOC and Detection Engineering":
            if not section_items and not detection_opportunities:
                continue

            primary_sections_html.append(
                f"<h2 style='margin-top:32px'>"
                f"{html.escape(display_title)}</h2>"
            )
            primary_sections_html.append(detection_html)
            primary_sections_html.extend(
                render_item_html(item) for item in section_items
            )
            continue

        if section == "Scandinavia and Europe":
            if not section_items and not regional_links:
                continue

            primary_sections_html.append(
                f"<h2 style='margin-top:32px'>"
                f"{html.escape(display_title)}</h2>"
            )
            if regional_html:
                primary_sections_html.append(f"<ul>{regional_html}</ul>")
            primary_sections_html.extend(
                render_item_html(item) for item in section_items
            )
            continue

        if not section_items:
            continue

        primary_sections_html.append(
            f"<h2 style='margin-top:32px'>"
            f"{html.escape(display_title)}</h2>"
        )
        primary_sections_html.extend(
            render_item_html(item) for item in section_items
        )

    active_health = [
        health
        for health in source_health
        if health["status"] == "OK" and health["items"] > 0
    ]
    failed_health = [
        health
        for health in source_health
        if health["status"] != "OK"
    ]
    quiet_health_count = sum(
        1
        for health in source_health
        if health["status"] == "OK" and health["items"] == 0
    )

    health_html = "".join(
        (
            "<tr>"
            f"<td style='padding:4px 12px 4px 0'>"
            f"{html.escape(str(health['source']))}</td>"
            "<td style='padding:4px 12px'>Checked</td>"
            f"<td style='padding:4px 12px'>{health['items']}</td>"
            "<td style='padding:4px 0'>"
            f"{html.escape(str(health.get('detail', '')))}</td>"
            "</tr>"
        )
        for health in active_sources
    )

    if quiet_source_count:
        health_html += (
            "<tr>"
            "<td style='padding:4px 12px 4px 0' colspan='4'>"
            f"<em>{quiet_source_count} additional source(s) checked with "
            "no qualifying updates.</em>"
            "</td>"
            "</tr>"
        )

    health_html += "".join(
        (
            "<tr>"
            f"<td style='padding:4px 12px 4px 0'>"
            f"{html.escape(str(health['source']))}</td>"
            "<td style='padding:4px 12px'>Failed</td>"
            "<td style='padding:4px 12px'>—</td>"
            f"<td style='padding:4px 0'>"
            f"{html.escape(str(health.get('detail', '')))}</td>"
            "</tr>"
        )
        for health in failed_sources
    )

    warnings_html = ""
    if warnings:
        warnings_html = (
            "<h2>Source Warnings</h2><ul>"
            + "".join(
                f"<li>{html.escape(warning)}</li>" for warning in warnings
            )
            + "</ul>"
        )

    badge = (
        f'<span style="display:inline-block;'
        f'background:{status["colour"]};'
        f'color:{status["text_colour"]};'
        f'font-weight:700;padding:7px 12px;'
        f'border-radius:5px;">'
        f'{html.escape(status["display"])}</span>'
    )
    enterprise_badge = (
        f'<span style="display:inline-block;'
        f'background:{enterprise_status["colour"]};'
        f'color:{enterprise_status["text_colour"]};'
        f'font-weight:700;padding:7px 12px;'
        f'border-radius:5px;">'
        f'{html.escape(enterprise_status["display"])}</span>'
    )

    monitored_html = ""
    if monitored_references:
        monitored_html = (
            "<p><strong>Monitored references:</strong> "
            + html.escape(", ".join(monitored_references))
            + "</p>"
        )

    relevant_news_block = ""
    if executive_news_html:
        relevant_news_block = (
            "<h3>Relevant Cyber News</h3>"
            "<p style='margin-top:0'>"
            "One-line discovery links filtered for technology, geography, "
            "customer-sector and exposure relevance. Primary sources remain "
            "authoritative for risk, compliance and remediation."
            "</p>"
            f"<ul>{executive_news_html}</ul>"
        )

    top_exposure_block = ""
    if top_exposure_html:
        top_exposure_block = (
            "<h3>Dark Web and Exposure Highlights</h3>"
            f"<ul>{top_exposure_html}</ul>"
        )

    ransomware_block = ""
    if ransomware_html:
        ransomware_block = (
            "<h3>Ransomware and Extortion Watch</h3>"
            f"<ul>{ransomware_html}</ul>"
        )

    credential_block = ""
    if credential_html:
        credential_block = (
            "<h3>Credential and Stealer Exposure</h3>"
            f"<ul>{credential_html}</ul>"
        )

    sector_block = ""
    if sector_html:
        sector_block = (
            "<h3>Customer and Sector Advisory Impact</h3>"
            f"<ul>{sector_html}</ul>"
        )

    governance_block = ""
    if governance_html:
        governance_block = (
            "<h3>Relevant Compliance and Governance Changes</h3>"
            f"<ul>{governance_html}</ul>"
        )

    upcoming_block = ""
    if upcoming_html:
        upcoming_block = (
            f"<h3>Going Live Today or Within {upcoming_days} Days</h3>"
            f"<ul>{upcoming_html}</ul>"
        )

    html_report = f"""
    <!doctype html>
    <html lang="en">
    <body style="
        font-family:Arial,Helvetica,sans-serif;
        line-height:1.5;
        color:#1f2328;
        max-width:900px;
        margin:20px auto;
        padding:0 20px;
    ">
      <h1>{html.escape(report_title)}</h1>

      <p>
        <strong>Reporting window:</strong>
        previous {lookback_hours} hours<br>
        <strong>Security advisory level:</strong> {badge}<br>
        <strong>Enterprise cyber threat level:</strong>
        {enterprise_badge}<br>
        <strong>Primary security developments:</strong> {len(items)}<br>
        <strong>Exposure and dark-web signals:</strong>
        {len(exposure_signals)}<br>
        <strong>Relevant discovery links:</strong> {len(executive_news)}
      </p>

      <h2>Security Advisory Overview</h2>

      <h3>Priority Security Advisories</h3>
      <ol>{top_advisories_html}</ol>

      {top_exposure_block}
      {ransomware_block}
      {credential_block}
      {relevant_news_block}

      <h3>Zero-Day and CVSS 10.0</h3>
      <ul>{special_html}</ul>

      {sector_block}
      {monitored_html}

      <h3>Recommended Security Advisory Actions</h3>
      <ul>{actions_html}</ul>

      {governance_block}
      {upcoming_block}

      {''.join(exposure_sections_html)}
      {''.join(primary_sections_html)}

      <h2>Source Coverage</h2>
      <table style="
          border-collapse:collapse;
          width:100%;
          margin-bottom:24px;
      ">
        <thead>
          <tr style="text-align:left;border-bottom:1px solid #b8bec5">
            <th style="padding:4px 12px 4px 0">Source</th>
            <th style="padding:4px 12px">Status</th>
            <th style="padding:4px 12px">Items</th>
            <th style="padding:4px 0">Detail</th>
          </tr>
        </thead>
        <tbody>{health_html}</tbody>
      </table>

      <h2>Security Advisory and CISO Watch List</h2>
      <ul>
        <li>Credential and stealer-log exposure affecting monitored domains.</li>
        <li>Ransomware claims involving customers, suppliers or key sectors.</li>
        <li>Initial-access listings targeting remote access or cloud identity.</li>
        <li>Leaks containing credentials, tokens, source code or customer data.</li>
        <li>Brand impersonation, typosquatting and AiTM phishing.</li>
        <li>New CISA KEV additions and active exploitation.</li>
        <li>Microsoft, Azure, Entra ID and Microsoft 365 attacks.</li>
        <li>Fortinet, HPE and Aruba advisories.</li>
        <li>OT, energy, oil and gas, and critical-infrastructure targeting.</li>
        <li>Scandinavian and European cybercrime developments.</li>
      </ul>

      <h2>Handling Note</h2>
      <p>
        Dark-web and criminal-ecosystem claims may be incomplete, misleading
        or intentionally false. Treat victim claims as reported intelligence
        until corroborated by the affected organisation, law enforcement or
        another reliable source. This briefing does not connect to onion
        services, criminal forums, leak sites or stolen-data repositories.
      </p>

      {warnings_html}
    </body>
    </html>
    """

    return "\n".join(text), html_report


def send_email(
    username: str,
    password: str,
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> None:
    message = EmailMessage()
    message["From"] = username
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    context = ssl.create_default_context()

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=60) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login(username, password.replace(" ", ""))
        refused = smtp.send_message(message)

        if refused:
            raise RuntimeError(f"SMTP refused recipients: {refused}")


def main() -> int:
    try:
        username = required("GMAIL_USERNAME")
        password = required("GMAIL_APP_PASSWORD")
        recipient = required("EMAIL_TO")

        lookback_hours = reporting_window_hours()
        max_items = integer_setting(
            "NEWS_MAX_ITEMS",
            default=40,
            minimum=5,
            maximum=80,
        )
        kev_days = kev_lookback_days(lookback_hours)
        upcoming_days = integer_setting(
            "UPCOMING_GOVERNANCE_DAYS",
            default=14,
            minimum=1,
            maximum=90,
        )
        exposure_max = integer_setting(
            "EXPOSURE_MAX_ITEMS",
            default=20,
            minimum=5,
            maximum=60,
        )
        monitored_brands = csv_setting("MONITORED_BRANDS")
        monitored_domains = csv_setting("MONITORED_DOMAINS")
        hibp_api_key = os.getenv("HIBP_API_KEY", "").strip()

        local_now = datetime.now(OSLO_TIMEZONE)
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=lookback_hours
        )

        print(
            f"Reporting window: {lookback_hours} hours "
            f"(Europe/Oslo weekday={local_now.strftime('%A')})"
        )

        collected: list[Item] = []
        exposure_candidates: list[ExposureSignal] = []
        warnings: list[str] = []
        source_health: list[dict[str, Any]] = []

        try:
            kev_items = fetch_kev(kev_days)
            collected.extend(kev_items)
            source_health.append(
                {
                    "source": "CISA KEV",
                    "status": "OK",
                    "items": len(kev_items),
                    "detail": "",
                }
            )
            print(f"CISA KEV: {len(kev_items)} item(s)")
        except Exception as error:
            warning = f"CISA KEV: {type(error).__name__}: {error}"
            warnings.append(warning)
            source_health.append(
                {
                    "source": "CISA KEV",
                    "status": "FAILED",
                    "items": 0,
                    "detail": f"{type(error).__name__}: {error}",
                }
            )
            print(f"WARNING: {warning}", file=sys.stderr)

        try:
            nvd_recent = fetch_recent_nvd_coverage(cutoff)
            collected.extend(nvd_recent)
            source_health.append(
                {
                    "source": "NVD recent priority-vendor CVEs",
                    "status": "OK",
                    "items": len(nvd_recent),
                    "detail": "",
                }
            )
            print(
                "NVD recent priority-vendor CVEs: "
                f"{len(nvd_recent)} item(s)"
            )
        except Exception as error:
            warning = (
                "NVD recent priority-vendor CVEs: "
                f"{type(error).__name__}: {error}"
            )
            warnings.append(warning)
            source_health.append(
                {
                    "source": "NVD recent priority-vendor CVEs",
                    "status": "FAILED",
                    "items": 0,
                    "detail": f"{type(error).__name__}: {error}",
                }
            )
            print(f"WARNING: {warning}", file=sys.stderr)

        for source in RSS_SOURCES:
            try:
                items = fetch_rss(source, cutoff)
                collected.extend(items)
                source_health.append(
                    {
                        "source": source.name,
                        "status": "OK",
                        "items": len(items),
                        "detail": "",
                    }
                )
                print(f"{source.name}: {len(items)} item(s)")
            except Exception as error:
                warning = (
                    f"{source.name}: "
                    f"{type(error).__name__}: {error}"
                )
                warnings.append(warning)
                source_health.append(
                    {
                        "source": source.name,
                        "status": "FAILED",
                        "items": 0,
                        "detail": f"{type(error).__name__}: {error}",
                    }
                )
                print(f"WARNING: {warning}", file=sys.stderr)

        for source in HTML_SOURCES:
            try:
                items = fetch_html(source, cutoff)
                collected.extend(items)
                source_health.append(
                    {
                        "source": source.name,
                        "status": "OK",
                        "items": len(items),
                        "detail": "",
                    }
                )
                print(f"{source.name}: {len(items)} item(s)")
            except Exception as error:
                warning = (
                    f"{source.name}: "
                    f"{type(error).__name__}: {error}"
                )
                warnings.append(warning)
                source_health.append(
                    {
                        "source": source.name,
                        "status": "FAILED",
                        "items": 0,
                        "detail": f"{type(error).__name__}: {error}",
                    }
                )
                print(f"WARNING: {warning}", file=sys.stderr)

        try:
            hibp_signals = fetch_hibp_breaches(cutoff)
            exposure_candidates.extend(hibp_signals)
            source_health.append(
                {
                    "source": "Have I Been Pwned breach catalogue",
                    "status": "OK",
                    "items": len(hibp_signals),
                    "detail": "Public breach metadata",
                }
            )
            print(
                "Have I Been Pwned breach catalogue: "
                f"{len(hibp_signals)} new exposure signal(s)"
            )
        except Exception as error:
            warning = (
                "Have I Been Pwned breach catalogue: "
                f"{type(error).__name__}: {error}"
            )
            warnings.append(warning)
            source_health.append(
                {
                    "source": "Have I Been Pwned breach catalogue",
                    "status": "FAILED",
                    "items": 0,
                    "detail": f"{type(error).__name__}: {error}",
                }
            )
            print(f"WARNING: {warning}", file=sys.stderr)

        if monitored_domains and hibp_api_key:
            try:
                domain_signals = fetch_hibp_domain_exposure(
                    monitored_domains,
                    hibp_api_key,
                )
                exposure_candidates.extend(domain_signals)
                source_health.append(
                    {
                        "source": "Have I Been Pwned domain search",
                        "status": "OK",
                        "items": len(domain_signals),
                        "detail": (
                            f"{len(monitored_domains)} verified domain(s) "
                            "configured"
                        ),
                    }
                )
                print(
                    "Have I Been Pwned domain search: "
                    f"{len(domain_signals)} domain exposure signal(s)"
                )
            except Exception as error:
                warning = (
                    "Have I Been Pwned domain search: "
                    f"{type(error).__name__}: {error}"
                )
                warnings.append(warning)
                source_health.append(
                    {
                        "source": "Have I Been Pwned domain search",
                        "status": "FAILED",
                        "items": 0,
                        "detail": f"{type(error).__name__}: {error}",
                    }
                )
                print(f"WARNING: {warning}", file=sys.stderr)

        all_items = deduplicate(collected)

        executive_news_candidates: list[NewsLink] = []

        for news_source in EXECUTIVE_NEWS_RSS:
            try:
                links = fetch_executive_news_rss(
                    news_source,
                    cutoff,
                )
                executive_news_candidates.extend(links)
                source_health.append(
                    {
                        "source": news_source["name"],
                        "status": "OK",
                        "items": len(links),
                        "detail": "Executive news discovery",
                    }
                )
                print(
                    f"{news_source['name']}: "
                    f"{len(links)} relevant news link(s)"
                )
            except Exception as error:
                warning = (
                    f"{news_source['name']}: "
                    f"{type(error).__name__}: {error}"
                )
                warnings.append(warning)
                source_health.append(
                    {
                        "source": news_source["name"],
                        "status": "FAILED",
                        "items": 0,
                        "detail": f"{type(error).__name__}: {error}",
                    }
                )
                print(f"WARNING: {warning}", file=sys.stderr)

        for news_source in EXECUTIVE_NEWS_HTML:
            try:
                links = fetch_executive_news_html(
                    news_source,
                    cutoff,
                )
                executive_news_candidates.extend(links)
                source_health.append(
                    {
                        "source": news_source["name"],
                        "status": "OK",
                        "items": len(links),
                        "detail": "Executive news discovery",
                    }
                )
                print(
                    f"{news_source['name']}: "
                    f"{len(links)} relevant news link(s)"
                )
            except Exception as error:
                warning = (
                    f"{news_source['name']}: "
                    f"{type(error).__name__}: {error}"
                )
                warnings.append(warning)
                source_health.append(
                    {
                        "source": news_source["name"],
                        "status": "FAILED",
                        "items": 0,
                        "detail": f"{type(error).__name__}: {error}",
                    }
                )
                print(f"WARNING: {warning}", file=sys.stderr)

        enrich_nvd(all_items, warnings)

        all_items.sort(
            key=lambda item: (item.score, item.published),
            reverse=True,
        )
        items = select_final_items(all_items, max_items)

        executive_news_max = integer_setting(
            "EXEC_NEWS_MAX_ITEMS",
            default=10,
            minimum=1,
            maximum=20,
        )
        executive_news = select_executive_news(
            executive_news_candidates,
            items,
            executive_news_max,
        )

        exposure_candidates.extend(
            build_open_source_exposure_signals(
                items,
                executive_news,
                monitored_brands,
                monitored_domains,
                max_items=exposure_max,
            )
        )
        exposure_signals = deduplicate_exposure_signals(
            exposure_candidates,
            exposure_max,
        )

        sector_impacts = build_sector_impacts(
            items,
            executive_news,
            max_items=5,
        )
        detection_opportunities = build_detection_opportunities(
            items,
            max_items=6,
        )
        regional_links = build_regional_links(
            items,
            executive_news,
            max_items=8,
        )

        today = local_now.date()
        configured_events = load_configured_governance_events(
            today,
            upcoming_days,
            warnings,
        )
        detected_events = detect_governance_go_live_events(
            all_items,
            today,
            upcoming_days,
        )
        upcoming_events = deduplicate_governance_events(
            configured_events + detected_events
        )

        text_body, html_body = render_report(
            items,
            warnings,
            lookback_hours,
            upcoming_events,
            upcoming_days,
            source_health,
            executive_news,
            sector_impacts,
            detection_opportunities,
            regional_links,
            exposure_signals,
            monitored_brands,
            monitored_domains,
        )

        status = advisory_status(items, exposure_signals)
        enterprise_status = defcon_status(items)
        subject = (
            f"{status['display']} Advisory | "
            f"{enterprise_status['display']} | "
            f"{BRIEF_NAME} v{BRIEF_VERSION}"
        )

        send_email(
            username,
            password,
            recipient,
            subject,
            text_body,
            html_body,
        )

        print(
            f"Briefing sent: {status['display']}, "
            f"{len(items)} item(s), "
            f"{len(upcoming_events)} upcoming event(s), "
            f"{len(executive_news)} relevant news link(s), "
            f"{len(exposure_signals)} exposure signal(s), "
            f"{len(sector_impacts)} sector impact(s), "
            f"{len(detection_opportunities)} detection opportunity(s), "
            f"{len(regional_links)} regional link(s), "
            f"{len(warnings)} warning(s)."
        )

        return 0

    except Exception as error:
        print(
            f"Pipeline failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
