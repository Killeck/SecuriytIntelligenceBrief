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
from urllib.parse import urljoin
from urllib.request import Request, urlopen

import feedparser
import requests
from bs4 import BeautifulSoup, Tag
from dateutil import parser as date_parser


USER_AGENT = (
    "security-intelligence-brief/1.1 "
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
    "Nordic Impact",
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
        name="CrowdStrike Blog",
        vendor="CrowdStrike",
        url="https://www.crowdstrike.com/en-us/blog/feed/",
        source_type="rss",
        base_score=24,
        section="Threat Intelligence",
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
        name="HPE Networking Security Advisories",
        vendor="HPE",
        url=(
            "https://www.hpe.com/us/en/networking/"
            "security-advisories.html"
        ),
        source_type="html",
        base_score=38,
        section="HPE",
        selectors=(
            "main a[href]",
            "article a[href]",
            "table a[href]",
            "h2 a[href]",
            "h3 a[href]",
        ),
        include_patterns=("hpe.com",),
        exclude_patterns=(
            "/products/",
            "/services/",
            "/contact/",
            "/events/",
            "privacy",
            "terms",
        ),
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
        topic_keywords=(
            "sikkerhetsloven",
            "nis2",
            "digital sikkerhet",
            "cybersikkerhet",
            "nasjonal sikkerhet",
            "sikkerhetsstyring",
            "risiko",
        ),
    ),
    Source(
        name="Norwegian Government NIS2 Search",
        vendor="Norwegian Government",
        url="https://www.regjeringen.no/no/sok/id86008/?term=NIS2",
        source_type="html",
        base_score=42,
        section="Norwegian Security Governance",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
            "main a[href]",
        ),
        include_patterns=("regjeringen.no",),
        exclude_patterns=(
            "#",
            "/tema/",
            "/departementer/",
            "kontakt",
            "personvern",
        ),
        max_candidates=40,
        locale="no",
        topic_keywords=(
            "nis2",
            "digitalsikkerhetsloven",
            "cybersikkerhetsloven",
            "nettverks- og informasjonssystemer",
        ),
    ),
    Source(
        name="Norwegian Government Security Act Search",
        vendor="Norwegian Government",
        url=(
            "https://www.regjeringen.no/no/sok/"
            "id86008/?term=sikkerhetsloven"
        ),
        source_type="html",
        base_score=42,
        section="Norwegian Security Governance",
        selectors=(
            "main h2 a[href]",
            "main h3 a[href]",
            "article a[href]",
            "main a[href]",
        ),
        include_patterns=("regjeringen.no",),
        exclude_patterns=(
            "#",
            "/tema/",
            "/departementer/",
            "kontakt",
            "personvern",
        ),
        max_candidates=40,
        locale="no",
        topic_keywords=(
            "sikkerhetsloven",
            "nasjonal sikkerhet",
            "grunnleggende nasjonale funksjoner",
            "sikkerhetsklarering",
        ),
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
        return "HPE"

    if source.vendor == "Microsoft":
        return "Microsoft"

    if category == "Regulatory and compliance":
        return "Compliance"

    if category == "Standards and frameworks":
        return "Standards"

    if source.section == "Norwegian Security Governance":
        return "Norwegian Security Governance"

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
        action=ACTIONS[category],
        why=WHY[category],
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

    selected: list[Item] = []
    seen: set[str] = set()

    for item in mandatory + ordered:
        key = item.link.lower().rstrip("/")

        if key in seen:
            continue

        if len(selected) >= max_items and item not in mandatory:
            break

        selected.append(item)
        seen.add(key)

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

    if any(item.section in {"Fortinet", "HPE", "Other Vendor Advisories"} for item in items):
        actions.append(
            "Check the vendor advisory section against deployed products and "
            "current patch or firmware levels."
        )

    if any(item.section == "Nordic Impact" for item in items):
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
        padding:4px 0 0 0;
        margin:0;
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
        margin:24px 0;
        width:100%;
    ">
    """


def render_report(
    items: list[Item],
    warnings: list[str],
    lookback_hours: int,
    upcoming_events: list[dict[str, str]],
    upcoming_days: int,
) -> tuple[str, str]:
    status = defcon_status(items)
    actions = immediate_actions(items)

    critical_special = [
        item
        for item in items
        if item.zero_day or item.cvss_score == 10.0
    ]
    top = items[:5]
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

    section_order = (
        "Known Exploited Vulnerabilities",
        "Microsoft",
        "Fortinet",
        "HPE",
        "Other Vendor Advisories",
        "Cloud and Identity",
        "Threat Intelligence",
        "Vulnerability Research",
        "Norwegian Security Governance",
        "Compliance",
        "Standards",
        "GRC",
        "Nordic Impact",
    )

    grouped: dict[str, list[Item]] = {
        section: [] for section in section_order
    }

    for item in items:
        grouped.setdefault(item.section, []).append(item)

    monitored_topics = ", ".join(MONITORED_GOVERNANCE_TOPICS)

    text = [
        "Daily CISO Cybersecurity Briefing",
        "=" * 36,
        "",
        f"Reporting window: previous {lookback_hours} hours",
        f"Overall threat level: {status['display']}",
        f"Included developments: {len(items)}",
        f"Governance horizon: today through the next {upcoming_days} days",
        "",
        "Executive Summary",
        "-----------------",
        "",
        "Top developments",
    ]

    if top:
        for index, item in enumerate(top, start=1):
            text.append(
                f"{index}. [{priority(item)}] {item.title} "
                f"— {item.source}"
            )
    else:
        text.append("No qualifying developments were collected.")

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
                f"— {item.source}"
            )
    else:
        text.append(
            "No explicit zero-day or CVSS 10.0 item was identified "
            "during the reporting window."
        )

    text.extend(["", "Major compliance, standards and governance changes"])

    if major_governance:
        for item in major_governance:
            text.append(
                f"- [{item.section}] {item.title} — {item.source}"
            )
    else:
        text.append(
            "No material compliance, standards or governance change "
            "was collected during the reporting window."
        )

    text.extend(
        [
            "",
            f"Going live today or within {upcoming_days} days",
        ]
    )

    if upcoming_events:
        for event in upcoming_events:
            text.append(
                f"- {event['date']}: {event['title']} "
                f"({event.get('topic') or event.get('source')})"
            )
    else:
        text.append(
            "No configured or source-detected effective date falls "
            f"within the next {upcoming_days} days."
        )

    text.extend(
        [
            "",
            f"Monitored governance topics: {monitored_topics}",
            "",
            "Immediate actions",
        ]
    )

    for action in actions:
        text.append(f"- {action}")

    for section in section_order:
        section_items = grouped.get(section, [])

        text.extend(["", section, "=" * len(section)])

        if not section_items:
            text.append(
                "No qualifying updates were collected for this section "
                "during the reporting window."
            )
            continue

        for number, item in enumerate(section_items, start=1):
            text.extend(render_item_text(item, number))

    text.extend(
        [
            "",
            "Upcoming Compliance, Standards and Governance",
            "---------------------------------------------",
        ]
    )

    if upcoming_events:
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
    else:
        text.append(
            f"No tracked event falls between today and "
            f"{upcoming_days} days from today."
        )

    text.extend(
        [
            "",
            "CISO Watch List",
            "---------------",
            "- New CISA KEV additions and confirmation of active exploitation.",
            "- Explicit zero-days and vulnerabilities with CVSS 10.0.",
            "- Internet-facing firewall, VPN, identity, and remote-access flaws.",
            "- Microsoft identity, Azure, and Microsoft 365 attack activity.",
            "- Fortinet and HPE security advisories affecting deployed estates.",
            "- Ransomware access trends and destructive malware developments.",
            "- Software supply-chain compromise and exposed build credentials.",
            "- NSM warnings and changes relating to Sikkerhetsloven.",
            "- Norwegian and EEA NIS2 implementation changes and deadlines.",
            "- ISO/IEC 27001, ISO 50001, ISO 9001, ISO 14001 and "
            "ISO/IEC 33000-series developments.",
            "- Compliance deadlines, regulatory interpretation, and audit duties.",
            "- GRC changes affecting risk ownership and assurance evidence.",
        ]
    )

    if warnings:
        text.extend(["", "Source warnings", "---------------"])
        text.extend(f"- {warning}" for warning in warnings)

    top_html = (
        "".join(
            f"<li><strong>{priority(item)}:</strong> "
            f"{html.escape(item.title)} "
            f"<em>— {html.escape(item.source)}</em></li>"
            for item in top
        )
        or "<li>No qualifying developments were collected.</li>"
    )

    special_html = (
        "".join(
            "<li>"
            + html.escape(
                " / ".join(
                    marker
                    for marker in (
                        "Zero-Day" if item.zero_day else "",
                        "CVSS 10.0"
                        if item.cvss_score == 10.0
                        else "",
                    )
                    if marker
                )
            )
            + ": "
            + html.escape(item.title)
            + " <em>— "
            + html.escape(item.source)
            + "</em></li>"
            for item in critical_special
        )
        or (
            "<li>No explicit zero-day or CVSS 10.0 item was identified "
            "during the reporting window.</li>"
        )
    )

    governance_html = (
        "".join(
            f"<li><strong>{html.escape(item.section)}:</strong> "
            f"{html.escape(item.title)} "
            f"<em>— {html.escape(item.source)}</em></li>"
            for item in major_governance
        )
        or (
            "<li>No material compliance, standards or governance change "
            "was collected during the reporting window.</li>"
        )
    )

    upcoming_html = (
        "".join(
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
        or (
            "<li>No configured or source-detected effective date falls "
            f"within the next {upcoming_days} days.</li>"
        )
    )

    actions_html = "".join(
        f"<li>{html.escape(action)}</li>" for action in actions
    )

    sections_html: list[str] = []

    for section in section_order:
        section_items = grouped.get(section, [])

        sections_html.append(
            f"<h2 style='margin-top:32px'>{html.escape(section)}</h2>"
        )

        if not section_items:
            sections_html.append(
                "<p><em>No qualifying updates were collected for this "
                "section during the reporting window.</em></p>"
            )
            continue

        sections_html.extend(
            render_item_html(item) for item in section_items
        )

    warnings_html = ""

    if warnings:
        warnings_html = (
            "<h2>Source warnings</h2><ul>"
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
      <h1>Daily CISO Cybersecurity Briefing</h1>

      <p>
        <strong>Reporting window:</strong>
        previous {lookback_hours} hours<br>
        <strong>Overall threat level:</strong> {badge}<br>
        <strong>Included developments:</strong> {len(items)}<br>
        <strong>Governance horizon:</strong>
        today through the next {upcoming_days} days
      </p>

      <h2>Executive Summary</h2>

      <h3>Top developments</h3>
      <ol>{top_html}</ol>

      <h3>Zero-Day and CVSS 10.0</h3>
      <ul>{special_html}</ul>

      <h3>Major compliance, standards and governance changes</h3>
      <ul>{governance_html}</ul>

      <h3>Going live today or within {upcoming_days} days</h3>
      <ul>{upcoming_html}</ul>

      <p>
        <strong>Monitored governance topics:</strong>
        {html.escape(monitored_topics)}
      </p>

      <h2>Immediate actions</h2>
      <ul>{actions_html}</ul>

      {''.join(sections_html)}

      <h2>Upcoming Compliance, Standards and Governance</h2>
      <ul>{upcoming_html}</ul>

      <h2>CISO Watch List</h2>
      <ul>
        <li>New CISA KEV additions and active exploitation.</li>
        <li>Explicit zero-days and CVSS 10.0 vulnerabilities.</li>
        <li>Internet-facing firewall, VPN, and identity flaws.</li>
        <li>Microsoft identity, Azure, and Microsoft 365 attacks.</li>
        <li>Fortinet and HPE security advisories.</li>
        <li>Ransomware access and destructive malware trends.</li>
        <li>Software supply-chain and build credential compromise.</li>
        <li>NSM, Sikkerhetsloven and Norwegian NIS2 changes.</li>
        <li>
          ISO/IEC 27001, ISO 50001, ISO 9001, ISO 14001 and
          ISO/IEC 33000-series developments.
        </li>
        <li>Compliance deadlines and regulatory implementation changes.</li>
        <li>Governance, risk, audit, and assurance developments.</li>
      </ul>

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

        local_now = datetime.now(OSLO_TIMEZONE)
        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=lookback_hours
        )

        print(
            f"Reporting window: {lookback_hours} hours "
            f"(Europe/Oslo weekday={local_now.strftime('%A')})"
        )

        collected: list[Item] = []
        warnings: list[str] = []

        try:
            kev_items = fetch_kev(kev_days)
            collected.extend(kev_items)
            print(f"CISA KEV: {len(kev_items)} item(s)")
        except Exception as error:
            warning = f"CISA KEV: {type(error).__name__}: {error}"
            warnings.append(warning)
            print(f"WARNING: {warning}", file=sys.stderr)

        for source in RSS_SOURCES:
            try:
                items = fetch_rss(source, cutoff)
                collected.extend(items)
                print(f"{source.name}: {len(items)} item(s)")
            except Exception as error:
                warning = (
                    f"{source.name}: "
                    f"{type(error).__name__}: {error}"
                )
                warnings.append(warning)
                print(f"WARNING: {warning}", file=sys.stderr)

        for source in HTML_SOURCES:
            try:
                items = fetch_html(source, cutoff)
                collected.extend(items)
                print(f"{source.name}: {len(items)} item(s)")
            except Exception as error:
                warning = (
                    f"{source.name}: "
                    f"{type(error).__name__}: {error}"
                )
                warnings.append(warning)
                print(f"WARNING: {warning}", file=sys.stderr)

        all_items = deduplicate(collected)

        enrich_nvd(all_items, warnings)

        all_items.sort(
            key=lambda item: (item.score, item.published),
            reverse=True,
        )
        items = select_final_items(all_items, max_items)

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
        )

        status = defcon_status(items)
        subject = (
            f"{status['display']} | Daily CISO Brief | "
            f"{len(items)} development(s)"
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
