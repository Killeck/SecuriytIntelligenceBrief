from __future__ import annotations

import calendar
import html
import json
import os
import re
import smtplib
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
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
    cvss: str = "Not available"
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
        section="Threat Intelligence",
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
        base_score=35,
        section="Vendor Advisories",
        selectors=(
            "a[href*='/psirt/FG-IR-']",
            "a[href*='/psirt/fg-ir-']",
        ),
        include_patterns=("/psirt/",),
        max_candidates=35,
    ),
    Source(
        name="Apple Security Releases",
        vendor="Apple",
        url="https://support.apple.com/en-us/100100",
        source_type="html",
        base_score=30,
        section="Vendor Advisories",
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

    if source.section == "Vendor Advisories":
        if source.vendor == "Apple":
            return "Security update", 15
        return "Vendor advisory", 15

    if source.section == "Nordic Impact":
        return "Nordic warning", 18

    return "General security", 0


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

    exploited = category == "Active exploitation"
    ransomware = category == "Ransomware"

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
        section=source.section,
        category=category,
        score=score,
        cves=cves,
        exploited=exploited,
        ransomware=ransomware,
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
    if item.kev or item.score >= 95:
        return "Critical"
    if item.score >= 70:
        return "High"
    if item.score >= 45:
        return "Medium"
    return "Monitor"


def overall_threat_level(items: list[Item]) -> str:
    if any(item.kev and item.ransomware for item in items):
        return "High"

    if any(item.kev or item.score >= 95 for item in items):
        return "Elevated"

    if any(
        item.category
        in {
            "Active exploitation",
            "Ransomware",
            "Nation-state activity",
        }
        for item in items
    ):
        return "Elevated"

    return "Guarded" if items else "Low"


def immediate_actions(items: list[Item]) -> list[str]:
    actions: list[str] = []

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

    if any(item.section == "Vendor Advisories" for item in items):
        actions.append(
            "Check the vendor advisory section against deployed products and "
            "current patch or firmware levels."
        )

    if any(item.section == "Nordic Impact" for item in items):
        actions.append(
            "Assess the NSM warning against Norwegian operations and customer "
            "environments."
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

    return [
        "",
        f"{number}. {item.title}",
        "-" * 72,
        f"Source: {item.source}",
        f"Published: {item.published.strftime('%Y-%m-%d %H:%M UTC')}",
        f"Category: {item.category}",
        f"Risk: {priority(item)}",
        f"CVEs: {cves}",
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

    return f"""
    <article style="
        border:1px solid #d0d7de;
        border-radius:8px;
        padding:18px;
        margin:0 0 16px 0;
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
    """


def render_report(
    items: list[Item],
    warnings: list[str],
    lookback_hours: int,
) -> tuple[str, str]:
    level = overall_threat_level(items)
    top = items[:5]
    actions = immediate_actions(items)

    section_order = (
        "Known Exploited Vulnerabilities",
        "Vendor Advisories",
        "Cloud and Identity",
        "Threat Intelligence",
        "Vulnerability Research",
        "Nordic Impact",
    )

    grouped: dict[str, list[Item]] = {
        section: [] for section in section_order
    }

    for item in items:
        grouped.setdefault(item.section, []).append(item)

    text = [
        "Daily CISO Cybersecurity Briefing",
        "=" * 36,
        "",
        f"Reporting window: previous {lookback_hours} hours",
        f"Overall threat level: {level}",
        f"Included developments: {len(items)}",
        "",
        "Executive Summary",
        "-----------------",
    ]

    if top:
        for index, item in enumerate(top, start=1):
            text.append(
                f"{index}. [{priority(item)}] {item.title} "
                f"— {item.source}"
            )
    else:
        text.append("No qualifying developments were collected.")

    text.extend(["", "Immediate actions"])

    for action in actions:
        text.append(f"- {action}")

    for section in section_order:
        section_items = grouped.get(section, [])

        if not section_items:
            continue

        text.extend(["", section, "=" * len(section)])

        for number, item in enumerate(section_items, start=1):
            text.extend(render_item_text(item, number))

    text.extend(
        [
            "",
            "CISO Watch List",
            "---------------",
            "- New CISA KEV additions and confirmation of active exploitation.",
            "- Internet-facing firewall, VPN, identity, and remote-access flaws.",
            "- Microsoft identity, Azure, and Microsoft 365 attack activity.",
            "- Ransomware access trends and destructive malware developments.",
            "- Software supply-chain compromise and exposed build credentials.",
            "- Nordic authority warnings affecting critical infrastructure.",
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

    actions_html = "".join(
        f"<li>{html.escape(action)}</li>" for action in actions
    )

    sections_html: list[str] = []

    for section in section_order:
        section_items = grouped.get(section, [])

        if not section_items:
            continue

        sections_html.append(f"<h2>{html.escape(section)}</h2>")
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
        <strong>Overall threat level:</strong> {level}<br>
        <strong>Included developments:</strong> {len(items)}
      </p>

      <h2>Executive Summary</h2>
      <ol>{top_html}</ol>

      <h2>Immediate actions</h2>
      <ul>{actions_html}</ul>

      {''.join(sections_html)}

      <h2>CISO Watch List</h2>
      <ul>
        <li>New CISA KEV additions and active exploitation.</li>
        <li>Internet-facing firewall, VPN, and identity flaws.</li>
        <li>Microsoft identity, Azure, and Microsoft 365 attacks.</li>
        <li>Ransomware access and destructive malware trends.</li>
        <li>Software supply-chain and build credential compromise.</li>
        <li>Nordic warnings affecting critical infrastructure.</li>
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

        lookback_hours = integer_setting(
            "NEWS_LOOKBACK_HOURS",
            default=168,
            minimum=1,
            maximum=720,
        )
        max_items = integer_setting(
            "NEWS_MAX_ITEMS",
            default=25,
            minimum=5,
            maximum=60,
        )
        kev_lookback_days = integer_setting(
            "KEV_LOOKBACK_DAYS",
            default=7,
            minimum=1,
            maximum=365,
        )

        cutoff = datetime.now(timezone.utc) - timedelta(
            hours=lookback_hours
        )

        collected: list[Item] = []
        warnings: list[str] = []

        try:
            kev_items = fetch_kev(kev_lookback_days)
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

        items = deduplicate(collected)
        items.sort(
            key=lambda item: (item.score, item.published),
            reverse=True,
        )
        items = items[:max_items]

        text_body, html_body = render_report(
            items,
            warnings,
            lookback_hours,
        )

        subject = (
            f"Daily CISO Brief: {overall_threat_level(items)} — "
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
            f"Combined briefing sent with {len(items)} item(s) "
            f"and {len(warnings)} source warning(s)."
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
