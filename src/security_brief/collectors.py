# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Network collectors and NVD enrichment.

Each function returns normalised model objects and raises on source-level
failure. Orchestration owns isolation, health reporting and retry policy.
"""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import feedparser
import requests
from bs4 import BeautifulSoup, Tag
from dateutil import parser as date_parser

from .analysis import build_item, build_news_link
from .http_client import get as http_get
from .config import (
    CISA_KEV_CATALOGUE,
    CISA_KEV_FEED,
    FIRST_EPSS_API,
    HIBP_BREACHED_DOMAIN_API,
    HIBP_BREACHES_API,
    HIBP_DASHBOARD,
    HIBP_PWNED_WEBSITES,
    MSRC_CVRF_API,
    NVD_CVE_API,
    USER_AGENT,
)
from .rules import ACTIONS, NVD_RECENT_COVERAGE, SENSITIVE_DATA_CLASSES, WHY
from .models import ExposureSignal, Item, NewsLink, Source
from .utils import (
    absolute_url,
    clean_text,
    ensure_utc,
    feed_entry_time,
    integer_setting,
    parse_date_text,
)


def _api_datetime(value: object) -> datetime | None:
    """Parse common API date representations into UTC."""

    if value is None or value == "":
        return None

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None

    raw = clean_text(value)
    if not raw:
        return None

    if raw.isdigit() and len(raw) >= 10:
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None

    try:
        return ensure_utc(date_parser.parse(raw))
    except (ValueError, TypeError, OverflowError):
        return None


def _nested_text(value: object) -> str:
    """Extract a human-readable value from common CVRF JSON structures."""

    if isinstance(value, str):
        return clean_text(value)

    if isinstance(value, dict):
        for key in ("Value", "value", "Title", "title", "Description"):
            candidate = _nested_text(value.get(key))
            if candidate:
                return candidate
        return ""

    if isinstance(value, list):
        for entry in value:
            candidate = _nested_text(entry)
            if candidate:
                return candidate

    return ""


def _msrc_summary(vulnerability: dict[str, Any], fallback: str) -> str:
    """Select the most useful English note from a Microsoft CVRF record."""

    notes = vulnerability.get("Notes", [])
    if isinstance(notes, list):
        preferred: list[str] = []
        other: list[str] = []
        for note in notes:
            if not isinstance(note, dict):
                continue
            value = _nested_text(note)
            if not value:
                continue
            note_type = clean_text(note.get("Type")).lower()
            if note_type in {"description", "summary", "general"}:
                preferred.append(value)
            else:
                other.append(value)
        if preferred:
            return preferred[0]
        if other:
            return other[0]

    return fallback


def _msrc_cvss(vulnerability: dict[str, Any]) -> tuple[float | None, str]:
    """Extract the highest CVSS score and vector from a CVRF vulnerability."""

    selected_score: float | None = None
    selected_vector = ""
    score_sets = vulnerability.get("CVSSScoreSets", [])

    if not isinstance(score_sets, list):
        return None, ""

    for score_set in score_sets:
        if not isinstance(score_set, dict):
            continue
        raw_score = score_set.get("BaseScore") or score_set.get("TemporalScore")
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            continue
        if selected_score is None or score > selected_score:
            selected_score = score
            selected_vector = clean_text(
                score_set.get("Vector") or score_set.get("VectorString")
            )

    return selected_score, selected_vector


def _msrc_exploitation_detected(vulnerability: dict[str, Any]) -> bool:
    """Return whether MSRC explicitly confirms exploitation in the wild."""

    for threat in vulnerability.get("Threats", []):
        if not isinstance(threat, dict):
            continue
        description = _nested_text(
            threat.get("Description")
            or threat.get("description")
        ).lower()
        value = _nested_text(
            threat.get("Value")
            or threat.get("value")
            or threat.get("Status")
            or threat.get("status")
        ).lower()
        combined = f"{description} {value}".strip()
        if any(
            marker in combined
            for marker in (
                "exploitation detected",
                "exploited in the wild",
                "active exploitation",
            )
        ):
            if any(
                negative in combined
                for negative in (
                    "not detected",
                    "no exploitation",
                    "false",
                    "unknown",
                )
            ):
                continue
            return True
    return False


def fetch_msrc_updates(source: Source, cutoff: datetime) -> list[Item]:
    """Collect current Microsoft releases without replaying old CVE catalogues.

    A newly published release is expanded into selected CVEs. A revision to an
    older monthly release is represented by one release-level item, because the
    CVRF document contains the complete historical release and cannot safely be
    treated as thousands of newly disclosed or newly exploited vulnerabilities.
    """

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    response = http_get(source.url, headers=headers, timeout=60)
    response.raise_for_status()
    payload = response.json()

    releases = payload.get("value", payload.get("Value", []))
    if not isinstance(releases, list):
        raise RuntimeError("MSRC updates response did not contain a release list")

    release_items: list[Item] = []
    vulnerability_items: list[Item] = []

    for release in releases:
        if not isinstance(release, dict):
            continue

        initial_date = _api_datetime(
            release.get("InitialReleaseDate")
            or release.get("initialReleaseDate")
        )
        current_date = _api_datetime(
            release.get("CurrentReleaseDate")
            or release.get("currentReleaseDate")
        )
        # Some MSRC responses and test fixtures omit InitialReleaseDate. In that
        # case CurrentReleaseDate is the only available publication timestamp and
        # must be treated as the initial date. Real revisions normally include
        # both values, so the historical-catalogue replay protection remains.
        if initial_date is None and current_date is not None:
            initial_date = current_date

        is_new_release = bool(initial_date and initial_date >= cutoff)
        is_recent_revision = bool(
            not is_new_release
            and current_date
            and current_date >= cutoff
        )
        if not is_new_release and not is_recent_revision:
            continue

        release_id = clean_text(
            release.get("ID") or release.get("Id") or release.get("id")
        )
        release_title = clean_text(
            release.get("DocumentTitle")
            or release.get("Title")
            or release.get("Alias")
            or release_id
            or "Microsoft security update"
        )
        release_severity = clean_text(
            release.get("Severity") or release.get("severity")
        )
        published = initial_date if is_new_release else current_date
        assert published is not None

        if is_recent_revision:
            release_items.append(
                Item(
                    title=f"MSRC revised: {release_title}",
                    summary=(
                        "Microsoft revised an existing Security Update Guide "
                        "release. The complete historical CVRF catalogue is not "
                        "replayed as new daily vulnerabilities; review the release "
                        "notes for the specific changes."
                    ),
                    link="https://msrc.microsoft.com/update-guide/",
                    published=published,
                    source=source.name,
                    vendor="Microsoft",
                    section="Microsoft, Azure and Identity",
                    category="Vendor advisory",
                    score=source.base_score,
                    affected=(
                        "Microsoft products covered by the revised Security "
                        "Update Guide release."
                    ),
                    action=(
                        "Review the revised release notes and validate whether "
                        "the changes affect deployed Microsoft products."
                    ),
                    why=(
                        "This is an authoritative MSRC release revision, not a "
                        "new declaration that every CVE in the release was "
                        "disclosed or exploited today."
                    ),
                )
            )
            continue

        vulnerabilities: list[dict[str, Any]] = []
        if release_id:
            detail_url = f"{MSRC_CVRF_API}/{quote(release_id, safe='')}"
            detail_response = http_get(
                detail_url,
                headers=headers,
                timeout=90,
            )
            detail_response.raise_for_status()
            detail = detail_response.json()
            raw_vulnerabilities = detail.get(
                "Vulnerability",
                detail.get("vulnerability", []),
            )
            if isinstance(raw_vulnerabilities, list):
                vulnerabilities = [
                    record
                    for record in raw_vulnerabilities
                    if isinstance(record, dict)
                ]

        if not vulnerabilities:
            release_items.append(
                Item(
                    title=release_title,
                    summary=(
                        "Microsoft published a Security Update Guide release. "
                        "Review the linked release for affected products, CVEs, "
                        "exploitability and deployment requirements."
                    ),
                    link="https://msrc.microsoft.com/update-guide/",
                    published=published,
                    source=source.name,
                    vendor="Microsoft",
                    section="Microsoft, Azure and Identity",
                    category="Vendor advisory",
                    score=source.base_score,
                    affected=(
                        "Microsoft products listed in the Security Update Guide "
                        "release."
                    ),
                    action=(
                        "Review the release, validate affected assets and deploy "
                        "applicable Microsoft security updates."
                    ),
                    why=(
                        "This is authoritative vulnerability and remediation "
                        "information from Microsoft MSRC."
                    ),
                )
            )
            continue

        for vulnerability in vulnerabilities:
            cve = clean_text(
                vulnerability.get("CVE")
                or vulnerability.get("Cve")
                or vulnerability.get("cve")
            )
            if not cve:
                continue

            title = _nested_text(vulnerability.get("Title")) or release_title
            summary = _msrc_summary(vulnerability, release_title)
            cvss_score, cvss_vector = _msrc_cvss(vulnerability)
            exploited = _msrc_exploitation_detected(vulnerability)

            # Keep the daily report focused on exploited and high-severity CVEs.
            if not exploited and (cvss_score is None or cvss_score < 8.0):
                continue

            category = "Active exploitation" if exploited else "Critical vulnerability"
            score = source.base_score
            if exploited:
                score += 45
            elif cvss_score == 10.0:
                score += 40
            elif cvss_score is not None and cvss_score >= 9.0:
                score += 25
            else:
                score += 15

            severity = release_severity or "Not available"
            if cvss_score is not None:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            vulnerability_items.append(
                Item(
                    title=f"{cve} — {title}",
                    summary=summary,
                    link=(
                        "https://msrc.microsoft.com/update-guide/"
                        f"vulnerability/{cve}"
                    ),
                    published=published,
                    source=source.name,
                    vendor="Microsoft",
                    section="Microsoft, Azure and Identity",
                    category=category,
                    score=score,
                    cves=[cve],
                    exploited=exploited,
                    cvss_score=cvss_score,
                    cvss_severity=severity,
                    cvss_vector=cvss_vector,
                    affected=(
                        "Microsoft products and versions identified in the "
                        "Security Update Guide record."
                    ),
                    action=(
                        "Validate affected Microsoft assets, deploy the applicable "
                        "update or mitigation, and investigate exposure when "
                        "exploitation is reported."
                    ),
                    why=(
                        "Microsoft MSRC is the authoritative source for Microsoft "
                        "vulnerability and security-update information."
                    ),
                )
            )

    max_cves = integer_setting(
        "MSRC_MAX_CVES",
        default=75,
        minimum=1,
        maximum=250,
    )
    vulnerability_items.sort(
        key=lambda item: (
            item.exploited,
            item.cvss_score or 0.0,
            item.score,
        ),
        reverse=True,
    )
    if len(vulnerability_items) > max_cves:
        print(
            "WARNING: MSRC daily CVE output limited to "
            f"{max_cves} of {len(vulnerability_items)} qualifying records.",
            file=sys.stderr,
        )
        vulnerability_items = vulnerability_items[:max_cves]

    return release_items + vulnerability_items


def fetch_rss(source: Source, cutoff: datetime) -> list[Item]:
    """Collect and normalise qualifying entries from one RSS or Atom feed.

    A failed or empty feed raises an error so Source Coverage can distinguish a
    collection problem from a healthy source with no relevant in-window entries.
    """

    if source.name == "Microsoft Security Response Center":
        return fetch_msrc_updates(source, cutoff)

    response = http_get(
        source.url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/rss+xml, application/atom+xml, "
                "application/xml, text/xml, */*"
            ),
        },
    )
    response.raise_for_status()
    payload = response.content

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
    """Find the nearest useful HTML container for an article link."""

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
    """Fetch an article page and extract publication date and summary metadata."""

    response = http_get(
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
    """Extract a concise description from common HTML metadata elements."""

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
    """Apply source-specific URL inclusion and exclusion rules."""

    lowered = link.lower()

    if source.include_patterns and not any(
        pattern.lower() in lowered for pattern in source.include_patterns
    ):
        return False

    if any(pattern.lower() in lowered for pattern in source.exclude_patterns):
        return False

    return True

def fetch_html(source: Source, cutoff: datetime) -> list[Item]:
    """Collect qualifying articles from a configured HTML index page.

    Candidate links are discovered with CSS selectors, filtered by URL policy and
    supplemented with detail-page metadata when the index does not expose a date.
    """

    response = http_get(
        source.url,
        timeout=45,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    candidates: list[tuple[str, str, str, datetime | None]] = []
    seen_links: set[str] = set()

    # A source can expose multiple historical layouts. Duplicate links are
    # removed later, allowing several selectors to be tried safely.
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


def fetch_ransomware_live(
    source: dict[str, Any],
    cutoff: datetime,
) -> list[NewsLink]:
    """Collect public ransomware victim claims as unverified discovery links.

    This adapter reads only the public aggregation API. It does not connect to
    onion services, criminal forums, leak sites or stolen-data repositories.
    Every result is explicitly labelled as an unverified claim and remains in
    the secondary-news/exposure path; it cannot set KEV, CVSS or confirmed
    exploitation status.
    """

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    api_key = os.getenv("RANSOMWARE_LIVE_API_KEY", "").strip()
    if api_key:
        headers["X-API-KEY"] = api_key

    response = http_get(source["url"], headers=headers, timeout=60)
    response.raise_for_status()
    payload = response.json()

    if isinstance(payload, list):
        records = payload
    elif isinstance(payload, dict):
        records = next(
            (
                payload[key]
                for key in ("data", "victims", "results", "items")
                if isinstance(payload.get(key), list)
            ),
            [],
        )
    else:
        raise RuntimeError("Ransomware.live response was not a list or object")

    links: list[NewsLink] = []
    seen: set[tuple[str, str]] = set()

    for record in records:
        if not isinstance(record, dict):
            continue

        published = None
        for key in (
            "discovered",
            "discovered_at",
            "published",
            "published_at",
            "created_at",
            "date",
            "attackdate",
        ):
            published = _api_datetime(record.get(key))
            if published is not None:
                break

        if published is None or published < cutoff:
            continue

        victim = clean_text(
            record.get("victim")
            or record.get("name")
            or record.get("post_title")
            or record.get("title")
        )
        group = clean_text(
            record.get("group")
            or record.get("group_name")
            or record.get("gang")
            or record.get("actor")
        )
        if not victim:
            continue

        dedupe_key = (victim.lower(), group.lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        country = clean_text(
            record.get("country")
            or record.get("country_name")
            or record.get("country_code")
        )
        sector = clean_text(
            record.get("activity")
            or record.get("sector")
            or record.get("business")
        )
        source_link = clean_text(
            record.get("post_url")
            or record.get("url")
            or record.get("link")
        )
        if not source_link.startswith(("http://", "https://")):
            source_link = "https://www.ransomware.live/"

        group_text = f" by {group}" if group else ""
        context = "; ".join(
            value for value in (country, sector) if value
        )
        context_text = f" Reported context: {context}." if context else ""

        links.append(
            NewsLink(
                title=f"Unverified ransomware claim: {victim}{group_text}",
                link=source_link,
                source=source["name"],
                published=published,
                score=int(source.get("base_score", 10)) + 20,
                tags=[
                    "Dark Web/Exposure",
                    "Ransomware",
                    "Unverified claim",
                ],
                summary=(
                    f"Ransomware.live reports an unverified victim claim{group_text} "
                    f"involving {victim}.{context_text} Treat this as discovery "
                    "intelligence until independently corroborated."
                ),
            )
        )

    return links


def fetch_executive_news_rss(
    source: dict[str, Any],
    cutoff: datetime,
) -> list[NewsLink]:
    """Collect relevant executive-news links from an RSS, Atom or API source."""

    if source.get("adapter") == "ransomware_live":
        return fetch_ransomware_live(source, cutoff)

    response = http_get(
        source["url"],
        headers={
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/rss+xml, application/atom+xml, "
                "application/xml, text/xml, */*"
            ),
        },
    )
    response.raise_for_status()
    payload = response.content

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
    
def canonicalise_article_url(url: str) -> str:
    """Normalise an article URL and remove tracking parameters."""

    parsed = urlsplit(url.strip())

    if parsed.scheme not in {"http", "https"}:
        return ""

    host = parsed.netloc.lower()

    if not host:
        return ""

    path = re.sub(r"/{2,}", "/", parsed.path or "/")

    if path != "/":
        path = path.rstrip("/")

    return urlunsplit(
        (
            "https",
            host,
            path,
            "",
            "",
        )
    )


def executive_article_url_allowed(
    source: dict[str, Any],
    url: str,
) -> bool:
    """Validate a discovery URL against the publisher article format."""

    parsed = urlsplit(url)

    if parsed.scheme not in {"http", "https"}:
        return False

    host = parsed.netloc.lower()
    path = parsed.path

    allowed_hosts = {
        str(value).lower()
        for value in source.get("allowed_hosts", ())
    }

    if allowed_hosts and host not in allowed_hosts:
        return False

    article_path_regex = str(
        source.get("article_path_regex", "")
    ).strip()

    if article_path_regex and not re.fullmatch(
        article_path_regex,
        path,
        flags=re.IGNORECASE,
    ):
        return False

    lowered_url = url.lower()

    if any(
        str(value).lower() in lowered_url
        for value in source.get("exclude", ())
    ):
        return False

    # Retain compatibility with sources that still use the previous
    # substring-based include configuration.
    include_values = tuple(source.get("include", ()))

    if include_values and not any(
        str(value).lower() in lowered_url
        for value in include_values
    ):
        return False

    return True
    
def fetch_executive_news_html(
    source: dict[str, Any],
    cutoff: datetime,
) -> list[NewsLink]:
    """Collect relevant executive-news links from an HTML publication index."""

    response = http_get(
        source["url"],
        timeout=45,
        headers={"User-Agent": USER_AGENT},
    )
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    links: list[NewsLink] = []
    seen_links: set[str] = set()
    max_candidates = int(source.get("max_candidates", 40))

    for selector in source["selectors"]:
        for node in soup.select(selector):
            if not isinstance(node, Tag):
                continue

            anchor = (
                node
                if node.name == "a"
                else node.find("a", href=True)
            )

            if not isinstance(anchor, Tag):
                continue

            raw_href = clean_text(anchor.get("href", ""))
            title = clean_text(anchor.get_text(" ", strip=True))

            if not raw_href or len(title) < 12:
                continue

            link = canonicalise_article_url(
                urljoin(source["url"], raw_href)
            )

            if not link:
                continue

            if not executive_article_url_allowed(source, link):
                continue

            if link in seen_links:
                continue

            # Register the URL before detail-page retrieval. This avoids
            # requesting the same article repeatedly when several selectors
            # match the same anchor.
            seen_links.add(link)

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

            if published is None or not summary:
                try:
                    detail_date, detail_summary = (
                        extract_page_metadata(link)
                    )
                    published = published or detail_date
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

            if len(seen_links) >= max_candidates:
                break

        if len(seen_links) >= max_candidates:
            break

    return links
    
def clean_html_text(value: str) -> str:
    """Strip HTML markup and normalise the remaining human-readable text."""

    if not value:
        return ""

    return clean_text(
        BeautifulSoup(value, "html.parser").get_text(" ", strip=True)
    )

def fetch_hibp_breaches(cutoff: datetime) -> list[ExposureSignal]:
    """Collect newly added public breach metadata from Have I Been Pwned.

    The function excludes spam lists and retired records, classifies credential or
    stealer exposure separately from general breaches, and never requests account-
    level data.
    """

    response = http_get(
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

    # The public HIBP catalogue contains organisation-level breach metadata,
    # not the compromised account records themselves.
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

        # Malware-sourced or authentication-related data warrants credential
        # response guidance even when the underlying breach is older.
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
    """Query HIBP for authorised, verified-domain breach exposure.

    Only aggregate counts and breach names are returned to the report. Individual
    email aliases are deliberately excluded to reduce unnecessary personal-data
    handling. This endpoint requires an HIBP API key and verified domain control.
    """

    if not domains or not api_key:
        return []

    signals: list[ExposureSignal] = []

    # HIBP requires verified control of each queried domain. Requests are
    # intentionally serialised to respect API rate limits.
    for domain in domains:
        url = (
            f"{HIBP_BREACHED_DOMAIN_API}/"
            f"{quote(domain, safe='')}"
        )
        response = http_get(
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

        # Reduce the response to domain-level aggregates. Individual aliases
        # never enter the report or application logs.
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

def fetch_kev(lookback_days: int) -> list[Item]:
    """Collect recent entries from the CISA Known Exploited Vulnerabilities catalogue.

    Each KEV record is converted directly into a high-priority item with CISA's
    required action, remediation deadline and ransomware-use flag.
    """

    response = http_get(
        CISA_KEV_FEED,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )
    response.raise_for_status()
    catalogue = response.json()

    cutoff_date = datetime.now(timezone.utc).date() - timedelta(
        days=lookback_days - 1
    )

    items: list[Item] = []

    # CISA's dateAdded field is the reporting-window anchor; the original CVE
    # publication date is not used for KEV inclusion.
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
    """Select the preferred CVSS metric from an NVD vulnerability record.

    CVSS v4 is preferred when present, followed by v3.1, v3.0 and v2. The function
    returns score, severity and vector while tolerating incomplete NVD data.
    """

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

def english_nvd_description(cve_record: dict[str, Any]) -> str:
    """Return the English NVD description for a vulnerability record."""

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
    """Match an NVD record to the configured priority-vendor coverage rules."""

    lowered = description.lower()

    for coverage in NVD_RECENT_COVERAGE:
        if any(term in lowered for term in coverage["terms"]):
            return coverage["vendor"], coverage["section"]

    return None

def fetch_recent_nvd_coverage(
    cutoff: datetime,
) -> list[Item]:
    """Collect recent NVD CVEs matching priority vendors and technologies."""

    end = datetime.now(timezone.utc)
    api_key = os.getenv("NVD_API_KEY", "").strip()

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    if api_key:
        headers["apiKey"] = api_key

    response = http_get(
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


def enrich_epss(
    items: list[Item],
    warnings: list[str],
) -> None:
    """Enrich CVE-bearing items with FIRST EPSS probability and percentile.

    EPSS is not treated as evidence of exploitation. It adjusts prioritisation
    and adds transparent context describing the modelled probability of observed
    exploitation activity during the next 30 days.
    """

    cve_to_items: dict[str, list[Item]] = {}
    for item in items:
        for cve in item.cves:
            normalised = clean_text(cve).upper()
            if normalised:
                cve_to_items.setdefault(normalised, []).append(item)

    if not cve_to_items:
        return

    max_cves = integer_setting(
        "EPSS_MAX_CVES",
        default=200,
        minimum=1,
        maximum=1000,
    )
    cves = sorted(cve_to_items)[:max_cves]
    if len(cve_to_items) > max_cves:
        warnings.append(
            f"EPSS enrichment limited to {max_cves} of {len(cve_to_items)} CVEs. "
            "Raise EPSS_MAX_CVES to enrich more records."
        )

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    for start in range(0, len(cves), 100):
        batch = cves[start : start + 100]
        try:
            response = http_get(
                FIRST_EPSS_API,
                params={"cve": ",".join(batch)},
                headers=headers,
                timeout=45,
            )
            response.raise_for_status()
            payload = response.json()
            records = payload.get("data", [])
            if not isinstance(records, list):
                raise RuntimeError("EPSS response did not contain a data list")

            for record in records:
                if not isinstance(record, dict):
                    continue
                cve = clean_text(record.get("cve")).upper()
                if cve not in cve_to_items:
                    continue
                try:
                    probability = float(record.get("epss"))
                    percentile = float(record.get("percentile"))
                except (TypeError, ValueError):
                    continue

                probability = max(0.0, min(probability, 1.0))
                percentile = max(0.0, min(percentile, 1.0))

                if probability >= 0.50:
                    priority_points = 25
                elif probability >= 0.20:
                    priority_points = 15
                elif probability >= 0.05:
                    priority_points = 8
                elif percentile >= 0.95:
                    priority_points = 4
                else:
                    priority_points = 0

                context = (
                    f"EPSS: {probability:.1%} probability of observed exploitation "
                    f"activity in the next 30 days; {percentile:.1%} percentile."
                )

                for item in cve_to_items[cve]:
                    if "EPSS:" in item.why:
                        continue
                    item.score += priority_points
                    item.why = f"{item.why.rstrip()} {context}".strip()

        except Exception as error:
            warnings.append(
                f"FIRST EPSS batch {start // 100 + 1}: "
                f"{type(error).__name__}: {error}"
            )


def enrich_nvd(
    items: list[Item],
    warnings: list[str],
) -> None:
    """Enrich collected items with NVD CVSS data and descriptions.

    Requests are deduplicated by CVE and rate-limited according to whether an NVD
    API key is available. Enrichment failures are recorded as warnings rather than
    terminating the briefing.
    """

    cve_to_items: dict[str, list[Item]] = {}

    # A single NVD request is made per unique CVE, even when several sources
    # report the same vulnerability.
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
            response = http_get(
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

    # Preserve the existing app.py contract: NVD and EPSS enrichment are both
    # completed by the single enrich_nvd call already used by the pipeline.
    enrich_epss(items, warnings)
