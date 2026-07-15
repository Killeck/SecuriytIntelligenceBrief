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
from urllib.parse import (
    parse_qs,
    quote,
    unquote,
    urljoin,
    urlsplit,
    urlunsplit,
)

import feedparser
import requests
from bs4 import BeautifulSoup, Tag
from dateutil import parser as date_parser

from .analysis import build_item, build_news_link
from .config import (
    CISA_KEV_CATALOGUE,
    CISA_KEV_FEED,
    HIBP_BREACHED_DOMAIN_API,
    HIBP_BREACHES_API,
    HIBP_DASHBOARD,
    HIBP_PWNED_WEBSITES,
    NVD_CVE_API,
    USER_AGENT,
)
from .http_client import get as http_get
from .models import ExposureSignal, Item, NewsLink, Source
from .rules import (
    ACTIONS,
    NVD_RECENT_COVERAGE,
    SENSITIVE_DATA_CLASSES,
    WHY,
)
from .utils import (
    absolute_url,
    clean_text,
    ensure_utc,
    feed_entry_time,
    integer_setting,
    parse_date_text,
)


def fetch_rss(
    source: Source,
    cutoff: datetime,
) -> list[Item]:
    """Collect and normalise qualifying entries from an RSS or Atom feed.

    A failed or empty feed raises an error so Source Coverage can distinguish
    a collection problem from a healthy source with no relevant in-window
    entries.
    """

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
        details = clean_text(
            getattr(feed, "bozo_exception", "")
        )
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

        text_length = len(
            clean_text(parent.get_text(" ", strip=True))
        )

        if parent.name in {
            "article",
            "li",
            "tr",
            "section",
        }:
            return parent

        if 40 <= text_length <= 2500:
            current = parent
        else:
            break

    return current


def extract_page_metadata(
    url: str,
) -> tuple[datetime | None, str]:
    """Fetch publication date and summary metadata from an article page."""

    response = http_get(
        url,
        timeout=30,
        headers={
            "User-Agent": USER_AGENT,
        },
    )
    response.raise_for_status()

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

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
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return (
                parsed.astimezone(timezone.utc),
                extract_meta_summary(soup),
            )
        except (
            ValueError,
            OverflowError,
        ):
            continue

    return (
        parse_date_text(
            soup.get_text(" ", strip=True)
        ),
        extract_meta_summary(soup),
    )


def extract_meta_summary(
    soup: BeautifulSoup,
) -> str:
    """Extract a concise description from common HTML metadata."""

    for selector in (
        "meta[name='description']",
        "meta[property='og:description']",
        "meta[name='twitter:description']",
    ):
        element = soup.select_one(selector)

        if element and element.get("content"):
            return clean_text(
                element.get("content")
            )

    paragraph = soup.select_one(
        "article p, main p"
    )

    if paragraph:
        return clean_text(
            paragraph.get_text(
                " ",
                strip=True,
            )
        )

    return ""


def link_allowed(
    source: Source,
    link: str,
) -> bool:
    """Apply source-specific URL inclusion and exclusion rules."""

    lowered = link.lower()

    if (
        source.include_patterns
        and not any(
            pattern.lower() in lowered
            for pattern in source.include_patterns
        )
    ):
        return False

    if any(
        pattern.lower() in lowered
        for pattern in source.exclude_patterns
    ):
        return False

    return True


def fetch_html(
    source: Source,
    cutoff: datetime,
) -> list[Item]:
    """Collect qualifying articles from a configured HTML index page."""

    response = http_get(
        source.url,
        timeout=45,
        headers={
            "User-Agent": USER_AGENT,
        },
    )
    response.raise_for_status()

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    candidates: list[
        tuple[
            str,
            str,
            str,
            datetime | None,
        ]
    ] = []

    seen_links: set[str] = set()

    for selector in source.selectors:
        for node in soup.select(selector):
            if not isinstance(node, Tag):
                continue

            anchor = (
                node
                if node.name == "a"
                else node.find(
                    "a",
                    href=True,
                )
            )

            if not isinstance(anchor, Tag):
                continue

            href = str(
                anchor.get("href", "")
            ).strip()

            if not href:
                continue

            link = absolute_url(
                source.url,
                href,
            )

            if (
                link in seen_links
                or not link_allowed(
                    source,
                    link,
                )
            ):
                continue

            title = clean_text(
                anchor.get_text(
                    " ",
                    strip=True,
                )
            )

            if len(title) < 8:
                continue

            container = candidate_container(
                anchor
            )

            container_text = clean_text(
                container.get_text(
                    " ",
                    strip=True,
                )
            )

            published = parse_date_text(
                container_text
            )

            summary = ""

            for paragraph in container.find_all(
                "p",
                limit=3,
            ):
                candidate = clean_text(
                    paragraph.get_text(
                        " ",
                        strip=True,
                    )
                )

                if candidate and candidate != title:
                    summary = candidate
                    break

            candidates.append(
                (
                    title,
                    summary,
                    link,
                    published,
                )
            )

            seen_links.add(link)

            if (
                len(candidates)
                >= source.max_candidates
            ):
                break

        if (
            len(candidates)
            >= source.max_candidates
        ):
            break

    items: list[Item] = []

    for (
        title,
        summary,
        link,
        published,
    ) in candidates:
        if published is None or not summary:
            try:
                (
                    detail_date,
                    detail_summary,
                ) = extract_page_metadata(link)

                published = (
                    published or detail_date
                )
                summary = (
                    summary or detail_summary
                )

                time.sleep(0.15)

            except requests.RequestException as error:
                print(
                    (
                        "WARNING: detail fetch failed "
                        f"for {link}: {error}"
                    ),
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


def canonicalise_article_url(
    url: str,
) -> str:
    """Normalise an article URL and remove tracking parameters."""

    parsed = urlsplit(url.strip())

    if parsed.scheme not in {
        "http",
        "https",
    }:
        return ""

    host = parsed.netloc.lower()

    if not host:
        return ""

    path = re.sub(
        r"/{2,}",
        "/",
        parsed.path or "/",
    )

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


def unwrap_discovery_url(
    url: str,
) -> str:
    """Extract a publisher URL from a supported discovery redirect."""

    parsed = urlsplit(url.strip())
    host = parsed.netloc.lower()

    if host not in {
        "bing.com",
        "www.bing.com",
    }:
        return canonicalise_article_url(url)

    query = parse_qs(parsed.query)

    for key in (
        "url",
        "u",
        "target",
    ):
        values = query.get(key)

        if not values:
            continue

        candidate = unquote(
            values[0]
        ).strip()

        if candidate.startswith(
            (
                "https://",
                "http://",
            )
        ):
            return canonicalise_article_url(
                candidate
            )

    return canonicalise_article_url(url)


def discovery_publisher_url_allowed(
    source_name: str,
    url: str,
) -> bool:
    """Ensure a discovery result belongs to the expected publisher."""

    host = urlsplit(url).netloc.lower()

    expected_hosts = {
        "Reuters Cybersecurity": {
            "reuters.com",
            "www.reuters.com",
        },
        "BankInfoSecurity": {
            "bankinfosecurity.com",
            "www.bankinfosecurity.com",
        },
    }

    allowed_hosts = expected_hosts.get(
        source_name
    )

    if allowed_hosts is None:
        return True

    return host in allowed_hosts


def executive_article_url_allowed(
    source: dict[str, Any],
    url: str,
) -> bool:
    """Validate a direct HTML discovery URL."""

    parsed = urlsplit(url)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        return False

    host = parsed.netloc.lower()
    path = parsed.path

    allowed_hosts = {
        str(value).lower()
        for value in source.get(
            "allowed_hosts",
            (),
        )
    }

    if (
        allowed_hosts
        and host not in allowed_hosts
    ):
        return False

    article_path_regex = str(
        source.get(
            "article_path_regex",
            "",
        )
    ).strip()

    if (
        article_path_regex
        and not re.fullmatch(
            article_path_regex,
            path,
            flags=re.IGNORECASE,
        )
    ):
        return False

    lowered_url = url.lower()

    if any(
        str(value).lower() in lowered_url
        for value in source.get(
            "exclude",
            (),
        )
    ):
        return False

    include_values = tuple(
        source.get(
            "include",
            (),
        )
    )

    if (
        include_values
        and not any(
            str(value).lower() in lowered_url
            for value in include_values
        )
    ):
        return False

    return True


def fetch_executive_news_rss(
    source: dict[str, Any],
    cutoff: datetime,
) -> list[NewsLink]:
    """Collect executive-news links from an RSS or Atom source."""

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

    feed = feedparser.parse(
        response.content
    )

    if not feed.entries:
        details = clean_text(
            getattr(
                feed,
                "bozo_exception",
                "",
            )
        )

        raise RuntimeError(
            "Feed returned no entries"
            + (
                f": {details}"
                if details
                else ""
            )
        )

    links: list[NewsLink] = []
    seen_links: set[str] = set()

    max_items = int(
        source.get(
            "max_items",
            20,
        )
    )

    for entry in feed.entries:
        published = feed_entry_time(entry)

        if published is None:
            continue

        raw_link = clean_text(
            entry.get(
                "link",
                "",
            )
        )

        if not raw_link:
            continue

        link = unwrap_discovery_url(
            raw_link
        )

        if not link:
            continue

        if not discovery_publisher_url_allowed(
            source["name"],
            link,
        ):
            continue

        if link in seen_links:
            continue

        seen_links.add(link)

        news_link = build_news_link(
            source=source["name"],
            base_score=source["base_score"],
            title=entry.get(
                "title",
                "",
            ),
            summary=(
                entry.get("summary")
                or entry.get("description")
                or entry.get("subtitle")
                or ""
            ),
            link=link,
            published=published,
            cutoff=cutoff,
        )

        if news_link:
            links.append(news_link)

        if len(links) >= max_items:
            break

    return links


def fetch_executive_news_html(
    source: dict[str, Any],
    cutoff: datetime,
) -> list[NewsLink]:
    """Collect executive-news links from an HTML publication index."""

    response = http_get(
        source["url"],
        timeout=45,
        headers={
            "User-Agent": USER_AGENT,
        },
    )
    response.raise_for_status()

    soup = BeautifulSoup(
        response.text,
        "html.parser",
    )

    links: list[NewsLink] = []
    seen_links: set[str] = set()

    max_candidates = int(
        source.get(
            "max_candidates",
            40,
        )
    )

    for selector in source["selectors"]:
        for node in soup.select(selector):
            if not isinstance(node, Tag):
                continue

            anchor = (
                node
                if node.name == "a"
                else node.find(
                    "a",
                    href=True,
                )
            )

            if not isinstance(anchor, Tag):
                continue

            raw_href = clean_text(
                anchor.get(
                    "href",
                    "",
                )
            )

            title = clean_text(
                anchor.get_text(
                    " ",
                    strip=True,
                )
            )

            if (
                not raw_href
                or len(title) < 12
            ):
                continue

            link = canonicalise_article_url(
                urljoin(
                    source["url"],
                    raw_href,
                )
            )

            if not link:
                continue

            if not executive_article_url_allowed(
                source,
                link,
            ):
                continue

            if link in seen_links:
                continue

            seen_links.add(link)

            container = candidate_container(
                anchor
            )

            container_text = clean_text(
                container.get_text(
                    " ",
                    strip=True,
                )
            )

            published = parse_date_text(
                container_text
            )

            summary = ""

            for paragraph in container.find_all(
                "p",
                limit=3,
            ):
                candidate = clean_text(
                    paragraph.get_text(
                        " ",
                        strip=True,
                    )
                )

                if candidate and candidate != title:
                    summary = candidate
                    break

            if published is None or not summary:
                try:
                    (
                        detail_date,
                        detail_summary,
                    ) = extract_page_metadata(
                        link
                    )

                    published = (
                        published
                        or detail_date
                    )
                    summary = (
                        summary
                        or detail_summary
                    )

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


def clean_html_text(
    value: str,
) -> str:
    """Strip HTML markup and normalise the remaining text."""

    if not value:
        return ""

    return clean_text(
        BeautifulSoup(
            value,
            "html.parser",
        ).get_text(
            " ",
            strip=True,
        )
    )


def fetch_hibp_breaches(
    cutoff: datetime,
) -> list[ExposureSignal]:
    """Collect newly added public HIBP breach metadata."""

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
        raise RuntimeError(
            "HIBP breach response was not a list"
        )

    signals: list[ExposureSignal] = []

    for entry in payload:
        if not isinstance(entry, dict):
            continue

        if (
            entry.get("IsSpamList")
            or entry.get("IsRetired")
        ):
            continue

        raw_added = clean_text(
            entry.get("AddedDate")
        )

        if not raw_added:
            continue

        try:
            observed = ensure_utc(
                date_parser.parse(raw_added)
            )
        except (
            ValueError,
            TypeError,
            OverflowError,
        ):
            continue

        if observed < cutoff:
            continue

        name = clean_text(
            entry.get("Name")
        )

        title = (
            clean_text(
                entry.get("Title")
            )
            or name
            or "Unknown breach"
        )

        domain = (
            clean_text(
                entry.get("Domain")
            )
            or "Domain not stated"
        )

        description = clean_html_text(
            str(
                entry.get("Description")
                or ""
            )
        )

        data_classes = [
            clean_text(value)
            for value in entry.get(
                "DataClasses",
                [],
            )
            if clean_text(value)
        ]

        class_set = set(data_classes)
        pwn_count = entry.get("PwnCount")

        try:
            affected_count = int(
                pwn_count or 0
            )
        except (
            TypeError,
            ValueError,
        ):
            affected_count = 0

        is_stealer = bool(
            entry.get("IsStealerLog")
        )

        is_malware = bool(
            entry.get("IsMalware")
        )

        sensitive = bool(
            class_set
            & SENSITIVE_DATA_CLASSES
        )

        if (
            is_stealer
            or is_malware
            or sensitive
        ):
            signal_type = (
                "Credential Exposure and Stealer Logs"
            )
            severity = "High"
            score = 82
            action = (
                "Identify potentially affected identities, force password "
                "resets where applicable, revoke sessions and tokens, and "
                "investigate endpoint or browser compromise."
            )
        else:
            signal_type = (
                "Data Breaches and Leaks"
            )
            severity = (
                "Elevated"
                if affected_count >= 100000
                else "Guarded"
            )
            score = (
                68
                if severity == "Elevated"
                else 54
            )
            action = (
                "Assess organisational and supplier exposure, identify "
                "affected identities or data classes, and activate privacy, "
                "legal and notification workflows where applicable."
            )

        confidence = (
            "Verified"
            if bool(
                entry.get("IsVerified")
            )
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

        breach_date = clean_text(
            entry.get("BreachDate")
        )

        summary_parts = [
            (
                description
                or f"HIBP added breach metadata for {title}."
            ),
            (
                "Breach date: "
                f"{breach_date or 'not stated'}."
            ),
        ]

        link = HIBP_PWNED_WEBSITES

        if name:
            link += (
                f"#{quote(name, safe='')}"
            )

        signals.append(
            ExposureSignal(
                title=(
                    f"New breach exposure: {title}"
                ),
                signal_type=signal_type,
                source="Have I Been Pwned",
                link=link,
                observed=observed,
                confidence=confidence,
                severity=severity,
                score=score,
                summary=" ".join(
                    summary_parts
                ),
                affected=(
                    f"{domain}; {count_text}; "
                    f"exposed data: {classes_text}."
                ),
                action=action,
                organisation=domain,
                tags=[
                    "HIBP",
                    (
                        "Stealer log"
                        if is_stealer
                        else ""
                    ),
                    (
                        "Malware-sourced"
                        if is_malware
                        else ""
                    ),
                ],
            )
        )

    return signals


def fetch_hibp_domain_exposure(
    domains: tuple[str, ...],
    api_key: str,
) -> list[ExposureSignal]:
    """Query HIBP for authorised verified-domain exposure."""

    if not domains or not api_key:
        return []

    signals: list[ExposureSignal] = []

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
                (
                    "HIBP domain response for "
                    f"{domain} was not an object"
                )
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

        displayed_breaches = ", ".join(
            breach_names[:12]
        )

        if len(breach_names) > 12:
            displayed_breaches += (
                f", plus {len(breach_names) - 12} "
                "additional breach(es)"
            )

        signals.append(
            ExposureSignal(
                title=(
                    "Verified-domain breach exposure: "
                    f"{domain}"
                ),
                signal_type=(
                    "Credential Exposure and Stealer Logs"
                ),
                source=(
                    "Have I Been Pwned Domain Search"
                ),
                link=HIBP_DASHBOARD,
                observed=datetime.now(
                    timezone.utc
                ),
                confidence=(
                    "Domain ownership verified"
                ),
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
                    "reused credentials, revoke sessions, strengthen MFA, "
                    "and increase phishing and account-takeover monitoring."
                ),
                organisation=domain,
                tags=[
                    "HIBP",
                    "Verified domain",
                    "Credential exposure",
                ],
            )
        )

        time.sleep(1.7)

    return signals


def fetch_kev(
    lookback_days: int,
) -> list[Item]:
    """Collect recent CISA Known Exploited Vulnerabilities entries."""

    response = http_get(
        CISA_KEV_FEED,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        },
    )
    response.raise_for_status()

    catalogue = response.json()

    cutoff_date = (
        datetime.now(
            timezone.utc
        ).date()
        - timedelta(
            days=lookback_days - 1
        )
    )

    items: list[Item] = []

    for entry in catalogue.get(
        "vulnerabilities",
        [],
    ):
        raw_date = str(
            entry.get(
                "dateAdded",
                "",
            )
        ).strip()

        if not raw_date:
            continue

        try:
            added = date.fromisoformat(
                raw_date
            )
        except ValueError:
            continue

        if added < cutoff_date:
            continue

        cve = clean_text(
            entry.get("cveID")
        )

        vendor = (
            clean_text(
                entry.get("vendorProject")
            )
            or "Unknown vendor"
        )

        product = (
            clean_text(
                entry.get("product")
            )
            or "Unknown product"
        )

        title = clean_text(
            entry.get(
                "vulnerabilityName"
            )
        )

        description = clean_text(
            entry.get(
                "shortDescription"
            )
        )

        required_action = clean_text(
            entry.get(
                "requiredAction"
            )
        )

        ransomware_value = clean_text(
            entry.get(
                "knownRansomwareCampaignUse"
            )
        ).lower()

        ransomware = (
            ransomware_value == "known"
        )

        published = datetime.combine(
            added,
            datetime.min.time(),
            tzinfo=timezone.utc,
        )

        action = (
            required_action
            or (
                "Apply the vendor remediation or mitigation and "
                "investigate potential compromise."
            )
        )

        due_date = clean_text(
            entry.get("dueDate")
        )

        summary = description

        if due_date:
            summary += (
                " CISA remediation due date: "
                f"{due_date}."
            )

        items.append(
            Item(
                title=f"{cve} — {title}",
                summary=summary,
                link=(
                    (
                        "https://nvd.nist.gov/"
                        f"vuln/detail/{cve}"
                    )
                    if cve
                    else CISA_KEV_CATALOGUE
                ),
                published=published,
                source="CISA KEV",
                vendor=vendor,
                section=(
                    "Known Exploited Vulnerabilities"
                ),
                category=(
                    "Ransomware"
                    if ransomware
                    else "Active exploitation"
                ),
                score=(
                    115
                    if ransomware
                    else 105
                ),
                cves=[
                    cve
                ] if cve else [],
                exploited=True,
                kev=True,
                ransomware=ransomware,
                affected=(
                    f"Organisations operating {vendor} {product} "
                    "in affected versions or configurations."
                ),
                action=action,
                why=(
                    "CISA has added this vulnerability to the Known "
                    "Exploited Vulnerabilities catalogue, confirming "
                    "real-world exploitation."
                ),
            )
        )

    return items


def select_cvss_metric(
    cve_record: dict[str, Any],
) -> tuple[
    float | None,
    str,
    str,
]:
    """Select the preferred CVSS metric from an NVD record."""

    metrics = cve_record.get(
        "metrics",
        {},
    )

    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        candidates = metrics.get(
            metric_name,
            [],
        )

        if not candidates:
            continue

        selected = next(
            (
                metric
                for metric in candidates
                if metric.get("type")
                == "Primary"
            ),
            candidates[0],
        )

        data = selected.get(
            "cvssData",
            {},
        )

        score = data.get(
            "baseScore"
        )

        severity = (
            data.get("baseSeverity")
            or selected.get(
                "baseSeverity"
            )
            or "Not available"
        )

        vector = data.get(
            "vectorString",
            "",
        )

        try:
            numeric_score = float(score)
        except (
            TypeError,
            ValueError,
        ):
            numeric_score = None

        return (
            numeric_score,
            str(severity),
            str(vector),
        )

    return (
        None,
        "Not available",
        "",
    )


def english_nvd_description(
    cve_record: dict[str, Any],
) -> str:
    """Return the English description from an NVD record."""

    descriptions = cve_record.get(
        "descriptions",
        [],
    )

    for description in descriptions:
        if description.get("lang") == "en":
            return clean_text(
                description.get("value")
            )

    if descriptions:
        return clean_text(
            descriptions[0].get("value")
        )

    return ""


def nvd_coverage_match(
    description: str,
) -> tuple[str, str] | None:
    """Match an NVD record to priority-vendor coverage rules."""

    lowered = description.lower()

    for coverage in NVD_RECENT_COVERAGE:
        if any(
            term in lowered
            for term in coverage["terms"]
        ):
            return (
                coverage["vendor"],
                coverage["section"],
            )

    return None


def nvd_request_headers() -> dict[str, str]:
    """Build NVD headers, including the optional API key."""

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }

    api_key = os.getenv(
        "NVD_API_KEY",
        "",
    ).strip()

    if api_key:
        headers["apiKey"] = api_key

    return headers


def fetch_recent_nvd_coverage(
    cutoff: datetime,
) -> list[Item]:
    """Collect recent NVD CVEs matching priority coverage."""

    end = datetime.now(
        timezone.utc
    )

    response = http_get(
        NVD_CVE_API,
        params={
            "pubStartDate": (
                cutoff.isoformat(
                    timespec="milliseconds"
                ).replace(
                    "+00:00",
                    "Z",
                )
            ),
            "pubEndDate": (
                end.isoformat(
                    timespec="milliseconds"
                ).replace(
                    "+00:00",
                    "Z",
                )
            ),
            "resultsPerPage": 2000,
        },
        headers=nvd_request_headers(),
        timeout=90,
    )
    response.raise_for_status()

    payload = response.json()
    items: list[Item] = []

    for vulnerability in payload.get(
        "vulnerabilities",
        [],
    ):
        cve_record = vulnerability.get(
            "cve",
            {},
        )

        cve_id = clean_text(
            cve_record.get("id")
        )

        description = english_nvd_description(
            cve_record
        )

        if not cve_id or not description:
            continue

        coverage = nvd_coverage_match(
            description
        )

        if coverage is None:
            continue

        vendor, section = coverage
        published_raw = cve_record.get(
            "published"
        )

        try:
            published = date_parser.parse(
                str(published_raw)
            )

            if published.tzinfo is None:
                published = published.replace(
                    tzinfo=timezone.utc
                )

            published = published.astimezone(
                timezone.utc
            )

        except (
            ValueError,
            TypeError,
            OverflowError,
        ):
            continue

        (
            cvss_score,
            cvss_severity,
            cvss_vector,
        ) = select_cvss_metric(
            cve_record
        )

        category = (
            "Critical vulnerability"
            if (
                cvss_score is not None
                and cvss_score >= 8.0
            )
            else "Vendor advisory"
        )

        base_score = 38

        if cvss_score == 10.0:
            base_score += 50
        elif (
            cvss_score is not None
            and cvss_score >= 9.0
        ):
            base_score += 30
        elif (
            cvss_score is not None
            and cvss_score >= 8.0
        ):
            base_score += 18

        items.append(
            Item(
                title=(
                    f"{cve_id} — {vendor}"
                ),
                summary=description,
                link=(
                    "https://nvd.nist.gov/"
                    f"vuln/detail/{cve_id}"
                ),
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
                    f"Organisations using affected {vendor} products "
                    "or services described in the NVD record."
                ),
                action=ACTIONS.get(
                    category,
                    ACTIONS[
                        "General security"
                    ],
                ),
                why=WHY.get(
                    category,
                    WHY[
                        "General security"
                    ],
                ),
            )
        )

    return items


def enrich_nvd(
    items: list[Item],
    warnings: list[str],
) -> None:
    """Enrich collected items with NVD CVSS information."""

    cve_to_items: dict[
        str,
        list[Item],
    ] = {}

    for item in items:
        for cve in item.cves:
            cve_to_items.setdefault(
                cve,
                [],
            ).append(item)

    if not cve_to_items:
        return

    api_key = os.getenv(
        "NVD_API_KEY",
        "",
    ).strip()

    default_limit = (
        75
        if api_key
        else 12
    )

    max_cves = integer_setting(
        "NVD_MAX_CVES",
        default=default_limit,
        minimum=1,
        maximum=100,
    )

    cves = sorted(
        cve_to_items
    )[:max_cves]

    if len(cve_to_items) > max_cves:
        if api_key:
            warning = (
                f"NVD enrichment limited to {max_cves} of "
                f"{len(cve_to_items)} CVEs. Raise NVD_MAX_CVES "
                "to enrich additional records."
            )
        else:
            warning = (
                f"NVD enrichment limited to {max_cves} of "
                f"{len(cve_to_items)} CVEs. Add a free "
                "NVD_API_KEY or raise NVD_MAX_CVES."
            )

        warnings.append(warning)

    headers = nvd_request_headers()

    pause = (
        0.75
        if api_key
        else 6.2
    )

    for index, cve in enumerate(cves):
        try:
            response = http_get(
                NVD_CVE_API,
                params={
                    "cveId": cve,
                },
                headers=headers,
                timeout=45,
            )
            response.raise_for_status()

            payload = response.json()

            vulnerabilities = payload.get(
                "vulnerabilities",
                [],
            )

            if not vulnerabilities:
                continue

            (
                score,
                severity,
                vector,
            ) = select_cvss_metric(
                vulnerabilities[0].get(
                    "cve",
                    {},
                )
            )

            for item in cve_to_items[cve]:
                if (
                    score is not None
                    and (
                        item.cvss_score is None
                        or score
                        > item.cvss_score
                    )
                ):
                    item.cvss_score = score
                    item.cvss_severity = (
                        severity
                    )
                    item.cvss_vector = vector

                    if score == 10.0:
                        item.score += 40
                    elif score >= 9.0:
                        item.score += 20
                    elif score >= 8.0:
                        item.score += 10

        except Exception as error:
            warnings.append(
                (
                    f"NVD {cve}: "
                    f"{type(error).__name__}: "
                    f"{error}"
                )
            )

        if index < len(cves) - 1:
            time.sleep(pause)
