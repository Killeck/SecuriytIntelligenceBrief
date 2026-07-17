# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Deterministic classification, relevance, prioritisation and advisory logic."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .config import DEFCON_LEVELS, ZERO_DAY_TERMS
from .rules import (
    ACTIONS,
    CATEGORY_RULES,
    DETECTION_TEMPLATES,
    EXECUTIVE_NEWS_EXCLUDE,
    EXPOSURE_SECTION_ORDER,
    EXPOSURE_SIGNAL_RULES,
    REGIONAL_TERMS,
    RELEVANCE_RULES,
    SECTOR_IMPACT_RULES,
    WHY,
)
from .sources import EXECUTIVE_NEWS_SOURCE_LIMITS
from .models import (
    DetectionOpportunity,
    ExposureSignal,
    Item,
    NewsLink,
    SectorImpact,
    Source,
)
from .utils import clean_text, ensure_utc, extract_cves, integer_setting, truncate


_EXPLICIT_EXPLOITATION_TERMS = (
    "actively exploited",
    "exploited in the wild",
    "under active exploitation",
    "exploitation detected",
    "observed exploitation",
    "known exploitation",
    "used in attacks",
    "attacks exploiting",
    "utnyttes aktivt",
)

_HISTORICAL_CONTEXT_TERMS = (
    "retrospective",
    "post-mortem",
    "last year",
    "previous year",
    "historical",
    "previously disclosed",
    "analysis of the",
)

_RESEARCH_CONTEXT_TERMS = (
    "vulnerability management",
    "security research",
    "research report",
    "researchers analysed",
    "researchers analyzed",
    "mean time-to-exploit",
    "time-to-exploit",
    "exploit development",
    "proof of concept",
    "proof-of-concept",
    "m-trends",
    "technical analysis",
    "blueprint",
)

_CONCRETE_INCIDENT_TERMS = (
    "breached",
    "compromised",
    "stolen credentials",
    "credentials exposed",
    "data stolen",
    "data leaked",
    "victim claim",
    "claimed responsibility",
    "ransom demand",
    "encrypted systems",
    "confirmed incident",
    "confirmed compromise",
    "used in attacks",
    "attacks exploiting",
)

_WIDESPREAD_TERMS = (
    "widespread exploitation",
    "mass exploitation",
    "large-scale exploitation",
    "internet-wide scanning",
    "internet wide scanning",
    "global exploitation campaign",
    "wormable",
    "broad exploitation campaign",
)

_PRIORITY_VENDOR_TERMS = (
    "microsoft",
    "fortinet",
    "palo alto",
    "cisco",
    "crowdstrike",
    "google",
    "aws",
    "apple",
    "okta",
    "hpe",
    "aruba",
)

_HIGH_IMPACT_TERMS = (
    "pre-authentication",
    "pre-auth",
    "remote code execution",
    "arbitrary code execution",
    "authentication bypass",
    "mfa bypass",
    "token theft",
    "credential theft",
    "supply-chain compromise",
    "destructive attack",
    "operational disruption",
)

_AUTHORITATIVE_SOURCE_TERMS = (
    "cisa",
    "nvd",
    "microsoft security response center",
    "cert-eu",
    "psirt",
    "security advisory",
    "nsm",
)

_EPSS_PATTERN = re.compile(r"EPSS:\s*(\d+(?:\.\d+)?)%", re.IGNORECASE)


def _contains_any(text: str, terms: tuple[str, ...]) -> bool:
    """Return whether normalised text contains any configured phrase."""

    lowered = text.lower()
    return any(term in lowered for term in terms)


def _explicit_exploitation(text: str) -> bool:
    """Require explicit evidence before marking a feed item as exploited."""

    return _contains_any(text, _EXPLICIT_EXPLOITATION_TERMS)


def _confirmed_exploitation(
    title: str,
    summary: str,
    source: Source,
) -> bool:
    """Require concrete, source-aware evidence of real-world exploitation.

    Research articles frequently discuss exploitation metrics, techniques or
    proof-of-concept work without reporting an active campaign. Those records
    must not drive the enterprise threat level.
    """

    combined = f"{title} {summary}".lower()
    if not _explicit_exploitation(combined):
        return False

    title_has_evidence = _explicit_exploitation(title.lower())
    cves = extract_cves(combined)
    authoritative = (
        source.vendor.lower() in _PRIORITY_VENDOR_TERMS
        or _contains_any(source.name, _AUTHORITATIVE_SOURCE_TERMS)
        or source.section in {
            "Known Exploited Vulnerabilities",
            "Other Vendor Advisories",
            "Fortinet",
            "Microsoft, Azure and Identity",
        }
    )

    if _contains_any(combined, _RESEARCH_CONTEXT_TERMS) and not (
        title_has_evidence or cves
    ):
        return False

    return bool(title_has_evidence or cves or authoritative)


def _is_widespread_item(item: Item) -> bool:
    """Return whether reporting explicitly indicates broad exploitation."""

    return _contains_any(
        f"{item.title} {item.summary} {item.why}",
        _WIDESPREAD_TERMS,
    )


def _is_priority_vendor(item: Item) -> bool:
    """Return whether an item concerns a priority enterprise vendor."""

    vendor = item.vendor.lower()
    return any(term in vendor for term in _PRIORITY_VENDOR_TERMS)


def _current_zero_day(title: str, summary: str) -> bool:
    """Identify current zero-day reporting while suppressing retrospectives."""

    combined = f"{title} {summary}".lower()
    if not any(term in combined for term in ZERO_DAY_TERMS):
        return False
    if _contains_any(combined, _HISTORICAL_CONTEXT_TERMS) and not _explicit_exploitation(combined):
        return False
    return True


def _epss_probability(item: Item) -> float:
    """Extract the EPSS probability appended by the enrichment collector."""

    match = _EPSS_PATTERN.search(item.why or "")
    if not match:
        return 0.0
    try:
        return float(match.group(1)) / 100.0
    except ValueError:
        return 0.0


def item_threat_score(item: Item) -> tuple[int, list[str]]:
    """Score one primary item using evidence, impact and operational reach.

    This is intentionally more conservative than the collection relevance
    score. A single KEV or critical CVSS record represents urgent triage, but
    does not by itself mean the enterprise threat landscape is High.
    """

    score = 0
    basis: list[str] = []
    combined = f"{item.title} {item.summary} {item.why}".lower()
    authoritative = item.kev or _contains_any(
        item.source,
        _AUTHORITATIVE_SOURCE_TERMS,
    )
    widespread = _is_widespread_item(item)

    if item.exploited:
        score += 18
        basis.append("confirmed exploitation")
    if item.kev:
        score += 12
        basis.append("CISA KEV")
    if item.zero_day:
        score += 10
        basis.append("current zero-day")

    if item.cvss_score is not None:
        if item.cvss_score >= 10.0:
            score += 7
            basis.append("CVSS 10.0")
        elif item.cvss_score >= 9.0:
            score += 5
            basis.append("CVSS critical")
        elif item.cvss_score >= 8.0:
            score += 3
            basis.append("CVSS high")

    epss = _epss_probability(item)
    if epss >= 0.50:
        score += 8
        basis.append("EPSS at least 50%")
    elif epss >= 0.20:
        score += 4
        basis.append("EPSS at least 20%")
    elif epss >= 0.05:
        score += 2
        basis.append("EPSS at least 5%")

    if _contains_any(combined, _HIGH_IMPACT_TERMS):
        score += 7
        basis.append("high-impact attack path")
    if widespread:
        score += 10
        basis.append("widespread exploitation evidence")
    if _is_priority_vendor(item):
        score += 4
        basis.append("priority enterprise vendor")

    if item.category == "Nation-state activity":
        score += 6
        basis.append("credible state-linked campaign")
    elif item.ransomware:
        score += 4 if (item.exploited or item.kev) else 2
        basis.append("ransomware relevance")

    if authoritative and (
        item.exploited
        or item.kev
        or item.zero_day
        or item.cvss_score is not None
    ):
        score += 3
        basis.append("authoritative source")

    if _contains_any(combined, _HISTORICAL_CONTEXT_TERMS) and not item.exploited:
        score -= 12
        basis.append("historical context")

    routine = not any(
        (item.exploited, item.kev, item.zero_day, item.ransomware)
    )
    if routine and (
        item.cvss_score is None or item.cvss_score < 8.0
    ) and item.category != "Nation-state activity":
        score = min(score, 18)
    elif routine and item.cvss_score is not None and item.cvss_score >= 9.0:
        # A non-exploited critical-severity vulnerability warrants normal
        # Guarded attention, but not an elevated enterprise state.
        score = max(score, 20)

    # KEV confirms exploitation, but without a zero-day or evidence of broad
    # operational reach it remains an Elevated enterprise concern.
    if item.kev and not item.zero_day and not widespread:
        score = min(score, 49)
    if item.exploited and not item.zero_day and not widespread:
        score = min(score, 54)

    return max(0, min(score, 79)), basis


def _direct_exposure(signal: ExposureSignal) -> bool:
    """Return whether an exposure signal is tied to an authorised domain query."""

    return (
        signal.confidence == "Domain ownership verified"
        or signal.source == "Have I Been Pwned Domain Search"
    )


def exposure_threat_score(signal: ExposureSignal) -> tuple[int, list[str]]:
    """Score exposure intelligence while preserving confidence boundaries."""

    score = 0
    basis: list[str] = []
    severity_points = {
        "Critical": 20,
        "High": 14,
        "Elevated": 8,
        "Guarded": 3,
        "Low": 0,
    }
    score += severity_points.get(signal.severity, 0)

    confidence = signal.confidence.lower()
    if signal.confidence == "Domain ownership verified":
        score += 45
        basis.append("verified monitored domain")
    elif signal.confidence == "Verified":
        score += 15
        basis.append("verified dataset")
    elif signal.confidence == "Primary or research source":
        score += 6
        basis.append("primary or research source")
    elif "secondary" in confidence:
        basis.append("secondary reporting")
    elif "unverified" in confidence:
        score -= 20
        basis.append("unverified claim")

    type_points = {
        "Credential Exposure and Stealer Logs": 18,
        "Ransomware and Extortion": 9,
        "Data Breaches and Leaks": 8,
        "Initial Access and Cybercrime Markets": 9,
        "Brand, Impersonation and Phishing": 6,
        "Dark Web and Criminal Ecosystem": 3,
    }
    score += type_points.get(signal.signal_type, 0)

    combined = f"{signal.title} {signal.summary}".lower()
    if _contains_any(combined, _CONCRETE_INCIDENT_TERMS):
        score += 5
        basis.append("concrete incident language")

    if _direct_exposure(signal):
        score += 20
        basis.append("direct organisational exposure")

    score = max(0, score)
    if "unverified" in confidence:
        score = min(score, 14)
    elif "secondary" in confidence:
        score = min(score, 29)
    elif signal.confidence == "Primary or research source" and not _direct_exposure(signal):
        score = min(score, 39)
    elif signal.confidence == "Verified" and not _direct_exposure(signal):
        score = min(score, 59)

    return min(score, 100), basis


def _level_for_score(score: int) -> int:
    """Map a conservative operational score to the five-level scale."""

    if score >= 80:
        return 1
    if score >= 60:
        return 2
    if score >= 40:
        return 3
    if score >= 20:
        return 4
    return 5

def classify(
    text: str,
    source: Source,
    *,
    allow_active_exploitation: bool = True,
) -> tuple[str, int]:
    """Assign a deterministic category and relevance weight to source text.

    Rules are evaluated in configured order. Source-specific fallbacks preserve
    meaningful section placement even when no general keyword category matches.
    """

    lowered = text.lower()

    # Rules are deliberately first-match: ordering therefore expresses
    # category precedence as well as keyword membership.
    for category, keywords, weight in CATEGORY_RULES:
        if category == "Active exploitation" and not allow_active_exploitation:
            continue
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
    """Map a classified record into its final report section.

    Vendor-specific and governance-specific routing takes precedence over the
    source's default section so the report structure stays predictable.
    """

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
    """Return ``True`` when text appears promotional rather than operational."""

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
    """Build a validated and scored primary security item."""

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

    cves = extract_cves(combined)
    exploited = _confirmed_exploitation(title, summary, source)
    category, weight = classify(
        combined,
        source,
        allow_active_exploitation=exploited,
    )

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

    zero_day = _current_zero_day(title, summary)
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


def executive_news_relevance(
    title: str,
    summary: str,
    base_score: int,
) -> tuple[int, list[str]]:
    """Score a secondary-news story against the configured advisory priorities.

    The result combines publisher baseline, technology, geography, sector and
    high-impact keyword weights. Promotional content receives a negative score and
    is excluded before report selection.
    """

    combined = f" {clean_text(title)} {clean_text(summary)} ".lower()

    if any(term in combined for term in EXECUTIVE_NEWS_EXCLUDE):
        return -100, []

    score = base_score
    tags: list[str] = []

    # A story may match several dimensions simultaneously, for example
    # Microsoft + identity + Europe. All matching dimensions contribute.
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
    """Validate, score and construct a secondary-news discovery record."""

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

def news_title_tokens(title: str) -> set[str]:
    """Tokenise a headline for lightweight similarity comparison."""

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
    """Calculate Jaccard similarity between two normalised headline token sets."""

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
    """Select a diverse, deduplicated set of executive-news links.

    Stories already represented by primary intelligence are suppressed. The
    selection also enforces near-duplicate removal and per-publisher limits.
    """

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

    # Selection is intentionally conservative: prefer fewer distinct stories
    # over several publishers repeating the same underlying event.
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
    """Derive the strongest advisory implication for each monitored customer sector."""

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
    """Create deterministic detection opportunities from primary items.

    Only one opportunity is normally selected per category to keep the SOC section
    concise and prevent repeated generic recommendations.
    """

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
    """Select developments with specific Scandinavian or European relevance."""

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

def exposure_severity_rank(severity: str) -> int:
    """Convert an exposure severity label into a sortable numeric rank."""

    return {
        "Critical": 4,
        "High": 3,
        "Elevated": 2,
        "Guarded": 1,
        "Low": 0,
    }.get(severity, 1)

def matched_monitored_references(
    combined: str,
    monitored_brands: tuple[str, ...],
    monitored_domains: tuple[str, ...],
) -> list[str]:
    """Return configured brands or domains mentioned in supplied text."""

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
    """Derive credible exposure signals from incident-oriented reporting.

    Vulnerability research and exploit-development articles are excluded unless
    they contain concrete incident language or directly mention a monitored
    reference. This prevents research material from becoming a breach signal.
    """

    records = [
        (
            item.title,
            item.summary,
            item.source,
            item.link,
            item.published,
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
            (
                "Unverified claim"
                if link.source == "Ransomware.live"
                or "Unverified claim" in link.tags
                else "Secondary reporting"
            ),
        )
        for link in news_links
    )

    signals: list[ExposureSignal] = []

    for title, summary, source, link, observed, confidence in records:
        combined = f" {title} {summary} "
        lowered = combined.lower()
        matches = matched_monitored_references(
            combined,
            monitored_brands,
            monitored_domains,
        )
        concrete_incident = _contains_any(
            lowered,
            _CONCRETE_INCIDENT_TERMS,
        )
        research_context = _contains_any(
            lowered,
            _RESEARCH_CONTEXT_TERMS,
        )

        if research_context and not concrete_incident and not matches:
            continue

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

            if (
                confidence == "Primary or research source"
                and not concrete_incident
                and not matches
                and keyword_hits < 2
            ):
                continue

            confidence_base = {
                "Primary or research source": 18,
                "Secondary reporting": 10,
                "Unverified claim": 0,
            }.get(confidence, 0)
            candidate_score = (
                confidence_base
                + weight
                + min(keyword_hits * 4, 12)
            )
            if concrete_incident:
                candidate_score += 8
            if matches:
                candidate_score += 35

            if matched_rule is None or candidate_score > matched_rule[0]:
                matched_rule = (
                    candidate_score,
                    signal_type,
                    default_severity,
                    action,
                )

        if matched_rule is None:
            continue

        score, signal_type, severity, action = matched_rule
        if confidence == "Unverified claim":
            severity = "Guarded"
        elif matches and score >= 90:
            severity = "Critical"
        elif score >= 72 and severity in {"Guarded", "Elevated"}:
            severity = "High"
        elif score >= 50 and severity == "Guarded":
            severity = "Elevated"

        affected = (
            "Potential monitored reference: " + ", ".join(matches) + "."
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

    return signals[: max_items * 3]


def deduplicate_exposure_signals(
    signals: list[ExposureSignal],
    max_items: int,
) -> list[ExposureSignal]:
    """Sort, deduplicate and limit exposure signals for the final report."""

    # Severity takes precedence over the raw score so a verified critical
    # exposure cannot be displaced by a large volume of low-impact reporting.
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
    """Group exposure signals into the configured dark-web report sections."""

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
    """Calculate an independent, confidence-aware advisory level."""

    enterprise = defcon_status(items)
    candidates: list[tuple[int, list[str], bool]] = [
        (
            int(enterprise.get("score", 0)),
            list(enterprise.get("basis", [])),
            False,
        )
    ]
    for signal in exposure_signals:
        score, basis = exposure_threat_score(signal)
        candidates.append((score, basis, _direct_exposure(signal)))

    score, basis, direct_exposure = max(
        candidates,
        key=lambda value: value[0],
    )

    credible_count = sum(
        1
        for value, candidate_basis, _ in candidates
        if value >= 40
        and "secondary reporting" not in candidate_basis
        and "unverified claim" not in candidate_basis
    )
    if credible_count >= 3:
        score += 3
        basis = basis + ["multiple credible developments"]

    if not direct_exposure:
        score = min(score, 79)

    level = _level_for_score(score)
    definition = DEFCON_LEVELS[level]
    return {
        "level": level,
        "label": definition["label"],
        "colour": definition["colour"],
        "text_colour": definition["text_colour"],
        "display": definition["label"],
        "score": score,
        "basis": basis,
    }


def advisory_actions(
    items: list[Item],
    signals: list[ExposureSignal],
) -> list[str]:
    """Build the highest-priority response actions for the executive advisory."""

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

def select_final_items(
    items: list[Item],
    max_items: int,
) -> list[Item]:
    """Select the final balanced set of primary intelligence items.

    Zero-days, CVSS 10.0 vulnerabilities and KEV entries are mandatory. The
    remaining capacity reserves limited representation for each report section
    before filling by overall score.
    """

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

    # Mandatory critical items are inserted first, followed by section floors
    # and finally the global score order.
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
    """Deduplicate primary items by CVE set or canonicalised source link."""

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
    """Translate weighted operational risk into a display priority."""

    score, _ = item_threat_score(item)
    if score >= 65:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    return "Monitor"


def defcon_status(items: list[Item]) -> dict[str, Any]:
    """Calculate the enterprise threat landscape without panic escalation.

    The highest item remains important, but High requires explicit evidence of
    widespread exploitation. Critical is reserved for direct organisational
    exposure and is therefore handled by ``advisory_status``.
    """

    scored = [(item, *item_threat_score(item)) for item in items]
    if scored:
        item, score, basis = max(scored, key=lambda value: value[1])
    else:
        item, score, basis = None, 0, []

    credible_count = sum(1 for _, value, _ in scored if value >= 40)
    if credible_count >= 3:
        score += 4
        basis = basis + ["multiple elevated developments"]
    if credible_count >= 6:
        score += 3
        basis = basis + ["sustained elevated activity"]

    high_allowed = bool(
        item
        and item.exploited
        and (item.kev or item.zero_day)
        and _is_widespread_item(item)
    )
    if not high_allowed:
        score = min(score, 59)
        if item and score >= 40:
            basis = basis + ["enterprise exposure not confirmed"]

    # Global intelligence alone cannot declare a Critical enterprise state.
    score = min(score, 79)
    level = _level_for_score(score)
    status = dict(DEFCON_LEVELS[level])
    status["level"] = level
    status["display"] = f"DEFCON {level} — {status['label']}"
    status["score"] = score
    status["basis"] = basis
    return status


def immediate_actions(items: list[Item]) -> list[str]:
    """Generate concise CISO-level actions from the current primary item set."""

    actions: list[str] = []

    if any(item.zero_day or item.cvss_score == 10.0 for item in items):
        actions.append(
            "Prioritise validation of exposure to zero-day and CVSS 10.0 "
            "vulnerabilities and assign named remediation owners."
        )

    if any(item.kev for item in items):
        actions.append(
            "Validate exposure to newly added KEV entries and assign "
            "appropriate remediation owners."
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
