# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Plain-text and HTML report rendering.

Rendering is deliberately side-effect free. It receives already selected and
classified records, which makes it testable without network or SMTP access.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit

from .analysis import (
    advisory_actions,
    advisory_status,
    defcon_status,
    group_exposure_signals,
    priority,
)
from .config import (
    BRIEF_NAME,
    BRIEF_VERSION,
    DEFCON_LEVELS,
    GOVERNANCE_SECTIONS,
    MONITORED_GOVERNANCE_TOPICS,
)
from .rules import EXPOSURE_SECTION_ORDER
from .governance import GOVERNANCE_HORIZONS
from .models import (
    DetectionOpportunity,
    ExposureSignal,
    Item,
    NewsLink,
    SectorImpact,
)
from .utils import truncate


_BLOCKED_EMAIL_LINK_HOSTS = {
    "ransomware.live",
    "www.ransomware.live",
    "api.ransomware.live",
}


_VENDOR_INFORMATION_URLS = {
    "Microsoft": "https://msrc.microsoft.com/update-guide/",
    "Fortinet": "https://www.fortiguard.com/psirt",
    "Palo Alto": "https://security.paloaltonetworks.com/",
    "Cisco": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    "HPE / Aruba": "https://support.hpe.com/connect/s/securitybulletinlibrary",
}

_VENDOR_NAME_INFORMATION_URLS = {
    "amazon": "https://aws.amazon.com/security/security-bulletins/",
    "aws": "https://aws.amazon.com/security/security-bulletins/",
    "google": "https://cloud.google.com/support/bulletins",
    "okta": "https://trust.okta.com/security-advisories/",
    "apple": "https://support.apple.com/en-us/100100",
    "adobe": "https://helpx.adobe.com/security.html",
    "atlassian": "https://www.atlassian.com/trust/security/advisories",
    "broadcom": "https://support.broadcom.com/security-advisories",
    "vmware": "https://support.broadcom.com/web/ecx/security-advisory",
    "ivanti": "https://forums.ivanti.com/s/security-advisories",
    "oracle": "https://www.oracle.com/security-alerts/",
    "sap": "https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html",
}


def _email_link_allowed(
    url: str,
    *,
    source: str = "",
    confidence: str = "",
    tags: Iterable[str] = (),
) -> bool:
    """Keep unverified or high-risk discovery URLs out of the email body."""

    if not url:
        return False
    lowered_source = source.lower()
    lowered_confidence = confidence.lower()
    lowered_tags = {str(tag).lower() for tag in tags}
    if "ransomware.live" in lowered_source:
        return False
    if "unverified" in lowered_confidence or "unverified claim" in lowered_tags:
        return False
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    host = parsed.netloc.lower().split(":", 1)[0]
    if host.endswith(".onion") or host in _BLOCKED_EMAIL_LINK_HOSTS:
        return False
    return True


def _plain_email_link(
    url: str,
    *,
    source: str = "",
    confidence: str = "",
    tags: Iterable[str] = (),
) -> str:
    """Return a URL or an explicit withheld-link marker for plain text."""

    if _email_link_allowed(
        url,
        source=source,
        confidence=confidence,
        tags=tags,
    ):
        return url
    return "Link withheld from email"

def _email_source_label(source: str) -> str:
    """Return a neutral label for sources unsuitable for corporate email."""

    if source.lower() == "ransomware.live":
        return "Open-source ransomware claim monitor"
    return source


def _source_health_label(source: str) -> str:
    """Return a restrained source-health label for outbound reports."""

    return _email_source_label(source)

def render_item_text(item: Item, number: int) -> list[str]:
    """Render one primary intelligence item for the plain-text email body."""

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
    """Render one primary intelligence item as a bordered HTML advisory card."""

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
    """Render one exposure signal for the plain-text email body."""

    return [
        "",
        f"{number}. [{signal.severity}] {signal.title}",
        f"   Signal type: {signal.signal_type}",
        f"   Source: {_email_source_label(signal.source)}",
        (
            "   Observed: "
            f"{signal.observed.strftime('%Y-%m-%d %H:%M UTC')}"
        ),
        f"   Confidence: {signal.confidence}",
        f"   Summary: {signal.summary}",
        f"   Potentially affected: {signal.affected}",
        f"   Advisory action: {signal.action}",
        f"   Link: {_plain_email_link(signal.link, source=signal.source, confidence=signal.confidence)}",
    ]

def render_exposure_html(signal: ExposureSignal) -> str:
    """Render one exposure signal as a distinct HTML exposure card."""

    source_link = _link(
        "Open supporting source",
        signal.link,
        source=signal.source,
        confidence=signal.confidence,
    )
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
          <td>{html.escape(_email_source_label(signal.source))}</td>
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

      <p>{source_link}</p>
    </article>
    <hr style="
        border:0;
        border-top:1px solid #b8bec5;
        margin:24px 0 28px 0;
        width:100%;
    ">
    """


@dataclass(frozen=True)
class ReportContext:
    """Shared derived report state used by both output formats."""

    status: dict[str, Any]
    enterprise_status: dict[str, Any]
    actions: list[str]
    exposure_grouped: dict[str, list[ExposureSignal]]
    critical_special: list[Item]
    top_advisories: list[Item]
    top_exposure: list[ExposureSignal]
    major_governance: list[Item]
    primary_section_order: tuple[str, ...]
    section_titles: dict[str, str]
    grouped: dict[str, list[Item]]
    monitored_topics: str
    monitored_references: tuple[str, ...]
    report_title: str
    ransomware_watch: list[ExposureSignal]
    credential_watch: list[ExposureSignal]
    active_sources: list[dict[str, Any]]
    failed_sources: list[dict[str, Any]]
    quiet_source_count: int


def build_report_context(
    items: list[Item],
    exposure_signals: list[ExposureSignal],
    source_health: list[dict[str, Any]],
    monitored_brands: tuple[str, ...],
    monitored_domains: tuple[str, ...],
) -> ReportContext:
    """Derive report-wide state once for consistent text and HTML output."""

    status = advisory_status(items, exposure_signals)
    enterprise_status = defcon_status(items)
    exposure_grouped = group_exposure_signals(exposure_signals)

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
    grouped = {section: [] for section in primary_section_order}
    for item in items:
        grouped.setdefault(item.section, []).append(item)

    return ReportContext(
        status=status,
        enterprise_status=enterprise_status,
        actions=advisory_actions(items, exposure_signals),
        exposure_grouped=exposure_grouped,
        critical_special=[
            item
            for item in items
            if item.zero_day
            or (item.cvss_score is not None and item.cvss_score >= 9.0)
        ],
        top_advisories=items[:5],
        top_exposure=exposure_signals[:5],
        major_governance=[
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
        ],
        primary_section_order=primary_section_order,
        section_titles=section_titles,
        grouped=grouped,
        monitored_topics=", ".join(MONITORED_GOVERNANCE_TOPICS),
        monitored_references=monitored_brands + monitored_domains,
        report_title=f"{BRIEF_NAME} v{BRIEF_VERSION}",
        ransomware_watch=exposure_grouped.get(
            "Ransomware and Extortion",
            [],
        )[:3],
        credential_watch=exposure_grouped.get(
            "Credential Exposure and Stealer Logs",
            [],
        )[:3],
        active_sources=[
            health
            for health in source_health
            if health["status"] == "OK" and health["items"] > 0
        ],
        failed_sources=[
            health
            for health in source_health
            if health["status"] != "OK"
        ],
        quiet_source_count=sum(
            1
            for health in source_health
            if health["status"] == "OK" and health["items"] == 0
        ),
    )


def _bind_context(context: ReportContext) -> tuple[Any, ...]:
    """Return context values for compact local assignment in renderers."""

    return (
        context.status,
        context.enterprise_status,
        context.actions,
        context.exposure_grouped,
        context.critical_special,
        context.top_advisories,
        context.top_exposure,
        context.major_governance,
        context.primary_section_order,
        context.section_titles,
        context.grouped,
        context.monitored_topics,
        context.monitored_references,
        context.report_title,
        context.ransomware_watch,
        context.credential_watch,
        context.active_sources,
        context.failed_sources,
        context.quiet_source_count,
    )


def render_text_report(
    context: ReportContext,
    items: list[Item],
    warnings: list[str],
    lookback_hours: int,
    upcoming_events: list[dict[str, str]],
    upcoming_days: int,
    executive_news: list[NewsLink],
    sector_impacts: list[SectorImpact],
    detection_opportunities: list[DetectionOpportunity],
    regional_links: list[NewsLink],
    exposure_signals: list[ExposureSignal],
) -> str:
    """Render the complete plain-text briefing."""

    (
        status,
        enterprise_status,
        actions,
        exposure_grouped,
        critical_special,
        top_advisories,
        top_exposure,
        major_governance,
        primary_section_order,
        section_titles,
        grouped,
        monitored_topics,
        monitored_references,
        report_title,
        ransomware_watch,
        credential_watch,
        active_sources,
        failed_sources,
        quiet_source_count,
    ) = _bind_context(context)

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
                f"{signal.title} — {_email_source_label(signal.source)}: {_plain_email_link(signal.link, source=signal.source, confidence=signal.confidence)}"
            )

    if ransomware_watch:
        text.extend(["", "Ransomware and Extortion Watch"])
        for signal in ransomware_watch:
            text.append(
                f"- [{signal.confidence}] {signal.title} "
                f"— {_email_source_label(signal.source)}: {_plain_email_link(signal.link, source=signal.source, confidence=signal.confidence)}"
            )

    if credential_watch:
        text.extend(["", "Credential and Stealer Exposure"])
        for signal in credential_watch:
            text.append(
                f"- [{signal.confidence}] {signal.title} "
                f"— {_email_source_label(signal.source)}: {_plain_email_link(signal.link, source=signal.source, confidence=signal.confidence)}"
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
                f"— {news_link.source}: {_plain_email_link(news_link.link, source=news_link.source, tags=news_link.tags)}"
            )

    text.extend(["", "Critical Vulnerabilities and Zero-Days"])

    if critical_special:
        for item in critical_special:
            markers = []
            if item.zero_day:
                markers.append("Zero-Day")
            if item.cvss_score is not None and item.cvss_score >= 9.0:
                markers.append(f"CVSS {item.cvss_score:.1f} Critical")
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

    text.extend(["", "Governance Forward Look"])
    for label, _, _ in GOVERNANCE_HORIZONS:
        horizon_events = [
            event for event in upcoming_events
            if event.get("horizon") == label
        ]
        text.append(f"- {label}:")
        if horizon_events:
            for event in horizon_events[:2]:
                text.append(
                    f"  {event['date']}: {event['title']} "
                    f"({event.get('topic') or event.get('source')})"
                )
        else:
            text.append("  No confirmed milestone currently recorded.")

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

    if active_sources or failed_sources or quiet_source_count:
        text.extend(["", "Source Coverage", "---------------"])

    for health in active_sources:
        text.append(
            f"- {_source_health_label(health['source'])}: {health['items']} qualifying item(s)."
        )

    if quiet_source_count:
        text.append(
            f"- {quiet_source_count} additional source(s) checked with "
            "no qualifying updates."
        )

    for health in failed_sources:
        text.append(
            f"- {_source_health_label(health['source'])}: temporarily unavailable."
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
            "- Material EU AI Act, NIS2, Sikkerhetsloven, DORA and standards deadlines.",
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

    text.extend(
        [
            "",
            "Ownership",
            "---------",
            (
                "Daily Security Brief © 2026 John-Helge Gantz. "
                "Report format and software implementation are proprietary. "
                "Third-party source content remains the property of its "
                "respective publishers."
            ),
        ]
    )

    return "\n".join(text)



# ---------------------------------------------------------------------------
# Compact dashboard HTML helpers
# ---------------------------------------------------------------------------

DASHBOARD_COLOURS = {
    "background": "#0b1118",
    "panel": "#121a24",
    "panel_alt": "#17212d",
    "border": "#2a3644",
    "text": "#eef3f8",
    "muted": "#9caabd",
    "link": "#c084fc",
    "critical": "#ff5f57",
    "high": "#ff9f43",
    "medium": "#f6c945",
    "highlight": "#f6c768",
    "blue": "#6ea8fe",
    "cyan": "#53c7ea",
    "green": "#4dd4ac",
    "purple": "#b778ff",
}


def _escape(value: object) -> str:
    """HTML-escape a value for compact dashboard fragments."""

    return html.escape(str(value or ""))


def _severity_colour(label: str) -> str:
    """Map a report severity or status label to a dashboard accent colour."""

    lowered = label.lower()

    if "critical" in lowered or "exploited" in lowered:
        return DASHBOARD_COLOURS["critical"]
    if "high" in lowered or "active" in lowered:
        return DASHBOARD_COLOURS["high"]
    if "medium" in lowered or "elevated" in lowered:
        return DASHBOARD_COLOURS["medium"]
    if "low" in lowered or "guarded" in lowered:
        return DASHBOARD_COLOURS["blue"]
    return DASHBOARD_COLOURS["green"]


def _pill(text: str, colour: str | None = None) -> str:
    """Render a small email-safe status pill."""

    resolved = colour or _severity_colour(text)
    return (
        '<span style="display:inline-block;'
        f'background:{resolved}22;'
        f'border:1px solid {resolved}66;'
        f'color:{resolved};'
        'font-size:11px;font-weight:700;line-height:1;'
        'padding:5px 7px;border-radius:4px;white-space:nowrap;">'
        f'{_escape(text)}</span>'
    )


def _link(
    label: str,
    url: str,
    *,
    source: str = "",
    confidence: str = "",
    tags: Iterable[str] = (),
    colour: str | None = None,
) -> str:
    """Render a restrained link or safe withheld-link label."""

    if not _email_link_allowed(
        url,
        source=source,
        confidence=confidence,
        tags=tags,
    ):
        return (
            f'<span style="color:{DASHBOARD_COLOURS["muted"]};">'
            f'{_escape(label)} (link withheld)</span>'
        )
    resolved_colour = colour or DASHBOARD_COLOURS["link"]
    return (
        f'<a href="{html.escape(url, quote=True)}" '
        f'style="color:{resolved_colour};'
        'text-decoration:underline;">'
        f'{_escape(label)}</a>'
    )


def _panel(
    title: str,
    body: str,
    accent: str = "#6ea8fe",
    anchor_id: str = "",
) -> str:
    """Wrap content in a reusable dark email panel.

    When ``anchor_id`` is supplied, the visible panel heading becomes the
    named destination. A visible, non-empty anchor is retained more reliably
    by email clients than an empty or zero-height anchor placed before a table.
    """

    title_html = _escape(title)

    if anchor_id:
        safe_anchor = html.escape(anchor_id, quote=True)
        title_html = (
            f'<a id="{safe_anchor}" name="{safe_anchor}" '
            f'style="color:{accent};text-decoration:none;">'
            f'{_escape(title)}</a>'
        )

    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="border-collapse:separate;border-spacing:0;
                  background:{DASHBOARD_COLOURS['panel']};
                  border:1px solid {DASHBOARD_COLOURS['border']};
                  border-radius:8px;margin:0 0 12px 0;">
      <tr>
        <td style="padding:14px 16px 8px 16px;
                   color:{accent};font-size:16px;font-weight:700;">
          {title_html}
        </td>
      </tr>
      <tr>
        <td style="padding:4px 16px 16px 16px;
                   color:{DASHBOARD_COLOURS['text']};">
          {body}
        </td>
      </tr>
    </table>
    """


def _metric_card(
    title: str,
    value: str,
    icon: str,
    accent: str,
    detail: str,
    anchor_id: str = "",
) -> str:
    """Render one top-level metric card as a single clickable control.

    The link wraps the complete visual card rather than only its individual
    text fragments. This gives the full box one destination and avoids
    duplicate links inside the same card.
    """

    card_style = (
        f'display:block;background:{DASHBOARD_COLOURS["panel"]};'
        f'border:1px solid {DASHBOARD_COLOURS["border"]};'
        'border-radius:7px;text-decoration:none;color:inherit;'
        'width:100%;box-sizing:border-box;cursor:pointer;'
    )

    if anchor_id:
        safe_anchor = html.escape(anchor_id, quote=True)
        safe_label = html.escape(f"Jump to {title}", quote=True)
        card_start = (
            f'<a href="#{safe_anchor}" aria-label="{safe_label}" '
            f'style="{card_style}">'
        )
        card_end = "</a>"
    else:
        card_start = f'<div style="{card_style}">'
        card_end = "</div>"

    return f"""
    <td width="16.66%" valign="top" style="padding:4px;">
      {card_start}
        <span style="display:block;padding:11px 10px 5px 10px;
                     color:{accent};font-size:11px;font-weight:700;">
          {_escape(title)}
        </span>
        <span style="display:block;padding:0 10px;
                     color:{DASHBOARD_COLOURS['text']};
                     font-size:20px;font-weight:700;white-space:nowrap;">
          <span style="color:{accent};font-size:20px;">
            {_escape(icon)}
          </span>
          <span style="color:{DASHBOARD_COLOURS['text']};">
            {_escape(value)}
          </span>
        </span>
        <span style="display:block;padding:5px 10px 11px 10px;
                     color:{DASHBOARD_COLOURS['muted']};font-size:10px;">
          {_escape(detail)}
        </span>
      {card_end}
    </td>
    """


def _render_defcon_triangle(current_level: int) -> str:
    """Render a layered triangle that explains the enterprise DEFCON scale."""

    layer_widths = {1: "36%", 2: "50%", 3: "64%", 4: "78%", 5: "92%"}
    descriptions = {
        1: "Immediate action: direct exposure or exceptional verified threat.",
        2: "Urgent action required for relevant active exploitation.",
        3: "Credible increased risk requiring enhanced attention.",
        4: "Meaningful developments, but no immediate direct exposure.",
        5: "Routine background threat activity and normal monitoring.",
    }

    rows: list[str] = []
    for level in range(1, 6):
        definition = DEFCON_LEVELS[level]
        is_current = level == current_level
        current_label = ""
        if is_current:
            current_label = (
                '<div style="margin-top:4px;font-size:10px;font-weight:700;'
                f'color:{definition["text_colour"]};">Current enterprise level</div>'
            )
        border = '2px solid #FFFFFF' if is_current else f'1px solid {DASHBOARD_COLOURS["border"]}'
        rows.append(
            f"""
            <tr>
              <td align="center" style="padding:0 0 6px 0;">
                <table role="presentation" width="{layer_widths[level]}" cellspacing="0" cellpadding="0"
                       style="width:{layer_widths[level]};margin:0 auto;border-collapse:separate;">
                  <tr>
                    <td style="padding:8px 10px;border-radius:6px;border:{border};
                               background:{definition['colour']};
                               color:{definition['text_colour']};text-align:center;">
                      <div style="font-size:12px;font-weight:700;line-height:1.2;">
                        DEFCON {level} — {_escape(definition['label'])}
                      </div>
                      <div style="font-size:10px;line-height:1.35;margin-top:3px;">
                        {_escape(descriptions[level])}
                      </div>
                      {current_label}
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            """
        )

    current_display = _escape(DEFCON_LEVELS[current_level]["label"])
    return (
        f'<div style="color:{DASHBOARD_COLOURS["muted"]};font-size:11px;line-height:1.35;margin-bottom:10px;">'
        f'Layered enterprise threat scale. Current enterprise level: <strong style="color:{DASHBOARD_COLOURS["text"]};">DEFCON {current_level} — {current_display}</strong>.'
        '</div>'
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        + ''.join(rows)
        + '</table>'
    )


def _bold_prefix_html(text: str) -> str:
    """Escape text and bold the first meaningful label before a colon."""

    prefix, separator, remainder = text.partition(":")
    if separator and prefix.strip() and remainder.strip():
        return (
            f'<strong style="color:{DASHBOARD_COLOURS["highlight"]};">'
            f'{_escape(prefix.strip())}</strong>: {_escape(remainder.strip())}'
        )
    return _escape(text)


def _compact_bullet(text: str, accent: str = "#6ea8fe") -> str:
    """Render one short TL;DR line with a bold label before the first colon."""

    return (
        '<tr><td valign="top" style="padding:3px 8px 3px 0;'
        f'color:{accent};font-weight:700;">•</td>'
        f'<td style="padding:3px 0;color:{DASHBOARD_COLOURS["text"]};'
        f'font-size:13px;line-height:1.35;">{_bold_prefix_html(text)}</td></tr>'
    )


def _short_tldr(item: Item, limit: int = 120) -> str:
    """Produce a compact one-line summary for a primary advisory."""

    source = item.summary if item.summary and "No source summary" not in item.summary else item.why
    return truncate(source, limit)


def _exploit_label(item: Item) -> str:
    """Return a concise exploitation-status label."""

    if item.kev:
        return "CISA KEV"
    if item.exploited:
        return "Exploited"
    if item.zero_day:
        return "Zero-Day"
    return "No evidence"


def _render_vulnerability_table(items: list[Item], limit: int = 8) -> str:
    """Render the critical/high vulnerability digest table."""

    selected = [
        item for item in items
        if item.zero_day
        or (item.cvss_score is not None and item.cvss_score >= 9.0)
    ][:limit]

    if not selected:
        return (
            f'<p style="margin:0;color:{DASHBOARD_COLOURS["muted"]};">'
            "No critical or zero-day vulnerabilities identified.</p>"
        )

    rows = []
    for item in selected:
        severity = priority(item)
        colour = _severity_colour(severity)
        cve_text = ", ".join(item.cves[:2]) or "—"
        cve_html = (
            _link(cve_text, item.link)
            if item.cves
            else "—"
        )
        cvss = (
            f"{item.cvss_score:.1f}"
            if item.cvss_score is not None
            else "N/A"
        )
        rows.append(
            f"""
            <tr>
              <td style="padding:8px;border-top:1px solid {DASHBOARD_COLOURS['border']};">
                {_pill(severity, colour)}
              </td>
              <td style="padding:8px;border-top:1px solid {DASHBOARD_COLOURS['border']};
                         color:{DASHBOARD_COLOURS['text']};font-weight:700;">
                {_escape(item.vendor or item.source)}
              </td>
              <td style="padding:8px;border-top:1px solid {DASHBOARD_COLOURS['border']};">
                {cve_html}
              </td>
              <td style="padding:8px;border-top:1px solid {DASHBOARD_COLOURS['border']};
                         color:{colour};font-weight:700;">{_escape(cvss)}</td>
              <td style="padding:8px;border-top:1px solid {DASHBOARD_COLOURS['border']};">
                {_pill(_exploit_label(item))}
              </td>
              <td style="padding:8px;border-top:1px solid {DASHBOARD_COLOURS['border']};
                         color:{DASHBOARD_COLOURS['muted']};font-size:12px;">
                {_escape(_short_tldr(item))}
              </td>
            </tr>
            """
        )

    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="border-collapse:collapse;font-size:12px;">
      <tr style="color:{DASHBOARD_COLOURS['muted']};text-align:left;">
        <th style="padding:7px 8px;">Severity</th>
        <th style="padding:7px 8px;">Vendor</th>
        <th style="padding:7px 8px;">CVE</th>
        <th style="padding:7px 8px;">CVSS</th>
        <th style="padding:7px 8px;">Status</th>
        <th style="padding:7px 8px;">TL;DR</th>
      </tr>
      {''.join(rows)}
    </table>
    """


_KNOWN_THREAT_ACTORS = (
    "Scattered Spider",
    "Lazarus Group",
    "Salt Typhoon",
    "Volt Typhoon",
    "Midnight Blizzard",
    "Sandworm",
    "Lotus Blossom",
    "Cl0p",
    "LockBit",
    "Akira",
    "Black Basta",
    "RansomHub",
    "Qilin",
    "ALPHV",
    "BlackCat",
    "Rhysida",
    "Hunters International",
    "DragonForce",
    "Medusa",
    "INC Ransom",
)


def _threat_actor(item: Item) -> tuple[str, str]:
    """Extract a named or suspected actor from source-provided text.

    The helper does not infer attribution from technology, geography or tactics.
    It only surfaces actor names already present in the headline or summary and
    labels tentative source language as suspected.
    """

    text = f"{item.title} {item.summary}"
    lowered = text.lower()
    tentative_terms = (
        "suspected",
        "likely",
        "believed",
        "linked to",
        "associated with",
        "possibly",
    )
    confidence = (
        "Suspected attribution"
        if any(term in lowered for term in tentative_terms)
        else "Named by source"
    )

    for actor in _KNOWN_THREAT_ACTORS:
        if actor.lower() in lowered:
            return actor, confidence

    identifier = re.search(
        r"\b(?:APT|UNC|DEV|TA)[-_]?\d{2,6}\b",
        text,
        flags=re.IGNORECASE,
    )
    if identifier:
        return identifier.group(0).upper(), confidence

    patterns = (
        r"(?:attributed to|claimed by|linked to|associated with|tracked as|"
        r"known as|operated by|members? of)\s+(?:the\s+)?"
        r"([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]+){0,3})",
        r"(?:ransomware|cybercrime|threat)\s+(?:group|gang|actor)\s+"
        r"([A-Z][A-Za-z0-9._-]+(?:\s+[A-Z][A-Za-z0-9._-]+){0,3})",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        actor = match.group(1).strip(" .,:;–—-")
        actor = re.sub(
            r"\s+(?:ransomware|cybercrime|threat|hacking)\s+"
            r"(?:group|gang|actor).*$",
            "",
            actor,
            flags=re.IGNORECASE,
        )
        if actor:
            return actor, confidence

    return "", ""


def _render_threat_rows(items: list[Item], limit: int = 5) -> str:
    """Render active exploitation, ransomware and actor activity as short rows."""

    selected = [
        item for item in items
        if (
            item.exploited
            or item.ransomware
            or item.category in {
                "Nation-state activity",
                "Active exploitation",
                "Ransomware",
                "Threat intelligence",
            }
        )
    ][:limit]

    if not selected:
        return (
            f'<p style="margin:0;color:{DASHBOARD_COLOURS["muted"]};">'
            "No qualifying active exploitation or actor activity.</p>"
        )

    rows = []
    icons = ["☠", "◎", "◉", "◆", "●"]
    for index, item in enumerate(selected):
        severity = priority(item)
        colour = _severity_colour(severity)
        impact = item.category.replace(" activity", "")
        actor, actor_confidence = _threat_actor(item)
        actor_detail = (
            f'<strong style="color:{DASHBOARD_COLOURS["highlight"]};">'
            f'{_escape(actor)}</strong><br>'
            f'<span style="color:{DASHBOARD_COLOURS["muted"]};">'
            f'{_escape(actor_confidence)}</span>'
            if actor
            else (
                f'<span style="color:{DASHBOARD_COLOURS["muted"]};">'
                'Not identified</span>'
            )
        )
        rows.append(
            f"""
            <tr>
              <td width="36" valign="top" style="padding:9px 6px;
                  color:{colour};font-size:20px;text-align:center;">
                {icons[index % len(icons)]}
              </td>
              <td valign="top" style="padding:9px 8px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};">
                <div style="color:{DASHBOARD_COLOURS['highlight']};
                            font-size:13px;font-weight:700;">
                  {_escape(item.title)} &nbsp; {_pill(severity, colour)}
                </div>
                <div style="color:{DASHBOARD_COLOURS['muted']};
                            font-size:12px;line-height:1.35;margin-top:3px;">
                  {_escape(_short_tldr(item, 145))}
                </div>
              </td>
              <td width="155" valign="middle" style="padding:9px 8px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  color:{DASHBOARD_COLOURS['muted']};font-size:11px;">
                Threat actor<br>
                {actor_detail}
              </td>
              <td width="125" valign="middle" style="padding:9px 8px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  color:{DASHBOARD_COLOURS['muted']};font-size:11px;">
                Activity<br>
                <strong style="color:{DASHBOARD_COLOURS['text']};">
                  {_escape(impact)}
                </strong>
              </td>
              <td width="80" valign="middle" style="padding:9px 8px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  font-size:11px;text-align:right;">
                {_link("Source ›", item.link)}
              </td>
            </tr>
            """
        )

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
        'style="border-collapse:collapse;">'
        + "".join(rows)
        + "</table>"
    )


def _render_exposure_cards(signals: list[ExposureSignal], limit: int = 4) -> str:
    """Render dark-web and exposure highlights as four compact cards."""

    selected = signals[:limit]
    if not selected:
        return (
            f'<p style="margin:0;color:{DASHBOARD_COLOURS["muted"]};">'
            "No qualifying dark-web or exposure signals.</p>"
        )

    cells = []
    icons = {
        "Ransomware and Extortion": "🔒",
        "Credential Exposure and Stealer Logs": "▣",
        "Data Breaches and Leaks": "◉",
        "Initial Access and Cybercrime Markets": "⌁",
        "Brand, Impersonation and Phishing": "◎",
        "Dark Web and Criminal Ecosystem": "◈",
    }
    accents = [
        DASHBOARD_COLOURS["purple"],
        DASHBOARD_COLOURS["critical"],
        DASHBOARD_COLOURS["high"],
        DASHBOARD_COLOURS["blue"],
    ]
    for index, signal in enumerate(selected):
        accent = accents[index % len(accents)]
        cells.append(
            f"""
            <td width="25%" valign="top" style="padding:5px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                     style="background:{DASHBOARD_COLOURS['panel_alt']};
                            border:1px solid {accent}55;border-radius:7px;">
                <tr>
                  <td style="padding:11px 10px 4px 10px;
                             color:{DASHBOARD_COLOURS['text']};
                             font-size:12px;font-weight:700;">
                    <span style="color:{accent};font-size:18px;">
                      {_escape(icons.get(signal.signal_type, "◈"))}
                    </span>
                    {_escape(signal.signal_type)}
                  </td>
                </tr>
                <tr>
                  <td style="padding:0 10px 5px 10px;">
                    {_pill(signal.severity, _severity_colour(signal.severity))}
                    <span style="color:{DASHBOARD_COLOURS['muted']};
                                 font-size:10px;margin-left:4px;">
                      {_escape(signal.confidence)}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:3px 10px;color:{DASHBOARD_COLOURS['highlight']};
                             font-size:12px;font-weight:700;">
                    {_escape(truncate(signal.title, 70))}
                  </td>
                </tr>
                <tr>
                  <td style="padding:2px 10px 7px 10px;
                             color:{DASHBOARD_COLOURS['muted']};
                             font-size:11px;line-height:1.35;">
                    {_escape(truncate(signal.summary, 95))}
                  </td>
                </tr>
                <tr>
                  <td style="padding:6px 10px 11px 10px;font-size:11px;">
                    <span style="color:{accent};font-weight:700;">Action:</span>
                    <span style="color:{DASHBOARD_COLOURS['text']};">
                      {_escape(truncate(signal.action, 72))}
                    </span><br>
                    {_link("Open source ›", signal.link, source=signal.source, confidence=signal.confidence)}
                  </td>
                </tr>
              </table>
            </td>
            """
        )

    while len(cells) < 4:
        cells.append('<td width="25%" style="padding:5px;"></td>')

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        '<tr>' + "".join(cells) + "</tr></table>"
    )


def _vendor_key(item: Item) -> str:
    """Normalise report items into a small set of vendor dashboard groups."""

    value = f"{item.vendor} {item.section}".lower()
    if "microsoft" in value or "azure" in value:
        return "Microsoft"
    if "fortinet" in value:
        return "Fortinet"
    if "palo alto" in value:
        return "Palo Alto"
    if "cisco" in value:
        return "Cisco"
    if any(term in value for term in ("aws", "okta", "cloud", "google")):
        return "Cloud / Identity"
    if "hpe" in value or "aruba" in value:
        return "HPE / Aruba"
    return "Other Vendors"


def _vendor_information_url(vendor: str, items: list[Item]) -> str:
    """Return the vendor's general security-advisory or bulletin page."""

    direct = _VENDOR_INFORMATION_URLS.get(vendor)
    if direct:
        return direct

    vendor_text = " ".join(
        f"{item.vendor} {item.source}" for item in items
    ).lower()
    for name, url in _VENDOR_NAME_INFORMATION_URLS.items():
        if name in vendor_text:
            return url
    return ""


def _linked_vendor_bullet(item: Item, accent: str) -> str:
    """Render a vendor update with a direct link to the underlying advisory."""

    return (
        '<tr><td valign="top" style="padding:3px 8px 3px 0;'
        f'color:{accent};font-weight:700;">•</td>'
        '<td style="padding:3px 0;font-size:12px;line-height:1.35;">'
        f'{_link(truncate(item.title, 62), item.link, source=item.source, colour=DASHBOARD_COLOURS["highlight"])}'
        '</td></tr>'
    )


def _render_vendor_cards(items: list[Item], limit_per_vendor: int = 2) -> str:
    """Group vendor intelligence and link both advisories and vendor centres."""

    groups: dict[str, list[Item]] = {}
    for item in items:
        if item.section in {
            "Microsoft, Azure and Identity",
            "Fortinet",
            "HPE and Aruba",
            "Other Vendor Advisories",
            "Cloud and Identity",
            "Cloud and Supply-Chain Security",
            "Threat Intelligence",
        }:
            groups.setdefault(_vendor_key(item), []).append(item)

    preferred = [
        "Microsoft",
        "Fortinet",
        "Palo Alto",
        "Cisco",
        "Cloud / Identity",
        "HPE / Aruba",
        "Other Vendors",
    ]
    cells = []
    accents = {
        "Microsoft": "#6ea8fe",
        "Fortinet": "#ff5f57",
        "Palo Alto": "#ff8b45",
        "Cisco": "#53c7ea",
        "Cloud / Identity": "#7fb6ff",
        "HPE / Aruba": "#4dd4ac",
        "Other Vendors": "#b778ff",
    }
    icons = {
        "Microsoft": "▦",
        "Fortinet": "▦",
        "Palo Alto": "◆",
        "Cisco": "≋",
        "Cloud / Identity": "☁",
        "HPE / Aruba": "◫",
        "Other Vendors": "◇",
    }

    for vendor in preferred:
        vendor_items = groups.get(vendor, [])
        if not vendor_items:
            continue
        accent = accents[vendor]
        bullets = "".join(
            _linked_vendor_bullet(item, accent)
            for item in vendor_items[:limit_per_vendor]
        )
        vendor_page = _vendor_information_url(vendor, vendor_items)
        centre_link = (
            _link("Vendor advisory centre ›", vendor_page)
            if vendor_page
            else ""
        )
        cells.append(
            f"""
            <td width="20%" valign="top" style="padding:5px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                     style="background:{DASHBOARD_COLOURS['panel_alt']};
                            border:1px solid {DASHBOARD_COLOURS['border']};
                            border-radius:7px;">
                <tr>
                  <td style="padding:11px 10px 4px;color:{accent};
                             font-size:16px;font-weight:700;">
                    {_escape(icons[vendor])}
                    <span style="font-size:12px;color:{DASHBOARD_COLOURS['highlight']};">
                      {_escape(vendor)}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:0 10px 4px;">
                    {_pill(f"{len(vendor_items)} alerts", accent)}
                  </td>
                </tr>
                <tr>
                  <td style="padding:5px 10px 10px;">
                    <table role="presentation" cellspacing="0" cellpadding="0">
                      {bullets}
                    </table>
                    <div style="margin-top:7px;font-size:11px;">
                      {centre_link}
                    </div>
                  </td>
                </tr>
              </table>
            </td>
            """
        )
        if len(cells) >= 5:
            break

    if not cells:
        return (
            f'<p style="margin:0;color:{DASHBOARD_COLOURS["muted"]};">'
            "No qualifying vendor updates.</p>"
        )

    while len(cells) < 5:
        cells.append('<td width="20%" style="padding:5px;"></td>')

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        '<tr>' + "".join(cells) + "</tr></table>"
    )


def _render_governance_cards(
    items: list[Item],
    upcoming_events: list[dict[str, str]],
    limit: int = 5,
) -> str:
    """Render current changes plus a five-band governance forward look."""

    current_changes = [
        item for item in items if item.section in GOVERNANCE_SECTIONS
    ][:3]
    current_html = ""
    if current_changes:
        current_html = (
            '<div style="margin-bottom:8px;color:'
            f'{DASHBOARD_COLOURS["muted"]};font-size:11px;font-weight:700;">'
            'CURRENT CHANGES</div>'
            '<table role="presentation" cellspacing="0" cellpadding="0">'
            + "".join(
                _compact_bullet(
                    f"{item.title}: {_short_tldr(item, 110)}",
                    DASHBOARD_COLOURS["green"],
                )
                for item in current_changes
            )
            + '</table><div style="height:8px;"></div>'
        )

    grouped_events: dict[str, list[dict[str, str]]] = {
        label: [] for label, _, _ in GOVERNANCE_HORIZONS
    }
    for event in upcoming_events:
        horizon = event.get("horizon", "")
        if horizon in grouped_events:
            grouped_events[horizon].append(event)

    rows: list[str] = []
    accents = [
        DASHBOARD_COLOURS["critical"],
        DASHBOARD_COLOURS["high"],
        DASHBOARD_COLOURS["blue"],
        DASHBOARD_COLOURS["cyan"],
        DASHBOARD_COLOURS["green"],
    ]
    for index, (label, _, _) in enumerate(GOVERNANCE_HORIZONS[:limit]):
        events = grouped_events[label]
        accent = accents[index % len(accents)]
        if events:
            detail_parts: list[str] = []
            link_parts: list[str] = []
            for event in events[:2]:
                title = event.get("title") or "Governance milestone"
                date_text = event.get("date") or "Date not supplied"
                notes = event.get("notes") or "Confirmed future milestone."
                url = event.get("source_url") or ""
                detail_parts.append(
                    '<div style="margin-bottom:7px;">'
                    f'<strong style="color:{DASHBOARD_COLOURS["highlight"]};">'
                    f'{_escape(title)}</strong><br>'
                    f'<span style="color:{DASHBOARD_COLOURS["muted"]};">'
                    f'{_escape(date_text)} — {_escape(truncate(notes, 135))}'
                    '</span></div>'
                )
                if url:
                    link_parts.append(_link("Details ›", url))
            detail = "".join(detail_parts)
            link_html = "<br><br>".join(link_parts)
        else:
            detail = (
                f'<span style="color:{DASHBOARD_COLOURS["muted"]};">'
                'No confirmed milestone currently recorded.</span>'
            )
            link_html = ""

        rows.append(
            f"""
            <tr>
              <td width="150" valign="top" style="padding:9px 10px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  color:{accent};font-size:12px;font-weight:700;">
                {_escape(label)}
              </td>
              <td valign="top" style="padding:9px 10px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  font-size:12px;line-height:1.4;">
                {detail}
              </td>
              <td width="75" valign="middle" style="padding:9px 10px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  font-size:11px;text-align:right;">
                {link_html}
              </td>
            </tr>
            """
        )

    return (
        current_html
        + '<div style="margin-bottom:4px;color:'
        + DASHBOARD_COLOURS["muted"]
        + ';font-size:11px;font-weight:700;">FORWARD LOOK</div>'
        + '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
        + 'style="border-collapse:collapse;">'
        + "".join(rows)
        + '</table>'
    )


def _render_action_cards(actions: list[str], limit: int = 5) -> str:
    """Render recommended actions as full-width rows inside one panel."""

    if not actions:
        return (
            f'<p style="margin:0;color:{DASHBOARD_COLOURS["muted"]};">'
            'No immediate action identified.</p>'
        )

    accents = [
        DASHBOARD_COLOURS["critical"],
        DASHBOARD_COLOURS["high"],
        DASHBOARD_COLOURS["blue"],
        DASHBOARD_COLOURS["green"],
        DASHBOARD_COLOURS["purple"],
    ]
    rows: list[str] = []
    for index, action in enumerate(actions[:limit], start=1):
        accent = accents[(index - 1) % len(accents)]
        rows.append(
            f"""
            <tr>
              <td width="42" valign="top" style="padding:10px 8px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  color:{accent};font-size:15px;font-weight:700;text-align:center;">
                {index}
              </td>
              <td valign="top" style="padding:10px 12px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  color:{DASHBOARD_COLOURS['text']};font-size:12px;line-height:1.45;">
                {_bold_prefix_html(action)}
              </td>
            </tr>
            """
        )

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
        'style="border-collapse:collapse;background:'
        + DASHBOARD_COLOURS["panel_alt"]
        + ';border:1px solid '
        + DASHBOARD_COLOURS["border"]
        + ';border-radius:7px;">'
        + "".join(rows)
        + '</table>'
    )


def _render_news_digest(news: list[NewsLink], limit: int = 6) -> str:
    """Render secondary discovery headlines as compact TL;DR rows."""

    if not news:
        return (
            f'<p style="margin:0;color:{DASHBOARD_COLOURS["muted"]};">'
            "No additional relevant cyber-news links.</p>"
        )

    rows = []
    for item in news[:limit]:
        tag = item.tags[0] if item.tags else "News"
        rows.append(
            f"""
            <tr>
              <td width="90" valign="top" style="padding:6px 8px 6px 0;">
                {_pill(tag, DASHBOARD_COLOURS['blue'])}
              </td>
              <td valign="top" style="padding:6px 6px;
                   border-top:1px solid {DASHBOARD_COLOURS['border']};">
                <div style="font-size:12px;font-weight:700;">
                  {_link(
                      item.title,
                      item.link,
                      source=item.source,
                      tags=item.tags,
                      colour=DASHBOARD_COLOURS["highlight"],
                  )}
                </div>
                <div style="color:{DASHBOARD_COLOURS['muted']};
                            font-size:11px;margin-top:2px;">
                  {_escape(item.source)}
                </div>
              </td>
            </tr>
            """
        )

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0" '
        'style="border-collapse:collapse;">'
        + "".join(rows)
        + "</table>"
    )


def _render_compact_detail_sections(
    context: ReportContext,
    detection_opportunities: list[DetectionOpportunity],
    regional_links: list[NewsLink],
) -> str:
    """Keep full section coverage below the dashboard without long prose cards."""

    blocks: list[str] = []

    for section in context.primary_section_order:
        section_items = context.grouped.get(section, [])
        display_title = context.section_titles.get(section, section)

        if section == "SOC and Detection Engineering":
            if not section_items and not detection_opportunities:
                continue
            rows = []
            for opportunity in detection_opportunities[:4]:
                rows.append(
                    _compact_bullet(
                        (
                            f"{opportunity.title}: "
                            f"{truncate(opportunity.detection, 135)}"
                        ),
                        DASHBOARD_COLOURS["cyan"],
                    )
                )
            for item in section_items[:4]:
                rows.append(
                    _compact_bullet(
                        f"{item.title}: {_short_tldr(item, 120)}",
                        DASHBOARD_COLOURS["cyan"],
                    )
                )
            blocks.append(
                _panel(
                    display_title,
                    '<table role="presentation" cellspacing="0" cellpadding="0">'
                    + "".join(rows)
                    + "</table>",
                    DASHBOARD_COLOURS["cyan"],
                )
            )
            continue

        if section == "Scandinavia and Europe":
            if not section_items and not regional_links:
                continue
            rows = [
                _compact_bullet(
                    f"{link.title} — {link.source}",
                    DASHBOARD_COLOURS["blue"],
                )
                for link in regional_links[:4]
            ]
            rows.extend(
                _compact_bullet(
                    f"{item.title}: {_short_tldr(item, 120)}",
                    DASHBOARD_COLOURS["blue"],
                )
                for item in section_items[:4]
            )
            blocks.append(
                _panel(
                    display_title,
                    '<table role="presentation" cellspacing="0" cellpadding="0">'
                    + "".join(rows)
                    + "</table>",
                    DASHBOARD_COLOURS["blue"],
                )
            )
            continue

        if not section_items:
            continue

        # The main dashboard already gives prominent treatment to these sections.
        if section in {
            "Known Exploited Vulnerabilities",
            "Dark Web and Criminal Ecosystem",
            "Microsoft, Azure and Identity",
            "Fortinet",
            "HPE and Aruba",
            "Other Vendor Advisories",
            "Cloud and Identity",
            "Compliance",
            "Standards",
            "GRC",
        }:
            continue

        rows = "".join(
            _compact_bullet(
                f"{item.title}: {_short_tldr(item, 125)}",
                DASHBOARD_COLOURS["blue"],
            )
            for item in section_items[:5]
        )
        blocks.append(
            _panel(
                display_title,
                '<table role="presentation" cellspacing="0" cellpadding="0">'
                + rows
                + "</table>",
                DASHBOARD_COLOURS["blue"],
            )
        )

    return "".join(blocks)

def render_html_report(
    context: ReportContext,
    items: list[Item],
    warnings: list[str],
    lookback_hours: int,
    upcoming_events: list[dict[str, str]],
    upcoming_days: int,
    executive_news: list[NewsLink],
    sector_impacts: list[SectorImpact],
    detection_opportunities: list[DetectionOpportunity],
    regional_links: list[NewsLink],
    exposure_signals: list[ExposureSignal],
) -> str:
    """Render a compact, dark, dashboard-style HTML email.

    The layout uses nested presentation tables and inline CSS so it remains
    usable in Gmail, Outlook and other email clients that do not support modern
    browser layout primitives.
    """

    status = context.status
    enterprise_status = context.enterprise_status
    actions = context.actions

    active_exploitation_count = sum(
        1 for item in items if item.exploited or item.kev
    )
    zero_day_count = sum(1 for item in items if item.zero_day)
    vendor_alert_count = sum(
        1
        for item in items
        if item.section
        in {
            "Microsoft, Azure and Identity",
            "Fortinet",
            "HPE and Aruba",
            "Other Vendor Advisories",
            "Cloud and Identity",
        }
    )
    governance_count = sum(
        1 for item in items if item.section in GOVERNANCE_SECTIONS
    ) + len(upcoming_events)

    summary_lines: list[str] = []
    for item in context.top_advisories[:3]:
        summary_lines.append(
            f"{item.title} — {_short_tldr(item, 105)}"
        )
    if context.top_exposure:
        summary_lines.append(
            (
                f"{context.top_exposure[0].signal_type}: "
                f"{truncate(context.top_exposure[0].title, 95)}"
            )
        )
    if not summary_lines:
        summary_lines.append(
            "No immediate critical development identified in the reporting window."
        )

    summary_html = (
        '<table role="presentation" cellspacing="0" cellpadding="0">'
        + "".join(
            _compact_bullet(line, DASHBOARD_COLOURS["blue"])
            for line in summary_lines[:4]
        )
        + "</table>"
    )

    metrics_html = f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="table-layout:fixed;margin:0 0 10px 0;">
      <tr>
        {_metric_card(
            "Overall Threat",
            status["display"].upper(),
            "!",
            status["colour"],
            f"Enterprise: {enterprise_status['display']}",
            "executive-summary",
        )}
        {_metric_card(
            "Active Exploitation",
            str(active_exploitation_count),
            "◉",
            DASHBOARD_COLOURS["high"],
            "KEV or exploitation evidence",
            "active-exploitation",
        )}
        {_metric_card(
            "Zero-Days",
            str(zero_day_count),
            "▲",
            DASHBOARD_COLOURS["medium"],
            "Explicit zero-day references",
            "critical-vulnerabilities",
        )}
        {_metric_card(
            "Dark Web / Exposure",
            str(len(exposure_signals)),
            "◉",
            DASHBOARD_COLOURS["blue"],
            "Exposure signals collected",
            "dark-web-exposure",
        )}
        {_metric_card(
            "Vendor Alerts",
            str(vendor_alert_count),
            "◆",
            DASHBOARD_COLOURS["purple"],
            "Priority vendor developments",
            "vendor-updates",
        )}
        {_metric_card(
            "Governance",
            str(governance_count),
            "✓",
            DASHBOARD_COLOURS["green"],
            "14d / 1m / 3m / 6m / 1y",
            "governance",
        )}
      </tr>
    </table>
    """

    executive_panel = _panel(
        "Executive Summary (TL;DR)",
        summary_html,
        DASHBOARD_COLOURS["blue"],
        anchor_id="executive-summary",
    )

    defcon_panel = _panel(
        "Enterprise DEFCON Scale",
        _render_defcon_triangle(int(enterprise_status["level"])),
        DASHBOARD_COLOURS["purple"],
    )

    vulnerability_panel = _panel(
        "1. Critical Vulnerabilities / Zero-Days",
        _render_vulnerability_table(items),
        DASHBOARD_COLOURS["critical"],
        anchor_id="critical-vulnerabilities",
    )
    
    threat_panel = _panel(
        "2. Active Exploitation / Threat Actor Activity",
        _render_threat_rows(items),
        DASHBOARD_COLOURS["blue"],
        anchor_id="active-exploitation",
    )
    
    exposure_panel = _panel(
        "3. Dark Web / Exposure Watch",
        _render_exposure_cards(exposure_signals),
        DASHBOARD_COLOURS["blue"],
        anchor_id="dark-web-exposure",
    )
    
    vendor_panel = _panel(
        "4. Vendor Updates",
        _render_vendor_cards(items),
        DASHBOARD_COLOURS["blue"],
        anchor_id="vendor-updates",
    )
    
    governance_panel = _panel(
        "5. Standards / Compliance / Governance",
        _render_governance_cards(
            items,
            upcoming_events,
        ),
        DASHBOARD_COLOURS["green"],
        anchor_id="governance",
    )
    action_panel = _panel(
        "6. Recommended Actions Today",
        _render_action_cards(actions),
        DASHBOARD_COLOURS["critical"],
    )
    news_panel = _panel(
        "Relevant Cyber News",
        _render_news_digest(executive_news),
        DASHBOARD_COLOURS["purple"],
    )

    sector_panel = ""
    if sector_impacts:
        sector_rows = "".join(
            _compact_bullet(
                f"{impact.sector}: {truncate(impact.implication, 145)}",
                DASHBOARD_COLOURS["green"],
            )
            for impact in sector_impacts[:5]
        )
        sector_panel = _panel(
            "Customer and Sector Impact",
            '<table role="presentation" cellspacing="0" cellpadding="0">'
            + sector_rows
            + "</table>",
            DASHBOARD_COLOURS["green"],
        )

    detail_sections = _render_compact_detail_sections(
        context,
        detection_opportunities,
        regional_links,
    )

    health_rows = []
    for health in context.active_sources[:12]:
        health_rows.append(
            _compact_bullet(
                f"{_source_health_label(health['source'])}: {health['items']} qualifying item(s)",
                DASHBOARD_COLOURS["green"],
            )
        )
    if context.quiet_source_count:
        health_rows.append(
            _compact_bullet(
                (
                    f"{context.quiet_source_count} additional source(s) "
                    "checked without qualifying updates"
                ),
                DASHBOARD_COLOURS["blue"],
            )
        )
    for health in context.failed_sources:
        health_rows.append(
            _compact_bullet(
                f"{_source_health_label(health['source'])}: temporarily unavailable",
                DASHBOARD_COLOURS["critical"],
            )
        )
    source_panel = _panel(
        "Source Coverage",
        '<table role="presentation" cellspacing="0" cellpadding="0">'
        + "".join(health_rows)
        + "</table>",
        DASHBOARD_COLOURS["muted"],
    )

    watch_items = (
        "Credential or stealer-log exposure affecting monitored domains.",
        "Ransomware claims involving customers, suppliers or key sectors.",
        "Initial-access activity targeting remote access or cloud identity.",
        "New CISA KEV additions and confirmed active exploitation.",
        "Microsoft, Fortinet, HPE, Aruba, cloud and identity advisories.",
        "OT, energy and critical-infrastructure targeting.",
        "Material EU AI Act, NIS2, Sikkerhetsloven, DORA and standards deadlines.",
    )
    watch_panel = _panel(
        "Security Advisory and CISO Watch List",
        '<table role="presentation" cellspacing="0" cellpadding="0">'
        + "".join(
            _compact_bullet(item, DASHBOARD_COLOURS["purple"])
            for item in watch_items
        )
        + "</table>",
        DASHBOARD_COLOURS["purple"],
    )

    monitored_text = ""
    if context.monitored_references:
        monitored_text = (
            '<div style="margin-top:5px;color:'
            f'{DASHBOARD_COLOURS["muted"]};font-size:10px;">'
            "<strong>Monitored:</strong> "
            + _escape(", ".join(context.monitored_references))
            + "</div>"
        )

    # Nested tables and inline CSS provide the strongest cross-client support.
    return f"""
    <!doctype html>
    <html lang="en">
      <body style="margin:0;padding:0;background:{DASHBOARD_COLOURS['background']};
                   font-family:Arial,Helvetica,sans-serif;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
               style="background:{DASHBOARD_COLOURS['background']};">
          <tr>
            <td align="center" style="padding:16px 10px;">
              <table role="presentation" width="1000" cellspacing="0" cellpadding="0"
                     style="width:100%;max-width:1000px;">
                <tr>
                  <td style="padding:4px 2px 16px 2px;">
                    <table role="presentation" width="100%" cellspacing="0"
                           cellpadding="0">
                      <tr>
                        <td valign="middle">
                          <div style="color:{DASHBOARD_COLOURS['text']};
                                      font-size:28px;font-weight:700;">
                            <span style="color:{DASHBOARD_COLOURS['purple']};">◈</span>
                            {_escape(context.report_title)}
                          </div>
                          <div style="color:{DASHBOARD_COLOURS['muted']};
                                      font-size:14px;margin-top:2px;">
                            Security Advisory + Threat Intelligence
                          </div>
                        </td>
                        <td align="right" valign="middle"
                            style="color:{DASHBOARD_COLOURS['muted']};font-size:11px;">
                          Reporting window: previous {lookback_hours} hours<br>
                          Primary sources: {len(context.active_sources) +
                              context.quiet_source_count +
                              len(context.failed_sources)}<br>
                          Version {BRIEF_VERSION}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <tr><td>{metrics_html}</td></tr>

                <tr>
                  <td>
                    <table role="presentation" width="100%" cellspacing="0"
                           cellpadding="0">
                      <tr>
                        <td width="66%" valign="top" style="padding-right:6px;">
                          {vulnerability_panel}
                        </td>
                        <td width="34%" valign="top" style="padding-left:6px;">
                          {defcon_panel}
                          {executive_panel}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <tr><td>{threat_panel}</td></tr>
                <tr><td>{news_panel}</td></tr>
                <tr><td>{exposure_panel}</td></tr>
                <tr><td>{vendor_panel}</td></tr>

                <tr>
                  <td>
                    <table role="presentation" width="100%" cellspacing="0"
                           cellpadding="0">
                      <tr>
                        <td width="50%" valign="top" style="padding-right:6px;">
                          {governance_panel}
                        </td>
                        <td width="50%" valign="top" style="padding-left:6px;">
                          {action_panel}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <tr><td>{sector_panel}</td></tr>
                <tr><td>{detail_sections}</td></tr>
                <tr><td>{watch_panel}</td></tr>
                <tr><td>{source_panel}</td></tr>

                <tr>
                  <td style="padding:10px 4px 20px 4px;
                             color:{DASHBOARD_COLOURS['muted']};font-size:10px;
                             border-top:1px solid {DASHBOARD_COLOURS['border']};">
                    Sources include CISA KEV, NVD, official vendor advisories,
                    threat research, governance publications and authorised
                    exposure metadata.
                    {monitored_text}
                    <div style="margin-top:5px;">
                      Dark-web claims remain reported intelligence until
                      independently corroborated. The pipeline does not connect
                      to onion services, criminal forums, leak sites or
                      stolen-data repositories.
                    </div>
                    <div style="margin-top:8px;">
                      Daily Security Brief © 2026 John-Helge Gantz.
                      Report format and software implementation are proprietary.
                      Third-party source content remains the property of its
                      respective publishers.
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
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
    """Render semantically equivalent plain-text and HTML briefings."""

    context = build_report_context(
        items,
        exposure_signals,
        source_health,
        monitored_brands,
        monitored_domains,
    )
    text_body = render_text_report(
        context,
        items,
        warnings,
        lookback_hours,
        upcoming_events,
        upcoming_days,
        executive_news,
        sector_impacts,
        detection_opportunities,
        regional_links,
        exposure_signals,
    )
    html_body = render_html_report(
        context,
        items,
        warnings,
        lookback_hours,
        upcoming_events,
        upcoming_days,
        executive_news,
        sector_impacts,
        detection_opportunities,
        regional_links,
        exposure_signals,
    )
    return text_body, html_body
