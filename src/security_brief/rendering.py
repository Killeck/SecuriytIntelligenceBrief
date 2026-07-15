# Copyright © 2026 John-Helge Gantz. All rights reserved.
#
# Proprietary and confidential.
# Unauthorised use, copying, modification or distribution is prohibited.
# See the LICENSE file at the repository root for complete terms.

"""Plain-text and HTML report rendering.

Rendering is deliberately side-effect free. It receives already selected and
classified records, which makes it testable without network or SMTP access.
"""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Any

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
    GOVERNANCE_SECTIONS,
    MONITORED_GOVERNANCE_TOPICS,
)
from .rules import EXPOSURE_SECTION_ORDER
from .models import (
    DetectionOpportunity,
    ExposureSignal,
    Item,
    NewsLink,
    SectorImpact,
)
from .utils import truncate

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
    """Render one exposure signal as a distinct HTML exposure card."""

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
            if item.zero_day or item.cvss_score == 10.0
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
                f"{signal.title} — {signal.source}: {signal.link}"
            )

    if ransomware_watch:
        text.extend(["", "Ransomware and Extortion Watch"])
        for signal in ransomware_watch:
            text.append(
                f"- [{signal.confidence}] {signal.title} "
                f"— {signal.source}: {signal.link}"
            )

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


def _link(label: str, url: str) -> str:
    """Render a restrained purple report link."""

    return (
        f'<a href="{html.escape(url, quote=True)}" '
        f'style="color:{DASHBOARD_COLOURS["link"]};'
        'text-decoration:underline;">'
        f'{_escape(label)}</a>'
    )


def _panel(title: str, body: str, accent: str = "#6ea8fe") -> str:
    """Wrap content in a reusable dark email panel."""

    return f"""
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
           style="border-collapse:separate;border-spacing:0;
                  background:{DASHBOARD_COLOURS['panel']};
                  border:1px solid {DASHBOARD_COLOURS['border']};
                  border-radius:8px;margin:0 0 12px 0;">
      <tr>
        <td style="padding:14px 16px 8px 16px;
                   color:{accent};font-size:16px;font-weight:700;">
          {_escape(title)}
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
) -> str:
    """Render one top-level metric card as a table cell."""

    return f"""
    <td width="16.66%" valign="top" style="padding:4px;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
             style="background:{DASHBOARD_COLOURS['panel']};
                    border:1px solid {DASHBOARD_COLOURS['border']};
                    border-radius:7px;">
        <tr>
          <td style="padding:11px 10px 5px 10px;color:{accent};
                     font-size:11px;font-weight:700;">
            {_escape(title)}
          </td>
        </tr>
        <tr>
          <td style="padding:0 10px;color:{DASHBOARD_COLOURS['text']};
                     font-size:20px;font-weight:700;white-space:nowrap;">
            <span style="color:{accent};font-size:20px;">{_escape(icon)}</span>
            {_escape(value)}
          </td>
        </tr>
        <tr>
          <td style="padding:5px 10px 11px 10px;
                     color:{DASHBOARD_COLOURS['muted']};font-size:10px;">
            {_escape(detail)}
          </td>
        </tr>
      </table>
    </td>
    """


def _compact_bullet(text: str, accent: str = "#6ea8fe") -> str:
    """Render one short TL;DR line."""

    return (
        '<tr><td valign="top" style="padding:3px 8px 3px 0;'
        f'color:{accent};font-weight:700;">•</td>'
        f'<td style="padding:3px 0;color:{DASHBOARD_COLOURS["text"]};'
        f'font-size:13px;line-height:1.35;">{_escape(text)}</td></tr>'
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
        if (
            item.zero_day
            or item.kev
            or item.exploited
            or (item.cvss_score is not None and item.cvss_score >= 8.0)
        )
    ][:limit]

    if not selected:
        return (
            f'<p style="margin:0;color:{DASHBOARD_COLOURS["muted"]};">'
            "No critical or high-priority vulnerabilities identified.</p>"
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
        rows.append(
            f"""
            <tr>
              <td width="36" valign="top" style="padding:9px 6px;
                  color:{colour};font-size:20px;text-align:center;">
                {icons[index % len(icons)]}
              </td>
              <td valign="top" style="padding:9px 8px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};">
                <div style="color:{DASHBOARD_COLOURS['text']};
                            font-size:13px;font-weight:700;">
                  {_escape(item.title)} &nbsp; {_pill(severity, colour)}
                </div>
                <div style="color:{DASHBOARD_COLOURS['muted']};
                            font-size:12px;line-height:1.35;margin-top:3px;">
                  {_escape(_short_tldr(item, 145))}
                </div>
              </td>
              <td width="125" valign="middle" style="padding:9px 8px;
                  border-top:1px solid {DASHBOARD_COLOURS['border']};
                  color:{DASHBOARD_COLOURS['muted']};font-size:11px;">
                Impact<br>
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
                  <td style="padding:3px 10px;color:{DASHBOARD_COLOURS['text']};
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
                    {_link("Open source ›", signal.link)}
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


def _render_vendor_cards(items: list[Item], limit_per_vendor: int = 2) -> str:
    """Group vendor intelligence into concise mini-cards."""

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
            _compact_bullet(
                truncate(item.title, 58),
                accent,
            )
            for item in vendor_items[:limit_per_vendor]
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
                    <span style="font-size:12px;color:{DASHBOARD_COLOURS['text']};">
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
                    <div style="margin-top:5px;font-size:11px;">
                      {_link("Open latest ›", vendor_items[0].link)}
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
    """Render compliance, standards and governance changes as mini-cards."""

    records: list[tuple[str, str, str, str]] = []
    for item in items:
        if item.section in GOVERNANCE_SECTIONS:
            records.append(
                (
                    item.section,
                    item.title,
                    _short_tldr(item, 95),
                    item.link,
                )
            )
    for event in upcoming_events:
        records.append(
            (
                event.get("topic") or "Deadline",
                event.get("title") or "Governance milestone",
                (
                    f"{event.get('date', '')} — "
                    f"{event.get('notes') or 'Upcoming implementation milestone.'}"
                ),
                event.get("source_url") or "",
            )
        )

    records = records[:limit]
    if not records:
        return (
            f'<p style="margin:0;color:{DASHBOARD_COLOURS["muted"]};">'
            "No material governance or compliance change identified.</p>"
        )

    accents = [
        DASHBOARD_COLOURS["green"],
        DASHBOARD_COLOURS["blue"],
        DASHBOARD_COLOURS["cyan"],
        DASHBOARD_COLOURS["high"],
        DASHBOARD_COLOURS["purple"],
    ]
    cells = []
    for index, (topic, title, summary, url) in enumerate(records):
        accent = accents[index % len(accents)]
        link_html = _link("Details ›", url) if url else ""
        cells.append(
            f"""
            <td width="20%" valign="top" style="padding:5px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                     style="background:{DASHBOARD_COLOURS['panel_alt']};
                            border:1px solid {DASHBOARD_COLOURS['border']};
                            border-radius:7px;">
                <tr>
                  <td style="padding:10px 9px 4px;color:{accent};
                             font-size:11px;font-weight:700;">
                    ◉ {_escape(topic)}
                  </td>
                </tr>
                <tr>
                  <td style="padding:2px 9px;color:{DASHBOARD_COLOURS['text']};
                             font-size:12px;font-weight:700;">
                    {_escape(truncate(title, 58))}
                  </td>
                </tr>
                <tr>
                  <td style="padding:4px 9px;color:{DASHBOARD_COLOURS['muted']};
                             font-size:11px;line-height:1.35;">
                    {_escape(truncate(summary, 90))}
                  </td>
                </tr>
                <tr>
                  <td style="padding:5px 9px 10px;font-size:11px;">
                    {link_html}
                  </td>
                </tr>
              </table>
            </td>
            """
        )

    while len(cells) < 5:
        cells.append('<td width="20%" style="padding:5px;"></td>')

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        '<tr>' + "".join(cells) + "</tr></table>"
    )


def _render_action_cards(actions: list[str], limit: int = 5) -> str:
    """Render the day's recommended actions as a compact checklist row."""

    accents = [
        DASHBOARD_COLOURS["critical"],
        DASHBOARD_COLOURS["high"],
        DASHBOARD_COLOURS["blue"],
        DASHBOARD_COLOURS["green"],
        DASHBOARD_COLOURS["purple"],
    ]
    icons = ["◈", "◎", "●", "▣", "□"]
    cells = []

    for index, action in enumerate(actions[:limit], start=1):
        accent = accents[(index - 1) % len(accents)]
        cells.append(
            f"""
            <td width="20%" valign="top" style="padding:5px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0"
                     style="background:{DASHBOARD_COLOURS['panel_alt']};
                            border:1px solid {accent}99;border-radius:7px;">
                <tr>
                  <td style="padding:10px 9px 4px;color:{accent};
                             font-size:11px;font-weight:700;">
                    {_escape(icons[index - 1])} {index} Action
                  </td>
                </tr>
                <tr>
                  <td style="padding:3px 9px 11px;color:{DASHBOARD_COLOURS['text']};
                             font-size:11px;line-height:1.4;">
                    {_escape(truncate(action, 125))}
                  </td>
                </tr>
              </table>
            </td>
            """
        )

    while len(cells) < 5:
        cells.append('<td width="20%" style="padding:5px;"></td>')

    return (
        '<table role="presentation" width="100%" cellspacing="0" cellpadding="0">'
        '<tr>' + "".join(cells) + "</tr></table>"
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
                  {_link(item.title, item.link)}
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
        )}
        {_metric_card(
            "Active Exploitation",
            str(active_exploitation_count),
            "◉",
            DASHBOARD_COLOURS["high"],
            "KEV or exploitation evidence",
        )}
        {_metric_card(
            "Zero-Days",
            str(zero_day_count),
            "▲",
            DASHBOARD_COLOURS["medium"],
            "Explicit zero-day references",
        )}
        {_metric_card(
            "Dark Web / Exposure",
            str(len(exposure_signals)),
            "◉",
            DASHBOARD_COLOURS["blue"],
            "Exposure signals collected",
        )}
        {_metric_card(
            "Vendor Alerts",
            str(vendor_alert_count),
            "◆",
            DASHBOARD_COLOURS["purple"],
            "Priority vendor developments",
        )}
        {_metric_card(
            "Governance",
            str(governance_count),
            "✓",
            DASHBOARD_COLOURS["green"],
            f"{upcoming_days}-day horizon",
        )}
      </tr>
    </table>
    """

    executive_panel = _panel(
        "Executive Summary (TL;DR)",
        summary_html,
        DASHBOARD_COLOURS["blue"],
    )

    vulnerability_panel = _panel(
        "1. Critical Vulnerabilities / Zero-Days",
        _render_vulnerability_table(items),
        DASHBOARD_COLOURS["critical"],
    )
    threat_panel = _panel(
        "2. Active Exploitation / Threat Actor Activity",
        _render_threat_rows(items),
        DASHBOARD_COLOURS["blue"],
    )
    exposure_panel = _panel(
        "3. Dark Web / Exposure Watch",
        _render_exposure_cards(exposure_signals),
        DASHBOARD_COLOURS["blue"],
    )
    vendor_panel = _panel(
        "4. Vendor Updates",
        _render_vendor_cards(items),
        DASHBOARD_COLOURS["blue"],
    )
    governance_panel = _panel(
        "5. Standards / Compliance / Governance",
        _render_governance_cards(items, upcoming_events),
        DASHBOARD_COLOURS["green"],
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
                f"{health['source']}: {health['items']} qualifying item(s)",
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
                f"{health['source']}: FAILED — {health.get('detail', '')}",
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
        "Material NIS2, Sikkerhetsloven, DORA and standards deadlines.",
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

    warnings_panel = ""
    if warnings:
        warning_rows = "".join(
            _compact_bullet(warning, DASHBOARD_COLOURS["critical"])
            for warning in warnings[:10]
        )
        warnings_panel = _panel(
            "Source Warnings",
            '<table role="presentation" cellspacing="0" cellpadding="0">'
            + warning_rows
            + "</table>",
            DASHBOARD_COLOURS["critical"],
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
                          {executive_panel}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <tr>
                  <td>
                    <table role="presentation" width="100%" cellspacing="0"
                           cellpadding="0">
                      <tr>
                        <td width="50%" valign="top" style="padding-right:6px;">
                          {threat_panel}
                        </td>
                        <td width="50%" valign="top" style="padding-left:6px;">
                          {news_panel}
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

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
                <tr><td>{warnings_panel}</td></tr>

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
                        Dailiy Security Brief © 2026 John-Helge Gantz.
                        Report format and software implementation are proprietary.
                        Third-party source content remains the property of its
                        respective publisher.
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
