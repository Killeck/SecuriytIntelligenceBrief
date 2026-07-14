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
    """Render the complete HTML briefing."""

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

    # Inline CSS is used because many email clients remove external stylesheets
    # and reject advanced layout features.
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

    return html_report


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
