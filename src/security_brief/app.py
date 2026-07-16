# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Application orchestration for the Daily Security Brief.

This module owns side effects and workflow sequencing. Collection functions are
pure source adapters; analysis and rendering remain deterministic and testable.
Independent public sources are fetched concurrently with a bounded worker pool,
which substantially reduces total runtime without increasing per-source load.
"""

from __future__ import annotations

import os
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Generic, TypeVar

from .analysis import (
    advisory_status,
    build_detection_opportunities,
    build_open_source_exposure_signals,
    build_regional_links,
    build_sector_impacts,
    deduplicate,
    deduplicate_exposure_signals,
    select_executive_news,
    select_final_items,
)
from .collectors import (
    enrich_nvd,
    fetch_executive_news_html,
    fetch_executive_news_rss,
    fetch_hibp_breaches,
    fetch_hibp_domain_exposure,
    fetch_html,
    fetch_kev,
    fetch_recent_nvd_coverage,
    fetch_rss,
)
from .config import EMAIL_SUBJECT, OSLO_TIMEZONE
from .sources import (
    EXECUTIVE_NEWS_HTML,
    EXECUTIVE_NEWS_RSS,
    HTML_SOURCES,
    RSS_SOURCES,
)
from .delivery import send_email
from .governance import (
    deduplicate_governance_events,
    detect_governance_go_live_events,
    load_configured_governance_events,
)
from .models import ExposureSignal, Item, NewsLink
from .rendering import render_report
from .utils import (
    csv_setting,
    integer_setting,
    kev_lookback_days,
    reporting_window_hours,
    required,
)


T = TypeVar("T")


@dataclass(frozen=True)
class RuntimeSettings:
    """Environment-derived settings resolved once per pipeline execution."""

    username: str
    password: str
    recipient: str
    lookback_hours: int
    max_items: int
    kev_days: int
    upcoming_days: int
    exposure_max: int
    executive_news_max: int
    source_workers: int
    monitored_brands: tuple[str, ...]
    monitored_domains: tuple[str, ...]
    hibp_api_key: str

    @classmethod
    def from_environment(cls) -> "RuntimeSettings":
        """Validate required secrets and load bounded optional settings."""

        lookback_hours = reporting_window_hours()
        return cls(
            username=required("GMAIL_USERNAME"),
            password=required("GMAIL_APP_PASSWORD"),
            recipient=required("EMAIL_TO"),
            lookback_hours=lookback_hours,
            max_items=integer_setting(
                "NEWS_MAX_ITEMS",
                default=40,
                minimum=5,
                maximum=80,
            ),
            kev_days=kev_lookback_days(lookback_hours),
            upcoming_days=integer_setting(
                "UPCOMING_GOVERNANCE_DAYS",
                default=14,
                minimum=1,
                maximum=90,
            ),
            exposure_max=integer_setting(
                "EXPOSURE_MAX_ITEMS",
                default=20,
                minimum=5,
                maximum=60,
            ),
            executive_news_max=integer_setting(
                "EXEC_NEWS_MAX_ITEMS",
                default=10,
                minimum=1,
                maximum=20,
            ),
            source_workers=integer_setting(
                "SOURCE_WORKERS",
                default=8,
                minimum=1,
                maximum=16,
            ),
            monitored_brands=csv_setting("MONITORED_BRANDS"),
            monitored_domains=csv_setting("MONITORED_DOMAINS"),
            hibp_api_key=os.getenv("HIBP_API_KEY", "").strip(),
        )


@dataclass
class PipelineState:
    """Mutable pipeline collections kept together to simplify orchestration."""

    primary_items: list[Item] = field(default_factory=list)
    exposure_candidates: list[ExposureSignal] = field(default_factory=list)
    news_candidates: list[NewsLink] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_health: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class FetchTask(Generic[T]):
    """A named source operation with reporting metadata."""

    name: str
    fetch: Callable[[], list[T]]
    detail: str = ""
    unit: str = "item(s)"


@dataclass(frozen=True)
class FetchOutcome(Generic[T]):
    """Normalised success or failure result from one source operation."""

    task: FetchTask[T]
    values: list[T]
    error: Exception | None = None


def _execute_task(task: FetchTask[T]) -> FetchOutcome[T]:
    """Execute one source adapter without allowing its error to escape."""

    try:
        return FetchOutcome(task=task, values=task.fetch())
    except Exception as error:  # Source isolation is intentional.
        return FetchOutcome(task=task, values=[], error=error)


def collect_tasks(
    tasks: list[FetchTask[T]],
    target: list[T],
    state: PipelineState,
    *,
    workers: int,
) -> None:
    """Fetch independent sources concurrently and record ordered health data.

    ``executor.map`` preserves task order, so Source Coverage remains stable
    even though network requests run concurrently.
    """

    if not tasks:
        return

    worker_count = min(workers, len(tasks))

    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="brief-source",
    ) as executor:
        outcomes = executor.map(_execute_task, tasks)

        for outcome in outcomes:
            task = outcome.task

            if outcome.error is None:
                target.extend(outcome.values)
                state.source_health.append(
                    {
                        "source": task.name,
                        "status": "OK",
                        "items": len(outcome.values),
                        "detail": task.detail,
                    }
                )
                print(
                    f"{task.name}: {len(outcome.values)} {task.unit}"
                )
                continue

            error = outcome.error
            detail = f"{type(error).__name__}: {error}"
            warning = f"{task.name}: {detail}"
            state.warnings.append(warning)
            state.source_health.append(
                {
                    "source": task.name,
                    "status": "FAILED",
                    "items": 0,
                    "detail": detail,
                }
            )
            print(f"WARNING: {warning}", file=sys.stderr)


def primary_tasks(
    cutoff: datetime,
    kev_days: int,
) -> list[FetchTask[Item]]:
    """Build all independent primary-intelligence source operations."""

    tasks: list[FetchTask[Item]] = [
        FetchTask(
            name="CISA KEV",
            fetch=lambda: fetch_kev(kev_days),
        ),
        FetchTask(
            name="NVD recent priority-vendor CVEs",
            fetch=lambda: fetch_recent_nvd_coverage(cutoff),
        ),
    ]
    tasks.extend(
        FetchTask(
            name=source.name,
            fetch=lambda source=source: fetch_rss(source, cutoff),
        )
        for source in RSS_SOURCES
    )
    tasks.extend(
        FetchTask(
            name=source.name,
            fetch=lambda source=source: fetch_html(source, cutoff),
        )
        for source in HTML_SOURCES
    )
    return tasks


def exposure_tasks(
    settings: RuntimeSettings,
    cutoff: datetime,
) -> list[FetchTask[ExposureSignal]]:
    """Build public and optional authorised exposure-source operations."""

    tasks = [
        FetchTask(
            name="Have I Been Pwned breach catalogue",
            fetch=lambda: fetch_hibp_breaches(cutoff),
            detail="Public breach metadata",
            unit="new exposure signal(s)",
        )
    ]

    if settings.monitored_domains and settings.hibp_api_key:
        tasks.append(
            FetchTask(
                name="Have I Been Pwned domain search",
                fetch=lambda: fetch_hibp_domain_exposure(
                    settings.monitored_domains,
                    settings.hibp_api_key,
                ),
                detail=(
                    f"{len(settings.monitored_domains)} verified domain(s) "
                    "configured"
                ),
                unit="domain exposure signal(s)",
            )
        )

    return tasks


def discovery_tasks(
    cutoff: datetime,
) -> list[FetchTask[NewsLink]]:
    """Build secondary discovery-source operations."""

    tasks = [
        FetchTask(
            name=source["name"],
            fetch=lambda source=source: fetch_executive_news_rss(
                source,
                cutoff,
            ),
            detail="Executive news discovery",
            unit="relevant news link(s)",
        )
        for source in EXECUTIVE_NEWS_RSS
    ]
    tasks.extend(
        FetchTask(
            name=source["name"],
            fetch=lambda source=source: fetch_executive_news_html(
                source,
                cutoff,
            ),
            detail="Executive news discovery",
            unit="relevant news link(s)",
        )
        for source in EXECUTIVE_NEWS_HTML
    )
    return tasks


def run_pipeline(settings: RuntimeSettings) -> None:
    """Collect, analyse, render and deliver one briefing."""

    local_now = datetime.now(OSLO_TIMEZONE)
    utc_now = datetime.now(timezone.utc)
    cutoff = utc_now - timedelta(hours=settings.lookback_hours)
    state = PipelineState()

    print(
        f"Reporting window: {settings.lookback_hours} hours "
        f"(Europe/Oslo weekday={local_now.strftime('%A')})"
    )
    print(
        f"Parallel source workers: {settings.source_workers}"
    )

    collect_tasks(
        primary_tasks(cutoff, settings.kev_days),
        state.primary_items,
        state,
        workers=settings.source_workers,
    )
    collect_tasks(
        exposure_tasks(settings, cutoff),
        state.exposure_candidates,
        state,
        workers=min(settings.source_workers, 2),
    )
    collect_tasks(
        discovery_tasks(cutoff),
        state.news_candidates,
        state,
        workers=settings.source_workers,
    )

    # Deduplicate before NVD enrichment so duplicate CVEs do not consume API
    # capacity. CVSS enrichment then participates in final prioritisation.
    all_items = deduplicate(state.primary_items)
    enrich_nvd(all_items, state.warnings)
    all_items.sort(
        key=lambda item: (item.score, item.published),
        reverse=True,
    )
    items = select_final_items(all_items, settings.max_items)

    executive_news = select_executive_news(
        state.news_candidates,
        items,
        settings.executive_news_max,
    )

    # Exposure intelligence remains separate from primary advisories, retaining
    # visible confidence labels and avoiding risk-score contamination.
    state.exposure_candidates.extend(
        build_open_source_exposure_signals(
            items,
            executive_news,
            settings.monitored_brands,
            settings.monitored_domains,
            max_items=settings.exposure_max,
        )
    )
    exposure_signals = deduplicate_exposure_signals(
        state.exposure_candidates,
        settings.exposure_max,
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
    upcoming_events = deduplicate_governance_events(
        load_configured_governance_events(
            today,
            settings.upcoming_days,
            state.warnings,
        )
        + detect_governance_go_live_events(
            all_items,
            today,
            settings.upcoming_days,
        )
    )

    text_body, html_body = render_report(
        items,
        state.warnings,
        settings.lookback_hours,
        upcoming_events,
        settings.upcoming_days,
        state.source_health,
        executive_news,
        sector_impacts,
        detection_opportunities,
        regional_links,
        exposure_signals,
        settings.monitored_brands,
        settings.monitored_domains,
    )

    advisory = advisory_status(items, exposure_signals)
    subject = EMAIL_SUBJECT

    send_email(
        settings.username,
        settings.password,
        settings.recipient,
        subject,
        text_body,
        html_body,
    )

    print(
        f"Briefing sent: {advisory['display']}, "
        f"{len(items)} item(s), "
        f"{len(upcoming_events)} upcoming event(s), "
        f"{len(executive_news)} relevant news link(s), "
        f"{len(exposure_signals)} exposure signal(s), "
        f"{len(sector_impacts)} sector impact(s), "
        f"{len(detection_opportunities)} detection opportunity(s), "
        f"{len(regional_links)} regional link(s), "
        f"{len(state.warnings)} warning(s)."
    )


def main() -> int:
    """CLI entry point with one top-level failure boundary."""

    try:
        run_pipeline(RuntimeSettings.from_environment())
        return 0
    except Exception as error:
        print(
            f"Pipeline failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1
