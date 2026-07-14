"""Forward-looking governance, compliance and standards milestones."""

from __future__ import annotations

import json
from datetime import date, timedelta
from .config import GOVERNANCE_SECTIONS, UPCOMING_GOVERNANCE_FILE
from .models import Item
from .utils import (
    clean_text,
    date_has_effective_context,
    parse_all_dates,
    truncate,
)

def load_configured_governance_events(
    today: date,
    days_ahead: int,
    warnings: list[str],
) -> list[dict[str, str]]:
    """Load enabled future milestones from the local governance JSON file."""

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
    """Infer near-term effective dates and deadlines from collected governance items."""

    end_date = today + timedelta(days=days_ahead)
    events: list[dict[str, str]] = []

    # Only governance-oriented sections are scanned for future dates. This
    # prevents ordinary vulnerability dates being misread as deadlines.
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
    """Merge duplicate governance milestones and return them in date order."""

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
