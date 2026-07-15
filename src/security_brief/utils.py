# Copyright © 2026 John-Helge Gantz. All rights reserved.
#
# Proprietary and confidential.
# Unauthorised use, copying, modification or distribution is prohibited.
# See the LICENSE file at the repository root for complete terms.

"""Small deterministic helpers used across the pipeline."""

from __future__ import annotations

import calendar
import math
import os
import re
from datetime import date, datetime, timezone
from functools import lru_cache
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from .config import EFFECTIVE_DATE_TERMS, OSLO_TIMEZONE
from .rules import DATE_PATTERNS, NORWEGIAN_MONTHS

def required(name: str) -> str:
    """Return a mandatory environment variable or fail fast.

    Whitespace-only values are treated as missing so secrets and addresses cannot
    silently propagate as invalid runtime configuration.
    """

    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value.strip()

@lru_cache(maxsize=None)
def integer_setting(
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    """Read, validate and bound an integer environment setting.

    The helper centralises defensive parsing for item limits, lookback windows and
    other numeric controls. A descriptive error is raised when the supplied value
    falls outside the permitted range.
    """

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
    """Resolve the news lookback window for the current run.

    ``NEWS_LOOKBACK_HOURS=auto`` uses 72 hours on Mondays and 36 hours on all other
    days in Europe/Oslo. Explicit numeric values are accepted for testing and
    manual investigations.
    """

    raw = os.getenv("NEWS_LOOKBACK_HOURS", "auto").strip().lower()

    # Automatic mode follows the Europe/Oslo working week rather than UTC.
    # Monday therefore includes the weekend by using a 72-hour window.
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
    """Resolve the CISA KEV lookback in calendar days.

    Automatic mode converts the hour-based reporting window into enough calendar
    days to avoid losing KEV entries around day boundaries.
    """

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
    """Normalise arbitrary input into compact single-line text.

    HTML entities are decoded and repeated whitespace is collapsed. This function
    is used at source boundaries before data enters scoring or rendering logic.
    """

    if value is None:
        return ""

    soup = BeautifulSoup(str(value), "html.parser")
    return re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()

def absolute_url(base: str, href: str) -> str:
    """Resolve a possibly relative link against its source page URL."""

    return urljoin(base, href.strip())

def extract_cves(text: str) -> list[str]:
    """Extract, normalise and deduplicate CVE identifiers from text."""

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
    """Parse one date from free-form English or Norwegian text.

    The parser handles ISO-like values, common month-name formats and Norwegian
    month names. Returned datetimes are normalised to UTC where possible.
    """

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
    """Return every distinct date recognised in a block of text.

    This is primarily used for governance milestones, where an article may mention
    publication, transition and enforcement dates in the same paragraph.
    """

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
    """Check whether a date appears near enforcement or deadline language."""

    lowered = clean_text(text).lower()
    return any(term in lowered for term in EFFECTIVE_DATE_TERMS)

def feed_entry_time(entry: Any) -> datetime | None:
    """Extract the most reliable publication timestamp from an RSS entry."""

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

@lru_cache(maxsize=None)
def csv_setting(name: str) -> tuple[str, ...]:
    """Parse a comma-separated environment variable into unique ordered values."""

    raw = os.getenv(name, "")
    values: list[str] = []
    seen: set[str] = set()

    for part in raw.split(","):
        value = clean_text(part)

        if not value:
            continue

        lowered = value.lower()

        if lowered in seen:
            continue

        values.append(value)
        seen.add(lowered)

    return tuple(values)

def ensure_utc(value: datetime) -> datetime:
    """Return a timezone-aware datetime normalised to UTC."""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)

def truncate(value: str, limit: int) -> str:
    """Shorten text to a safe display length without splitting the output unnecessarily."""

    value = clean_text(value)
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"

