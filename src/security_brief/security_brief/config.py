"""Application identity, endpoints and global runtime constants."""

from __future__ import annotations

import os
from pathlib import Path
from zoneinfo import ZoneInfo

BRIEF_NAME = "Daily Security Brief"

BRIEF_VERSION = "4.2"

USER_AGENT = (
    f"daily-security-brief/{BRIEF_VERSION} "
    "(GitHub Actions; security news aggregation)"
)

CISA_KEV_FEED = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CISA_KEV_CATALOGUE = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HIBP_BREACHES_API = "https://haveibeenpwned.com/api/v3/breaches"

HIBP_BREACHED_DOMAIN_API = (
    "https://haveibeenpwned.com/api/v3/breachedDomain"
)

HIBP_PWNED_WEBSITES = "https://haveibeenpwned.com/PwnedWebsites"

HIBP_DASHBOARD = "https://haveibeenpwned.com/Dashboard"

OSLO_TIMEZONE = ZoneInfo("Europe/Oslo")

UPCOMING_GOVERNANCE_FILE = Path(
    os.getenv(
        "UPCOMING_GOVERNANCE_FILE",
        "config/upcoming_governance.json",
    )
)

MONITORED_GOVERNANCE_TOPICS = (
    "NSM updates",
    "Sikkerhetsloven",
    "NIS2",
    "ISO/IEC 27001",
    "ISO 50001",
    "ISO 9001",
    "ISO 14001",
    "ISO/IEC 33000 series",
)

DEFCON_LEVELS = {
    1: {
        "label": "Critical",
        "colour": "#B71C1C",
        "text_colour": "#FFFFFF",
    },
    2: {
        "label": "High",
        "colour": "#E65100",
        "text_colour": "#FFFFFF",
    },
    3: {
        "label": "Elevated",
        "colour": "#F9A825",
        "text_colour": "#111111",
    },
    4: {
        "label": "Guarded",
        "colour": "#1565C0",
        "text_colour": "#FFFFFF",
    },
    5: {
        "label": "Low",
        "colour": "#2E7D32",
        "text_colour": "#FFFFFF",
    },
}

ZERO_DAY_TERMS = (
    "zero-day",
    "zero day",
    "0-day",
    "0day",
    "nulldag",
)

EFFECTIVE_DATE_TERMS = (
    "effective",
    "takes effect",
    "enters into force",
    "entry into force",
    "applies from",
    "applicable from",
    "enforcement begins",
    "enforced from",
    "deadline",
    "go live",
    "goes live",
    "transition period",
    "compliance date",
    "implementation date",
    "trer i kraft",
    "ikrafttredelse",
    "gjelder fra",
    "håndheves fra",
    "frist",
    "overgangsperiode",
)

GOVERNANCE_SECTIONS = {
    "Norwegian Security Governance",
    "Compliance",
    "Standards",
    "GRC",
    "Scandinavia and Europe",
}
