# Copyright © 2026 John-Helge Gantz. All rights reserved.
#
# Proprietary and confidential.
# Unauthorised use, copying, modification or distribution is prohibited.
# See the LICENSE file at the repository root for complete terms.

"""Data models shared by collectors, analysis, rendering and orchestration.

The models intentionally contain no network or rendering behaviour. Keeping the
records small and mutable preserves compatibility with the original pipeline
while allowing each layer to depend on a stable data contract.
"""

from __future__ import annotations
from .config import BRIEF_VERSION
from dataclasses import dataclass, field
from datetime import datetime

@dataclass(frozen=True)
class Source:
    """Describe one configured intelligence source and its parser rules.

    A source can be an RSS feed or an HTML index. Optional selectors and URL
    patterns are used only by HTML collectors, while ``topic_keywords`` can narrow
    a broad source to security-relevant entries.
    """

    name: str
    vendor: str
    url: str
    source_type: str
    base_score: int
    section: str
    selectors: tuple[str, ...] = ()
    include_patterns: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    max_candidates: int = 25
    locale: str = "en"
    topic_keywords: tuple[str, ...] = ()

@dataclass
class Item:
    """Represent a normalised primary security development.

    Instances combine source metadata, deterministic classification, CVE and
    exploitation attributes, and advisory text used by both report renderers.
    """

    title: str
    summary: str
    link: str
    published: datetime
    source: str
    vendor: str
    section: str
    category: str
    score: int
    cves: list[str] = field(default_factory=list)
    exploited: bool = False
    kev: bool = False
    ransomware: bool = False
    zero_day: bool = False
    cvss_score: float | None = None
    cvss_severity: str = "Not available"
    cvss_vector: str = ""
    affected: str = ""
    action: str = ""
    why: str = ""

@dataclass
class NewsLink:
    """Represent a concise secondary-news discovery link.

    News links are intentionally lighter than primary items: they support executive
    awareness and navigation but do not independently determine remediation or
    compliance conclusions.
    """

    title: str
    link: str
    source: str
    published: datetime
    score: int
    tags: list[str] = field(default_factory=list)
    summary: str = ""

@dataclass
class ExposureSignal:
    """Represent a dark-web, breach or external-exposure intelligence signal.

    The confidence and severity fields are kept separate because an alarming claim
    may still be unverified. The report uses this distinction to avoid presenting
    secondary reporting as a confirmed customer incident.
    """

    title: str
    signal_type: str
    source: str
    link: str
    observed: datetime
    confidence: str
    severity: str
    score: int
    summary: str
    affected: str
    action: str
    organisation: str = ""
    tags: list[str] = field(default_factory=list)

@dataclass
class SectorImpact:
    """Represent the most relevant implication for one customer sector."""

    sector: str
    headline: str
    implication: str
    source: str
    link: str
    score: int

@dataclass
class DetectionOpportunity:
    """Represent a suggested SOC detection or hunting opportunity.

    These records are deterministic starting points containing a detection focus,
    recommended telemetry and a MITRE ATT&CK reference. They require analyst
    validation before operational use.
    """

    title: str
    detection: str
    data_sources: str
    mitre: str
    source: str
    link: str
    score: int
