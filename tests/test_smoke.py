# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Offline regression tests for the optimised briefing pipeline."""

from __future__ import annotations

import unittest
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch

from security_brief.analysis import (
    build_detection_opportunities,
    build_open_source_exposure_signals,
    build_regional_links,
    build_sector_impacts,
    deduplicate_exposure_signals,
)
from security_brief.app import (
    FetchTask,
    PipelineState,
    collect_tasks,
)
from security_brief import BRIEF_VERSION, collectors
from security_brief.models import Item, NewsLink
from security_brief.rendering import render_report


class MockResponse:
    """Minimal requests-compatible response used by collector tests."""

    def __init__(self, payload: object, status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self) -> object:
        return self._payload


class PipelineTests(unittest.TestCase):
    """Validate failure isolation, exposure mapping and report rendering."""

    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.item = Item(
            title="Actively exploited Fortinet authentication bypass",
            summary=(
                "Attackers exploit an internet-facing Fortinet flaw against "
                "European energy and managed-service organisations."
            ),
            link="https://example.invalid/fortinet",
            published=self.now,
            source="Sample Vendor",
            vendor="Fortinet",
            section="Fortinet",
            category="Active exploitation",
            score=105,
            cves=["CVE-2026-12345"],
            exploited=True,
            kev=True,
            affected="Internet-facing Fortinet systems.",
            action="Patch and investigate exposed appliances.",
            why="The flaw can provide initial access.",
        )
        self.news = NewsLink(
            title="Ransomware group claims Nordic retail supplier",
            link="https://example.invalid/ransomware",
            source="Sample News",
            published=self.now,
            score=78,
            tags=[
                "Dark Web/Exposure",
                "Nordics",
                "Retail/Hospitality/Property",
            ],
            summary=(
                "A ransomware claim alleges stolen customer data from a "
                "Nordic retail supplier."
            ),
        )

    def test_parallel_collection_preserves_health_order(self) -> None:
        state = PipelineState()
        target: list[int] = []

        def fail() -> list[int]:
            raise RuntimeError("source unavailable")

        tasks = [
            FetchTask(name="First", fetch=lambda: [1]),
            FetchTask(name="Second", fetch=fail),
            FetchTask(name="Third", fetch=lambda: [3]),
        ]

        collect_tasks(tasks, target, state, workers=3)

        self.assertEqual(target, [1, 3])
        self.assertEqual(
            [record["source"] for record in state.source_health],
            ["First", "Second", "Third"],
        )
        self.assertEqual(
            [record["status"] for record in state.source_health],
            ["OK", "FAILED", "OK"],
        )
        self.assertEqual(len(state.warnings), 1)

    def test_hibp_public_breach_mapping(self) -> None:
        payload = [
            {
                "Name": "ExampleBreach",
                "Title": "Example Breach",
                "Domain": "example.com",
                "BreachDate": "2026-07-13",
                "AddedDate": self.now.isoformat(),
                "PwnCount": 250000,
                "Description": (
                    "<p>Email addresses and passwords were exposed.</p>"
                ),
                "DataClasses": ["Email addresses", "Passwords"],
                "IsVerified": True,
                "IsSpamList": False,
                "IsRetired": False,
                "IsStealerLog": False,
                "IsMalware": False,
            }
        ]

        with patch.object(
            collectors,
            "http_get",
            return_value=MockResponse(payload),
        ):
            signals = collectors.fetch_hibp_breaches(
                self.now.replace(
                    hour=0,
                    minute=0,
                    second=0,
                    microsecond=0,
                )
            )

        self.assertEqual(len(signals), 1)
        self.assertEqual(
            signals[0].signal_type,
            "Credential Exposure and Stealer Logs",
        )
        self.assertEqual(signals[0].confidence, "Verified")
        self.assertNotIn("@", signals[0].affected)

    def test_version_matches_repository_file(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        expected = (
            project_root / "VERSION"
        ).read_text(encoding="utf-8").strip()

        self.assertEqual(BRIEF_VERSION, expected)

    def test_report_retains_advisory_and_ciso_views(self) -> None:
        exposure = deduplicate_exposure_signals(
            build_open_source_exposure_signals(
                [self.item],
                [self.news],
                ("NetNordic",),
                ("example.com",),
                max_items=20,
            ),
            20,
        )
        sector_impacts = build_sector_impacts(
            [self.item],
            [self.news],
        )
        detections = build_detection_opportunities([self.item])
        regional = build_regional_links(
            [self.item],
            [self.news],
        )

        text_body, html_body = render_report(
            items=[self.item],
            warnings=[],
            lookback_hours=36,
            upcoming_events=[],
            upcoming_days=14,
            source_health=[
                {
                    "source": "Sample",
                    "status": "OK",
                    "items": 1,
                    "detail": "",
                }
            ],
            executive_news=[self.news],
            sector_impacts=sector_impacts,
            detection_opportunities=detections,
            regional_links=regional,
            exposure_signals=exposure,
            monitored_brands=("NetNordic",),
            monitored_domains=("example.com",),
        )

        for expected in (
            "Daily Security Brief",
            "Security advisory level",
            "Enterprise cyber threat level",
            "Dark Web and Exposure Highlights",
            "Relevant Cyber News",
            "Zero-Day and CVSS 10.0",
            "Fortinet",
            "SOC and Detection Engineering",
            "Security Advisory and CISO Watch List",
            "Executive Summary (TL;DR)",
            "Critical Vulnerabilities / Zero-Days",
            "Active Exploitation / Threat Actor Activity",
            "Dark Web / Exposure Watch",
            "Vendor Updates",
            "Recommended Actions Today",
            "Daily Security Brief © 2026 John-Helge Gantz",
        ):
            self.assertIn(expected, text_body + html_body)


if __name__ == "__main__":
    unittest.main()
