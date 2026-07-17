# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Offline regression tests for the optimised briefing pipeline."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from security_brief import BRIEF_VERSION, collectors
from security_brief.analysis import (
    advisory_status,
    build_item,
    build_detection_opportunities,
    build_open_source_exposure_signals,
    build_regional_links,
    build_sector_impacts,
    deduplicate_exposure_signals,
    defcon_status,
)
from security_brief.app import FetchTask, PipelineState, collect_tasks
from security_brief.collectors import (
    canonicalise_article_url,
    executive_article_url_allowed,
)
from security_brief.models import ExposureSignal, Item, NewsLink
from security_brief.rendering import render_report
from security_brief.delivery import build_message
from security_brief.governance import governance_horizon
from security_brief.config import EMAIL_SUBJECT
from security_brief.sources import (
    EXECUTIVE_NEWS_RSS,
    HTML_SOURCES,
    RSS_SOURCES,
)


class MockResponse:
    """Minimal requests-compatible response used by collector tests."""

    def __init__(
        self,
        payload: object,
        status_code: int = 200,
        content: bytes = b"",
    ) -> None:
        self._payload = payload
        self.status_code = status_code
        self.content = content

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

    def test_reuters_article_url_validation(self) -> None:
        source = {
            "allowed_hosts": ("www.reuters.com", "reuters.com"),
            "article_path_regex": (
                r"^/(technology|world|legal|business|sustainability)/"
                r".+-\d{4}-\d{2}-\d{2}/?$"
            ),
            "exclude": (
                "/video/",
                "/pictures/",
                "/graphics/",
                "/commentary/",
            ),
        }

        valid_urls = (
            "https://www.reuters.com/technology/example-cyber-story-2026-07-14",
            "https://www.reuters.com/world/example-ransomware-story-2026-07-14",
            (
                "https://www.reuters.com/legal/government/"
                "example-cyber-law-story-2026-07-14"
            ),
        )
        for url in valid_urls:
            with self.subTest(url=url):
                self.assertTrue(executive_article_url_allowed(source, url))

        invalid_urls = (
            "https://www.reuters.com/technology/cybersecurity/",
            "https://www.reuters.com/video/example/",
            "https://www.reuters.com/world/",
            "https://example.com/technology/fake-2026-07-14/",
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                self.assertFalse(executive_article_url_allowed(source, url))

    def test_bankinfosecurity_article_url_validation(self) -> None:
        source = {
            "allowed_hosts": (
                "www.bankinfosecurity.com",
                "bankinfosecurity.com",
            ),
            "article_path_regex": r"^/[a-z0-9][a-z0-9-]*-a-\d+/?$",
            "exclude": (
                "/webinars/",
                "/events/",
                "/training/",
                "/latest-news",
            ),
        }

        self.assertTrue(
            executive_article_url_allowed(
                source,
                (
                    "https://www.bankinfosecurity.com/"
                    "microsoft-signed-legacy-shims-"
                    "undermine-secure-boot-a-32224"
                ),
            )
        )

        for url in (
            "https://www.bankinfosecurity.com/latest-news",
            "https://www.bankinfosecurity.com/topics/ransomware",
            "https://www.bankinfosecurity.com/webinars/example",
            "https://www.bankinfosecurity.com/",
        ):
            with self.subTest(url=url):
                self.assertFalse(executive_article_url_allowed(source, url))

    def test_article_url_canonicalisation(self) -> None:
        url = (
            "http://www.bankinfosecurity.com/"
            "example-security-story-a-12345/"
            "?utm_source=newsletter#article"
        )
        self.assertEqual(
            canonicalise_article_url(url),
            "https://www.bankinfosecurity.com/example-security-story-a-12345",
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
                "Description": "<p>Email addresses and passwords were exposed.</p>",
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
                self.now.replace(hour=0, minute=0, second=0, microsecond=0)
            )

        self.assertEqual(len(signals), 1)
        self.assertEqual(
            signals[0].signal_type,
            "Credential Exposure and Stealer Logs",
        )
        self.assertEqual(signals[0].confidence, "Verified")
        self.assertNotIn("@", signals[0].affected)

    def test_priority_source_additions_are_configured(self) -> None:
        primary_names = {source.name for source in RSS_SOURCES + HTML_SOURCES}
        discovery_names = {source["name"] for source in EXECUTIVE_NEWS_RSS}

        for expected in (
            "Microsoft Security Response Center",
            "CERT-EU Security Advisories",
            "Google Threat Intelligence",
            "Rapid7 Vulnerability Research",
            "Shadowserver Foundation",
        ):
            self.assertIn(expected, primary_names)
        self.assertIn("Ransomware.live", discovery_names)

    def test_epss_enrichment_adjusts_priority_without_claiming_exploitation(self) -> None:
        self.item.exploited = False
        self.item.kev = False
        original_score = self.item.score
        payload = {
            "data": [
                {
                    "cve": "CVE-2026-12345",
                    "epss": "0.650000",
                    "percentile": "0.990000",
                }
            ]
        }

        with patch.object(
            collectors,
            "http_get",
            return_value=MockResponse(payload),
        ):
            warnings: list[str] = []
            collectors.enrich_epss([self.item], warnings)

        self.assertEqual(warnings, [])
        self.assertEqual(self.item.score, original_score + 25)
        self.assertIn("EPSS: 65.0%", self.item.why)
        self.assertFalse(self.item.exploited)
        self.assertFalse(self.item.kev)

    def test_ransomware_live_is_discovery_only_and_unverified(self) -> None:
        source = next(
            record
            for record in EXECUTIVE_NEWS_RSS
            if record["name"] == "Ransomware.live"
        )
        payload = [
            {
                "victim": "Example Organisation",
                "group": "Example Group",
                "discovered": self.now.isoformat(),
                "country": "NO",
                "activity": "Information technology",
                "post_url": "https://www.ransomware.live/claim/example",
            }
        ]

        with patch.object(
            collectors,
            "http_get",
            return_value=MockResponse(payload),
        ):
            links = collectors.fetch_executive_news_rss(
                source,
                self.now - timedelta(hours=1),
            )

        self.assertEqual(len(links), 1)
        self.assertIn("Unverified ransomware claim", links[0].title)
        self.assertIn("Unverified claim", links[0].tags)
        self.assertIn("independently corroborated", links[0].summary)

    def test_msrc_api_expands_release_into_cve_items(self) -> None:
        source = next(
            record
            for record in RSS_SOURCES
            if record.name == "Microsoft Security Response Center"
        )
        update_payload = {
            "value": [
                {
                    "ID": "2026-Jul",
                    "DocumentTitle": "July 2026 Security Updates",
                    "InitialReleaseDate": self.now.isoformat(),
                    "CurrentReleaseDate": self.now.isoformat(),
                    "Severity": "Critical",
                }
            ]
        }
        detail_payload = {
            "Vulnerability": [
                {
                    "CVE": "CVE-2026-11111",
                    "Title": {"Value": "Microsoft test remote code execution"},
                    "Notes": [
                        {
                            "Type": "Description",
                            "Value": "A remote code execution vulnerability.",
                        }
                    ],
                    "CVSSScoreSets": [
                        {
                            "BaseScore": "9.8",
                            "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "Threats": [
                        {"Description": {"Value": "Exploitation Detected"}}
                    ],
                }
            ]
        }

        with patch.object(
            collectors,
            "http_get",
            side_effect=[
                MockResponse(update_payload),
                MockResponse(detail_payload),
            ],
        ):
            items = collectors.fetch_rss(
                source,
                self.now - timedelta(hours=1),
            )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].cves, ["CVE-2026-11111"])
        self.assertTrue(items[0].exploited)
        self.assertEqual(items[0].source, "Microsoft Security Response Center")
        self.assertEqual(items[0].section, "Microsoft, Azure and Identity")


    def test_msrc_revision_does_not_replay_historical_cves(self) -> None:
        source = next(
            record
            for record in RSS_SOURCES
            if record.name == "Microsoft Security Response Center"
        )
        update_payload = {
            "value": [
                {
                    "ID": "2025-Jan",
                    "DocumentTitle": "January 2025 Security Updates",
                    "InitialReleaseDate": (
                        self.now - timedelta(days=500)
                    ).isoformat(),
                    "CurrentReleaseDate": self.now.isoformat(),
                    "Severity": "Critical",
                }
            ]
        }
        with patch.object(
            collectors,
            "http_get",
            return_value=MockResponse(update_payload),
        ) as mocked_get:
            items = collectors.fetch_rss(
                source,
                self.now - timedelta(hours=1),
            )

        self.assertEqual(len(items), 1)
        self.assertTrue(items[0].title.startswith("MSRC revised:"))
        self.assertEqual(items[0].cves, [])
        self.assertFalse(items[0].exploited)
        self.assertEqual(mocked_get.call_count, 1)


    def test_zero_day_reference_does_not_imply_exploitation(self) -> None:
        source = next(source for source in RSS_SOURCES if source.name == "Google Project Zero")
        result = build_item(
            source=source,
            title="Retrospective analysis of last year's zero-day",
            summary="Historical research describing a previously disclosed flaw.",
            link="https://example.invalid/history",
            published=self.now,
            cutoff=self.now - timedelta(hours=1),
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertFalse(result.zero_day)
        self.assertFalse(result.exploited)

    def test_cvss_ten_without_exploitation_is_guarded(self) -> None:
        item = Item(
            title="Critical product vulnerability",
            summary="A remote code execution flaw has been fixed; no exploitation is reported.",
            link="https://example.invalid/cve",
            published=self.now,
            source="NVD Recent CVEs",
            vendor="Example",
            section="Other Vendor Advisories",
            category="Critical vulnerability",
            score=90,
            cves=["CVE-2026-99999"],
            cvss_score=10.0,
        )
        status = defcon_status([item])
        self.assertEqual(status["level"], 4)

    def test_unverified_ransomware_claim_cannot_raise_advisory_above_guarded(self) -> None:
        signal = ExposureSignal(
            title="Unverified ransomware claim: Example",
            signal_type="Ransomware and Extortion",
            source="Ransomware.live",
            link="https://www.ransomware.live/claim/example",
            observed=self.now,
            confidence="Unverified claim",
            severity="High",
            score=90,
            summary="Unverified claim.",
            affected="Example organisation.",
            action="Validate independently.",
        )
        status = advisory_status([], [signal])
        self.assertGreaterEqual(status["level"], 4)

    def test_verified_domain_credential_exposure_can_be_critical(self) -> None:
        signal = ExposureSignal(
            title="Verified-domain breach exposure: example.com",
            signal_type="Credential Exposure and Stealer Logs",
            source="Have I Been Pwned Domain Search",
            link="https://haveibeenpwned.com/Dashboard",
            observed=self.now,
            confidence="Domain ownership verified",
            severity="High",
            score=95,
            summary="Verified monitored-domain exposure.",
            affected="example.com",
            action="Review affected identities.",
        )
        status = advisory_status([], [signal])
        self.assertEqual(status["level"], 1)

    def test_email_subject_and_envelope_match_delivered_v5_structure(self) -> None:
        message = build_message(
            "sender@example.com",
            "recipient@example.org",
            EMAIL_SUBJECT,
            "Plain body",
            "<p>HTML body</p>",
        )
        self.assertEqual(message["Subject"], "Security Intelligence Brief")
        self.assertNotIn("DEFCON", message["Subject"])
        self.assertNotIn("Critical", message["Subject"])
        self.assertEqual(message["From"], "sender@example.com")
        self.assertIsNone(message["Auto-Submitted"])
        self.assertIsNone(message["X-Auto-Response-Suppress"])

    def test_unverified_ransomware_url_is_not_hyperlinked(self) -> None:
        signal = ExposureSignal(
            title="Unverified ransomware claim: Example",
            signal_type="Ransomware and Extortion",
            source="Ransomware.live",
            link="https://www.ransomware.live/claim/example",
            observed=self.now,
            confidence="Unverified claim",
            severity="High",
            score=30,
            summary="Unverified claim.",
            affected="Example.",
            action="Validate independently.",
        )
        from security_brief.rendering import render_exposure_html, render_exposure_text
        rendered_html = render_exposure_html(signal)
        rendered_text = "\n".join(render_exposure_text(signal, 1))
        self.assertNotIn('href="https://www.ransomware.live', rendered_html)
        self.assertIn("link withheld", rendered_html.lower())
        self.assertIn("Link withheld from email", rendered_text)

    def test_research_article_does_not_become_exploited_or_exposure(self) -> None:
        source = next(
            source
            for source in RSS_SOURCES
            if source.name == "Google Threat Intelligence"
        )
        item = build_item(
            source=source,
            title="Demystifying AI Exploits: A Blueprint for Vulnerability Management",
            summary=(
                "Research discusses mean time-to-exploit and exploit development "
                "without reporting a concrete active campaign or victim incident."
            ),
            link="https://example.invalid/research",
            published=self.now,
            cutoff=self.now - timedelta(hours=1),
        )
        self.assertIsNotNone(item)
        assert item is not None
        self.assertFalse(item.exploited)
        self.assertNotEqual(item.category, "Active exploitation")
        signals = build_open_source_exposure_signals(
            [item],
            [],
            (),
            (),
            max_items=10,
        )
        self.assertEqual(signals, [])

    def test_kev_without_widespread_exposure_is_elevated_not_high(self) -> None:
        item = Item(
            title="CVE-2026-12345 — Microsoft remote code execution",
            summary=(
                "CISA added the vulnerability to KEV. No widespread campaign "
                "or confirmed organisational exposure is reported."
            ),
            link="https://example.invalid/kev",
            published=self.now,
            source="CISA KEV",
            vendor="Microsoft",
            section="Known Exploited Vulnerabilities",
            category="Active exploitation",
            score=115,
            cves=["CVE-2026-12345"],
            exploited=True,
            kev=True,
            cvss_score=9.8,
            why="CISA confirms exploitation.",
        )
        status = defcon_status([item])
        self.assertEqual(status["level"], 3)

    def test_widespread_exploited_zero_day_can_be_high_not_critical(self) -> None:
        item = Item(
            title="Widespread exploitation of Microsoft zero-day",
            summary=(
                "A global exploitation campaign is targeting an internet-facing "
                "authentication bypass before patches are broadly deployed."
            ),
            link="https://example.invalid/zero-day",
            published=self.now,
            source="CISA KEV",
            vendor="Microsoft",
            section="Known Exploited Vulnerabilities",
            category="Active exploitation",
            score=130,
            cves=["CVE-2026-54321"],
            exploited=True,
            kev=True,
            zero_day=True,
            cvss_score=10.0,
            why="Widespread exploitation is confirmed.",
        )
        status = defcon_status([item])
        self.assertEqual(status["level"], 2)
        self.assertNotEqual(status["level"], 1)

    def test_source_warnings_and_unverified_domain_are_not_in_email(self) -> None:
        signal = ExposureSignal(
            title="Unverified ransomware claim: Example",
            signal_type="Ransomware and Extortion",
            source="Ransomware.live",
            link="https://www.ransomware.live/claim/example",
            observed=self.now,
            confidence="Unverified claim",
            severity="Guarded",
            score=20,
            summary="Unverified claim.",
            affected="Example.",
            action="Validate independently.",
        )
        text_body, html_body = render_report(
            items=[self.item],
            warnings=[
                "Reuters: HTTPError 401 for https://example.invalid/failure"
            ],
            lookback_hours=36,
            upcoming_events=[],
            upcoming_days=14,
            source_health=[
                {
                    "source": "Ransomware.live",
                    "status": "OK",
                    "items": 1,
                    "detail": "",
                },
                {
                    "source": "Reuters Cybersecurity",
                    "status": "FAILED",
                    "items": 0,
                    "detail": "HTTPError 401 for https://example.invalid/failure",
                },
            ],
            executive_news=[],
            sector_impacts=[],
            detection_opportunities=[],
            regional_links=[],
            exposure_signals=[signal],
            monitored_brands=(),
            monitored_domains=(),
        )
        combined = text_body + html_body
        self.assertNotIn("ransomware.live", combined.lower())
        self.assertNotIn("HTTPError", combined)
        self.assertNotIn("https://example.invalid/failure", combined)
        self.assertIn("temporarily unavailable", combined)

    def test_governance_horizon_bands(self) -> None:
        today = self.now.date()
        self.assertEqual(governance_horizon(today + timedelta(days=14), today), "Next 14 days")
        self.assertEqual(governance_horizon(today + timedelta(days=31), today), "15 days to 1 month")
        self.assertEqual(governance_horizon(today + timedelta(days=90), today), "1 to 3 months")
        self.assertEqual(governance_horizon(today + timedelta(days=180), today), "3 to 6 months")
        self.assertEqual(governance_horizon(today + timedelta(days=365), today), "6 to 12 months")

    def test_dashboard_uses_action_rows_vendor_centre_and_bold_prefixes(self) -> None:
        sector_impacts = build_sector_impacts([self.item], [self.news])
        text_body, html_body = render_report(
            items=[self.item],
            warnings=[],
            lookback_hours=36,
            upcoming_events=[
                {
                    "date": (self.now.date() + timedelta(days=20)).isoformat(),
                    "title": "Example regulatory milestone",
                    "topic": "Compliance",
                    "source": "Authority",
                    "source_url": "https://example.invalid/governance",
                    "notes": "Prepare evidence and ownership.",
                    "horizon": "15 days to 1 month",
                }
            ],
            upcoming_days=365,
            source_health=[],
            executive_news=[self.news],
            sector_impacts=sector_impacts,
            detection_opportunities=build_detection_opportunities([self.item]),
            regional_links=[],
            exposure_signals=[],
            monitored_brands=(),
            monitored_domains=(),
        )
        self.assertIn("Vendor advisory centre", html_body)
        self.assertIn("15 days to 1 month", html_body)
        self.assertIn("No confirmed milestone currently recorded", html_body)
        self.assertIn("<strong", html_body)
        self.assertNotIn("1 Action", html_body)
        self.assertIn("Recommended Actions Today", html_body)
        self.assertIn("Governance Forward Look", text_body)

    def test_version_matches_repository_file(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        expected = (project_root / "VERSION").read_text(encoding="utf-8").strip()
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
        sector_impacts = build_sector_impacts([self.item], [self.news])
        detections = build_detection_opportunities([self.item])
        regional = build_regional_links([self.item], [self.news])

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
