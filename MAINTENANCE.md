# Maintenance priorities

V5.1
Aims to fix
- 1
- 2
  

## Priority 1 — Restore and protect core functionality

1. Fix erroneous or obsolete URLs and parsers for:
   - Reuters Cybersecurity
   - BankInfoSecurity

2. Configure and validate `NVD_API_KEY` support for reliable NVD enrichment.

3. Add live parser-health and source-freshness monitoring.
   - Detect failed requests.
   - Detect successful responses with no usable records.
   - Detect stale feeds.
   - Detect broken HTML selectors.
   - Report source-health changes.

## Priority 2 — Improve security and report reliability

4. Pin Python dependencies with hashes.

5. Generate a machine-readable CycloneDX or SPDX SBOM.

6. Add persistent state and cross-run deduplication.
   - Prevent repeated advisories across overlapping reporting windows.
   - Retain meaningful updates to previously reported stories.
   - Track first-seen and last-seen timestamps.

## Priority 3 — Improve report usability

7. Add internal cross-reference links to the HTML email.
   - Link summary metrics to their detailed sections.
   - Add “Back to summary” links.
   - Link vendor cards to vendor sections.
   - Link action items to supporting advisories.

## Priority 4 — Improve maintainability

8. Externalise frequently changed source definitions and relevance rules.
   - Source URLs
   - Selectors
   - Keywords
   - Vendor priorities
   - Sector mappings
   - Source limits

## Priority 5 — Add historical capability

9. Add private report archiving and historical comparison.
   - Store generated HTML or structured JSON.
   - Compare daily, weekly and monthly trends.
   - Avoid introducing paid infrastructure.
