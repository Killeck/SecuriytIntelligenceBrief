# Step 3 — Non-CVE security news collector

This step adds a separate test briefing for non-KEV security news.

## Files to copy into the repository

- `src/send_news_brief.py`
- `.github/workflows/test-news-brief.yml`
- Add the content of `requirements.txt` to the repository's existing
  `requirements.txt`. Create the file if it does not exist.

## Existing GitHub secrets reused

- `GMAIL_USERNAME`
- `GMAIL_APP_PASSWORD`
- `EMAIL_TO`

No new secret is required.

## Test

1. Commit the files to the default branch.
2. Open GitHub **Actions**.
3. Select **Test security news briefing**.
4. Run it with:
   - `lookback_hours`: `72`
   - `max_items`: `15`
5. Review both the workflow log and the resulting email.

## Expected log

Each source reports the number of accepted items:

```text
Microsoft Security Blog: 3 item(s)
AWS Security Blog: 1 item(s)
...
Brief sent with 8 item(s) and 0 warning(s).
```

A single failed feed is treated as a warning and does not stop the entire
briefing. Feed warnings are included at the bottom of the email.

## Current coverage

- Microsoft security and threat intelligence
- AWS security and identity
- Palo Alto Networks Unit 42
- Cisco Talos
- Google Project Zero
- Active exploitation
- Ransomware
- Nation-state activity
- Identity security
- Cloud security
- Supply-chain security
- General threat intelligence

## Deliberate limitations

- This is a separate test email. It is not yet merged with the CISA KEV email.
- Summaries come from the publisher's RSS/Atom feed.
- “Why it matters” and recommended actions are deterministic category templates.
- The collector does not yet fetch and analyse the full linked article.
- Fortinet PSIRT, Cisco PSIRT, Apple security releases, Okta advisories,
  CrowdStrike, Azure service notices, Nordic sources, and NIS2 updates will be
  added as source-specific adapters after this generic feed collector works.
- No state file exists yet, so the same article may be sent again within the
  selected lookback window.

## Next step after successful testing

Merge this collector with the existing CISA KEV collector into one email, then
add persistent state so previously reported items are not repeated.
