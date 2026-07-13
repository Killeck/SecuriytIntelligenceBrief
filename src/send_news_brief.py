import calendar
import html
import os
import re
import smtplib
import ssl
import sys
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.request import Request, urlopen

import feedparser


SOURCES = [
    {
        "name": "Microsoft Security Blog",
        "vendor": "Microsoft",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "priority": 30,
    },
    {
        "name": "AWS Security Blog",
        "vendor": "AWS",
        "url": "https://aws.amazon.com/blogs/security/feed/",
        "priority": 18,
    },
    {
        "name": "Palo Alto Unit 42",
        "vendor": "Palo Alto Networks",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "priority": 25,
    },
    {
        "name": "Cisco Talos",
        "vendor": "Cisco",
        "url": "https://blog.talosintelligence.com/feeds/posts/default?alt=rss",
        "priority": 25,
    },
    {
        "name": "Google Project Zero",
        "vendor": "Google",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
        "priority": 24,
    },
]

RULES = [
    (
        "Active exploitation",
        ["actively exploited", "exploited in the wild", "zero-day", "0-day"],
        40,
    ),
    (
        "Ransomware",
        ["ransomware", "extortion", "encryptor"],
        30,
    ),
    (
        "Nation-state activity",
        [
            "nation-state",
            "state-sponsored",
            "apt",
            "espionage",
            "north korea",
            "russia",
            "china",
            "iran",
        ],
        25,
    ),
    (
        "Identity security",
        [
            "entra",
            "active directory",
            "okta",
            "identity",
            "oauth",
            "mfa",
            "authentication",
            "token",
            "credential",
            "kerberos",
        ],
        20,
    ),
    (
        "Supply-chain security",
        [
            "supply chain",
            "npm",
            "pypi",
            "dependency",
            "package",
            "github actions",
            "build pipeline",
        ],
        25,
    ),
    (
        "Cloud security",
        [
            "azure",
            "aws",
            "google cloud",
            "cloud",
            "kubernetes",
            "container",
            "docker",
            "terraform",
        ],
        15,
    ),
    (
        "Threat intelligence",
        [
            "malware",
            "campaign",
            "threat actor",
            "phishing",
            "botnet",
            "backdoor",
            "infostealer",
            "wiper",
            "initial access",
        ],
        15,
    ),
]

WHY = {
    "Active exploitation": (
        "The reporting indicates current exploitation or a sharply reduced "
        "window for exposure assessment and remediation."
    ),
    "Ransomware": (
        "The development may affect current initial-access, extortion, "
        "containment, or recovery assumptions."
    ),
    "Nation-state activity": (
        "The activity may indicate espionage or disruptive targeting relevant "
        "to exposed sectors, regions, and technologies."
    ),
    "Identity security": (
        "Identity compromise can provide direct access to cloud, email, "
        "administrative, and business systems."
    ),
    "Supply-chain security": (
        "A compromised package, build process, or supplier can propagate access "
        "across many downstream organisations."
    ),
    "Cloud security": (
        "Cloud control-plane and workload identity weaknesses can create broad "
        "access with limited traditional network visibility."
    ),
    "Threat intelligence": (
        "The report may provide current attacker behaviours, infrastructure, "
        "malware characteristics, or detection opportunities."
    ),
    "Vendor update": (
        "The development may require review where the named product, service, "
        "or security control is used."
    ),
}

ACTION = {
    "Active exploitation": (
        "Identify exposure, verify patches or mitigations, review public-facing "
        "assets, and hunt for the published behaviours or indicators."
    ),
    "Ransomware": (
        "Review initial-access controls, ingest relevant indicators, verify "
        "protected backups, and confirm containment paths."
    ),
    "Nation-state activity": (
        "Assess sector and geographic relevance, then map published indicators "
        "and techniques to existing controls and detections."
    ),
    "Identity security": (
        "Review sign-ins and token use, enforce phishing-resistant MFA where "
        "possible, and revoke suspicious sessions or credentials."
    ),
    "Supply-chain security": (
        "Check dependency and supplier exposure, verify package provenance, "
        "review build logs, and rotate secrets where compromise is plausible."
    ),
    "Cloud security": (
        "Review workload identities, public exposure, privileged roles, and "
        "control-plane logs relevant to the report."
    ),
    "Threat intelligence": (
        "Read the primary report, extract applicable IOCs and TTPs, validate "
        "detection coverage, and run a targeted threat hunt."
    ),
    "Vendor update": (
        "Determine whether the technology is in use and assign an owner to "
        "assess operational or security impact."
    ),
}


class TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        cleaned = data.strip()
        if cleaned:
            self.parts.append(cleaned)


def clean(value: str) -> str:
    parser = TextParser()
    parser.feed(value or "")
    return re.sub(r"\s+", " ", " ".join(parser.parts)).strip()


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value.strip()


def integer_setting(name: str, default: int, minimum: int, maximum: int) -> int:
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


def published_time(entry) -> datetime | None:
    for field in ("published_parsed", "updated_parsed"):
        parsed = entry.get(field)
        if parsed:
            return datetime.fromtimestamp(
                calendar.timegm(parsed),
                tz=timezone.utc,
            )
    return None


def classify(text: str) -> tuple[str, int]:
    lowered = text.lower()
    for category, keywords, weight in RULES:
        if any(keyword in lowered for keyword in keywords):
            return category, weight
    return "Vendor update", 0


def fetch(source: dict, cutoff: datetime) -> list[dict]:
    request = Request(
        source["url"],
        headers={"User-Agent": "security-intelligence-brief/1.0"},
    )
    with urlopen(request, timeout=45) as response:
        feed = feedparser.parse(response.read())

    if not feed.entries:
        raise RuntimeError("Feed returned no entries")

    items: list[dict] = []

    for entry in feed.entries:
        published = published_time(entry)
        if published is None or published < cutoff:
            continue

        title = clean(entry.get("title", "Untitled"))
        summary = clean(
            entry.get("summary")
            or entry.get("description")
            or "No summary supplied by source."
        )
        combined = f"{title} {summary}"
        category, weight = classify(combined)
        score = source["priority"] + weight

        if published >= datetime.now(timezone.utc) - timedelta(hours=24):
            score += 10

        if any(
            word in combined.lower()
            for word in [
                "webinar",
                "event",
                "award",
                "gartner",
                "forrester",
                "customer story",
            ]
        ):
            score -= 35

        if score < 20:
            continue

        items.append(
            {
                "title": title,
                "summary": summary[:700],
                "link": str(entry.get("link", "")).strip(),
                "published": published,
                "source": source["name"],
                "vendor": source["vendor"],
                "category": category,
                "score": score,
                "cves": sorted(
                    set(
                        re.findall(
                            r"\bCVE-\d{4}-\d{4,7}\b",
                            combined,
                            re.IGNORECASE,
                        )
                    )
                ),
            }
        )

    return items


def priority(score: int) -> str:
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Monitor"


def threat_level(items: list[dict]) -> str:
    if any(item["score"] >= 80 for item in items):
        return "High"

    if any(
        item["category"]
        in {"Active exploitation", "Ransomware", "Nation-state activity"}
        for item in items
    ):
        return "Elevated"

    return "Guarded" if items else "Low"


def render(items: list[dict], warnings: list[str], hours: int) -> tuple[str, str]:
    level = threat_level(items)
    top = items[:5]

    text = [
        "Daily Cybersecurity News Brief",
        f"Reporting window: previous {hours} hours",
        f"Overall threat level: {level}",
        "",
        "Top developments:",
    ]

    if not top:
        text.append("- No qualifying news items were collected.")

    for item in top:
        text.append(
            f"- [{priority(item['score'])}] {item['title']} "
            f"({item['source']})"
        )

    cards: list[str] = []

    for item in items:
        cves = ", ".join(item["cves"]) or "None identified"

        text.extend(
            [
                "",
                item["title"],
                f"Source: {item['source']}",
                f"Category: {item['category']}",
                f"Priority: {priority(item['score'])}",
                f"CVEs: {cves}",
                f"Summary: {item['summary']}",
                f"Why it matters: {WHY[item['category']]}",
                (
                    "Who is affected: Organisations using "
                    f"{item['vendor']} technologies or matching the affected "
                    "sectors and attack surface described by the source."
                ),
                f"Recommended action: {ACTION[item['category']]}",
                f"Primary source: {item['link']}",
            ]
        )

        cards.append(
            f"""
            <article style="
                border:1px solid #d0d7de;
                border-radius:8px;
                padding:18px;
                margin-bottom:16px
            ">
              <h2 style="margin-top:0">{html.escape(item["title"])}</h2>
              <p>
                <strong>Source:</strong> {html.escape(item["source"])}<br>
                <strong>Published:</strong>
                {item["published"].strftime("%Y-%m-%d %H:%M UTC")}<br>
                <strong>Category:</strong>
                {html.escape(item["category"])}<br>
                <strong>Priority:</strong> {priority(item["score"])}<br>
                <strong>CVEs:</strong> {html.escape(cves)}
              </p>

              <h3>Summary</h3>
              <p>{html.escape(item["summary"])}</p>

              <h3>Why it matters</h3>
              <p>{html.escape(WHY[item["category"]])}</p>

              <h3>Who is affected</h3>
              <p>
                Organisations using {html.escape(item["vendor"])} technologies
                or matching the affected sectors and attack surface described
                by the source.
              </p>

              <h3>Recommended action</h3>
              <p>{html.escape(ACTION[item["category"]])}</p>

              <p>
                <a href="{html.escape(item["link"], quote=True)}">
                    Open primary source
                </a>
              </p>
            </article>
            """
        )

    if warnings:
        text.extend(["", "Feed warnings:"])
        text.extend(f"- {warning}" for warning in warnings)

    top_html = "".join(
        f"<li><strong>{priority(item['score'])}:</strong> "
        f"{html.escape(item['title'])} "
        f"<em>({html.escape(item['source'])})</em></li>"
        for item in top
    ) or "<li>No qualifying news items were collected.</li>"

    warning_html = ""
    if warnings:
        warning_html = (
            "<h2>Feed warnings</h2><ul>"
            + "".join(
                f"<li>{html.escape(warning)}</li>" for warning in warnings
            )
            + "</ul>"
        )

    html_body = f"""
    <!doctype html>
    <html>
    <body style="
        font-family:Arial,sans-serif;
        line-height:1.5;
        max-width:900px;
        margin:20px auto;
        padding:0 20px
    ">
      <h1>Daily Cybersecurity News Brief</h1>

      <p>
        <strong>Reporting window:</strong> previous {hours} hours<br>
        <strong>Overall threat level:</strong> {level}<br>
        <strong>Included items:</strong> {len(items)}
      </p>

      <h2>Top developments</h2>
      <ul>{top_html}</ul>

      {''.join(cards)}

      <h2>CISO watch list</h2>
      <ul>
        <li>New active exploitation and CISA KEV additions.</li>
        <li>Identity attacks involving tokens, MFA, OAuth, and sessions.</li>
        <li>Ransomware initial-access and extortion developments.</li>
        <li>Cloud control-plane and software supply-chain compromises.</li>
      </ul>

      {warning_html}
    </body>
    </html>
    """

    return "\n".join(text), html_body


def send_email(
    username: str,
    password: str,
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> None:
    message = EmailMessage()
    message["From"] = username
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    context = ssl.create_default_context()

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=45) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login(username, password.replace(" ", ""))
        refused = smtp.send_message(message)

        if refused:
            raise RuntimeError(f"SMTP refused recipients: {refused}")


def main() -> int:
    try:
        username = required("GMAIL_USERNAME")
        password = required("GMAIL_APP_PASSWORD")
        recipient = required("EMAIL_TO")

        hours = integer_setting(
            "NEWS_LOOKBACK_HOURS",
            default=72,
            minimum=1,
            maximum=720,
        )
        max_items = integer_setting(
            "NEWS_MAX_ITEMS",
            default=15,
            minimum=1,
            maximum=50,
        )

        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
        items: list[dict] = []
        warnings: list[str] = []

        for source in SOURCES:
            try:
                found = fetch(source, cutoff)
                items.extend(found)
                print(f"{source['name']}: {len(found)} item(s)")
            except Exception as error:
                warning = (
                    f"{source['name']}: "
                    f"{type(error).__name__}: {error}"
                )
                warnings.append(warning)
                print(f"WARNING: {warning}", file=sys.stderr)

        unique: dict[str, dict] = {}

        for item in items:
            key = item["link"] or item["title"].lower()
            unique[key] = item

        items = sorted(
            unique.values(),
            key=lambda item: (item["score"], item["published"]),
            reverse=True,
        )[:max_items]

        text_body, html_body = render(items, warnings, hours)

        subject = (
            f"Security News Brief: {len(items)} item(s), "
            f"threat level {threat_level(items)}"
        )

        send_email(
            username,
            password,
            recipient,
            subject,
            text_body,
            html_body,
        )

        print(
            f"Brief sent with {len(items)} item(s) and "
            f"{len(warnings)} warning(s)."
        )
        return 0

    except Exception as error:
        print(
            f"Pipeline failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
