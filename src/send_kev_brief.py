import html
import json
import os
import smtplib
import ssl
import sys
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


KEV_FEED_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

KEV_CATALOG_URL = (
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
)


def required_environment_variable(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise RuntimeError(
            f"Required environment variable is missing: {name}"
        )

    return value.strip()


def get_lookback_days() -> int:
    raw_value = os.getenv("KEV_LOOKBACK_DAYS", "7")

    try:
        value = int(raw_value)
    except ValueError as error:
        raise RuntimeError(
            "KEV_LOOKBACK_DAYS must be an integer."
        ) from error

    if value < 1 or value > 365:
        raise RuntimeError(
            "KEV_LOOKBACK_DAYS must be between 1 and 365."
        )

    return value


def fetch_kev_catalogue() -> dict[str, Any]:
    request = Request(
        KEV_FEED_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": (
                "security-intelligence-brief/1.0 "
                "(GitHub Actions KEV collector)"
            ),
        },
    )

    try:
        with urlopen(request, timeout=45) as response:
            if response.status != 200:
                raise RuntimeError(
                    f"CISA returned HTTP status {response.status}."
                )

            return json.load(response)

    except HTTPError as error:
        raise RuntimeError(
            f"CISA KEV request failed with HTTP {error.code}."
        ) from error

    except URLError as error:
        raise RuntimeError(
            f"Unable to connect to the CISA KEV feed: {error.reason}"
        ) from error

    except json.JSONDecodeError as error:
        raise RuntimeError(
            "The CISA KEV feed did not contain valid JSON."
        ) from error


def select_recent_entries(
    catalogue: dict[str, Any],
    lookback_days: int,
) -> list[dict[str, Any]]:
    vulnerabilities = catalogue.get("vulnerabilities", [])

    if not isinstance(vulnerabilities, list):
        raise RuntimeError(
            "Unexpected CISA KEV feed structure: "
            "'vulnerabilities' is not a list."
        )

    today = datetime.now(timezone.utc).date()
    cutoff_date = today - timedelta(days=lookback_days - 1)

    selected: list[dict[str, Any]] = []

    for vulnerability in vulnerabilities:
        date_added_raw = vulnerability.get("dateAdded")

        if not date_added_raw:
            continue

        try:
            date_added = date.fromisoformat(date_added_raw)
        except ValueError:
            print(
                f"Skipping entry with invalid dateAdded: "
                f"{date_added_raw}",
                file=sys.stderr,
            )
            continue

        if date_added >= cutoff_date:
            selected.append(vulnerability)

    selected.sort(
        key=lambda item: (
            item.get("dateAdded", ""),
            item.get("cveID", ""),
        ),
        reverse=True,
    )

    return selected


def normalise_value(value: Any, fallback: str = "Not specified") -> str:
    if value is None:
        return fallback

    rendered = str(value).strip()
    return rendered if rendered else fallback


def render_text_report(
    catalogue: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    lookback_days: int,
) -> str:
    catalogue_version = normalise_value(
        catalogue.get("catalogVersion")
    )
    catalogue_release = normalise_value(
        catalogue.get("dateReleased")
    )

    lines = [
        "CISA Known Exploited Vulnerabilities Brief",
        "=" * 45,
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Catalogue version: {catalogue_version}",
        f"Catalogue release: {catalogue_release}",
        f"Lookback period: {lookback_days} calendar days",
        f"Matching additions: {len(vulnerabilities)}",
        "",
    ]

    if not vulnerabilities:
        lines.extend(
            [
                "No CISA KEV additions were found during "
                "the selected period.",
                "",
                f"Catalogue: {KEV_CATALOG_URL}",
            ]
        )

        return "\n".join(lines)

    for index, item in enumerate(vulnerabilities, start=1):
        cve_id = normalise_value(item.get("cveID"))
        vendor = normalise_value(item.get("vendorProject"))
        product = normalise_value(item.get("product"))
        name = normalise_value(item.get("vulnerabilityName"))
        date_added = normalise_value(item.get("dateAdded"))
        due_date = normalise_value(item.get("dueDate"))
        ransomware = normalise_value(
            item.get("knownRansomwareCampaignUse"),
            fallback="Unknown",
        )
        description = normalise_value(
            item.get("shortDescription")
        )
        required_action = normalise_value(
            item.get("requiredAction")
        )
        notes = normalise_value(
            item.get("notes"),
            fallback="No additional notes.",
        )

        lines.extend(
            [
                f"{index}. {cve_id} — {vendor} {product}",
                "-" * 70,
                f"Vulnerability: {name}",
                f"Date added: {date_added}",
                f"CISA due date: {due_date}",
                f"Known ransomware use: {ransomware}",
                "",
                "Why it matters:",
                (
                    "CISA has confirmed that this vulnerability "
                    "has been exploited in real-world attacks."
                ),
                "",
                "Who is affected:",
                f"Organisations operating {vendor} {product}.",
                "",
                "Description:",
                description,
                "",
                "Recommended action:",
                required_action,
                "",
                f"Additional notes: {notes}",
                "",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
                f"CISA catalogue: {KEV_CATALOG_URL}",
                "",
            ]
        )

    return "\n".join(lines)


def render_html_report(
    catalogue: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    lookback_days: int,
) -> str:
    generated = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    catalogue_version = html.escape(
        normalise_value(catalogue.get("catalogVersion"))
    )

    sections: list[str] = []

    for item in vulnerabilities:
        cve_id_raw = normalise_value(item.get("cveID"))
        cve_id = html.escape(cve_id_raw)
        vendor = html.escape(
            normalise_value(item.get("vendorProject"))
        )
        product = html.escape(
            normalise_value(item.get("product"))
        )
        name = html.escape(
            normalise_value(item.get("vulnerabilityName"))
        )
        date_added = html.escape(
            normalise_value(item.get("dateAdded"))
        )
        due_date = html.escape(
            normalise_value(item.get("dueDate"))
        )
        ransomware = html.escape(
            normalise_value(
                item.get("knownRansomwareCampaignUse"),
                fallback="Unknown",
            )
        )
        description = html.escape(
            normalise_value(item.get("shortDescription"))
        )
        required_action = html.escape(
            normalise_value(item.get("requiredAction"))
        )

        sections.append(
            f"""
            <section style="
                border: 1px solid #d0d7de;
                border-radius: 6px;
                padding: 18px;
                margin: 0 0 18px 0;
            ">
                <h2 style="margin-top: 0;">
                    {cve_id} — {vendor} {product}
                </h2>

                <p><strong>{name}</strong></p>

                <table style="border-collapse: collapse;">
                    <tr>
                        <td style="padding: 3px 15px 3px 0;">
                            <strong>Date added</strong>
                        </td>
                        <td>{date_added}</td>
                    </tr>
                    <tr>
                        <td style="padding: 3px 15px 3px 0;">
                            <strong>CISA due date</strong>
                        </td>
                        <td>{due_date}</td>
                    </tr>
                    <tr>
                        <td style="padding: 3px 15px 3px 0;">
                            <strong>Known ransomware use</strong>
                        </td>
                        <td>{ransomware}</td>
                    </tr>
                </table>

                <h3>Why it matters</h3>
                <p>
                    CISA has confirmed that this vulnerability
                    has been exploited in real-world attacks.
                </p>

                <h3>Who is affected</h3>
                <p>
                    Organisations operating {vendor} {product}.
                </p>

                <h3>Description</h3>
                <p>{description}</p>

                <h3>Recommended action</h3>
                <p>{required_action}</p>

                <p>
                    <a href="
                        https://nvd.nist.gov/vuln/detail/{cve_id}
                    ">
                        NVD record
                    </a>
                    |
                    <a href="{KEV_CATALOG_URL}">
                        CISA KEV catalogue
                    </a>
                </p>
            </section>
            """
        )

    if not sections:
        sections.append(
            """
            <p>
                No CISA KEV additions were found during the
                selected period.
            </p>
            """
        )

    return f"""
    <!doctype html>
    <html lang="en">
    <body style="
        font-family: Arial, Helvetica, sans-serif;
        line-height: 1.5;
        color: #1f2328;
        max-width: 850px;
        margin: 20px auto;
        padding: 0 20px;
    ">
        <h1>CISA Known Exploited Vulnerabilities Brief</h1>

        <p>
            <strong>Generated:</strong> {generated}<br>
            <strong>Catalogue version:</strong>
            {catalogue_version}<br>
            <strong>Lookback:</strong>
            {lookback_days} calendar days<br>
            <strong>Matching additions:</strong>
            {len(vulnerabilities)}
        </p>

        {''.join(sections)}
    </body>
    </html>
    """


def send_email(
    username: str,
    app_password: str,
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

    ssl_context = ssl.create_default_context()

    with smtplib.SMTP(
        "smtp.gmail.com",
        587,
        timeout=45,
    ) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl_context)
        smtp.ehlo()
        smtp.login(username, app_password.replace(" ", ""))
        smtp.send_message(message)


def main() -> int:
    try:
        gmail_username = required_environment_variable(
            "GMAIL_USERNAME"
        )
        gmail_app_password = required_environment_variable(
            "GMAIL_APP_PASSWORD"
        )
        email_to = required_environment_variable("EMAIL_TO")
        lookback_days = get_lookback_days()

        print("Downloading the CISA KEV catalogue...")
        catalogue = fetch_kev_catalogue()

        vulnerabilities = select_recent_entries(
            catalogue,
            lookback_days,
        )

        print(
            f"Found {len(vulnerabilities)} entries added "
            f"within {lookback_days} days."
        )

        text_report = render_text_report(
            catalogue,
            vulnerabilities,
            lookback_days,
        )

        html_report = render_html_report(
            catalogue,
            vulnerabilities,
            lookback_days,
        )

        subject = (
            f"CISA KEV Brief: {len(vulnerabilities)} "
            f"addition(s) in {lookback_days} days"
        )

        send_email(
            username=gmail_username,
            app_password=gmail_app_password,
            recipient=email_to,
            subject=subject,
            text_body=text_report,
            html_body=html_report,
        )

        print("CISA KEV briefing sent successfully.")
        return 0

    except (
        RuntimeError,
        smtplib.SMTPException,
        OSError,
    ) as error:
        print(
            f"Pipeline failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
