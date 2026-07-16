# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""SMTP delivery for the rendered briefing."""

from __future__ import annotations

import smtplib
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, make_msgid


def build_message(
    username: str,
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> EmailMessage:
    """Build a standards-compliant multipart message.

    The authenticated Gmail or Google Workspace address remains the RFC 5322
    sender so SPF, DKIM and DMARC alignment are not weakened by an alias. The
    display name and subject remain neutral to avoid unnecessary urgency signals.
    """

    sender_domain = username.rpartition("@")[2] or None
    message = EmailMessage()
    message["From"] = formataddr(("Security Intelligence Brief", username))
    message["To"] = recipient
    message["Reply-To"] = username
    message["Subject"] = subject
    message["Date"] = format_datetime(datetime.now(timezone.utc))
    message["Message-ID"] = make_msgid(domain=sender_domain)
    message["Auto-Submitted"] = "auto-generated"
    message["X-Auto-Response-Suppress"] = "All"
    message["Content-Language"] = "en-GB"
    message.set_content(text_body, charset="utf-8")
    message.add_alternative(html_body, subtype="html", charset="utf-8")
    return message


def send_email(
    username: str,
    password: str,
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> None:
    """Send the multipart briefing through Gmail SMTP with STARTTLS."""

    message = build_message(
        username,
        recipient,
        subject,
        text_body,
        html_body,
    )
    context = ssl.create_default_context()

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=60) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login(username, password.replace(" ", ""))
        refused = smtp.send_message(
            message,
            from_addr=username,
            to_addrs=[recipient],
        )

        if refused:
            raise RuntimeError(f"SMTP refused recipients: {refused}")
