# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""SMTP delivery for the rendered briefing."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage


def build_message(
    username: str,
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> EmailMessage:
    """Build the same simple multipart structure used by V5.0."""

    message = EmailMessage()
    message["From"] = username
    message["To"] = recipient
    message["Subject"] = subject
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
        refused = smtp.send_message(message)

        if refused:
            raise RuntimeError(f"SMTP refused recipients: {refused}")
