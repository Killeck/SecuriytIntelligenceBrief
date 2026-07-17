# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Gmail API delivery for the rendered briefing."""

from __future__ import annotations

import base64
from email.message import EmailMessage

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"


def build_message(
    username: str,
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> EmailMessage:
    """Build the multipart briefing message."""

    message = EmailMessage()
    message["From"] = username
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(text_body, charset="utf-8")
    message.add_alternative(html_body, subtype="html", charset="utf-8")
    return message


def send_email(
    username: str,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    recipient: str,
    subject: str,
    text_body: str,
    html_body: str,
) -> None:
    """Send the multipart briefing through the Gmail API."""

    message = build_message(
        username,
        recipient,
        subject,
        text_body,
        html_body,
    )

    credentials = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=GOOGLE_TOKEN_URI,
        client_id=client_id,
        client_secret=client_secret,
        scopes=[GMAIL_SEND_SCOPE],
    )
    credentials.refresh(Request())

    service = build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )
    raw_message = base64.urlsafe_b64encode(
        message.as_bytes()
    ).decode("ascii")

    response = (
        service.users()
        .messages()
        .send(
            userId="me",
            body={"raw": raw_message},
        )
        .execute()
    )

    if not response.get("id"):
        raise RuntimeError("Gmail API returned no message ID.")
