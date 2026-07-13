import os
import smtplib
import ssl
import sys
from datetime import datetime, timezone
from email.message import EmailMessage


def required_environment_variable(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")

    return value


def main() -> int:
    gmail_username = required_environment_variable("GMAIL_USERNAME")
    gmail_app_password = required_environment_variable("GMAIL_APP_PASSWORD")
    email_to = required_environment_variable("EMAIL_TO")

    generated_at = datetime.now(timezone.utc)

    message = EmailMessage()
    message["From"] = gmail_username
    message["To"] = email_to
    message["Subject"] = "Security intelligence pipeline test"

    message.set_content(
        "\n".join(
            [
                "GitHub Actions successfully sent this test email through Gmail.",
                "",
                f"Generated at: {generated_at.isoformat()}",
                "",
                "The email-delivery component of the security intelligence "
                "pipeline is working.",
            ]
        )
    )

    ssl_context = ssl.create_default_context()

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl_context)
            smtp.ehlo()
            smtp.login(gmail_username, gmail_app_password)
            smtp.send_message(message)

    except smtplib.SMTPAuthenticationError as error:
        print(
            "Gmail authentication failed. Verify the Gmail address, "
            "two-step verification and App Password.",
            file=sys.stderr,
        )
        print(f"SMTP response code: {error.smtp_code}", file=sys.stderr)
        return 1

    except (smtplib.SMTPException, OSError) as error:
        print(
            f"Email transmission failed: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    print("Test email sent successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
