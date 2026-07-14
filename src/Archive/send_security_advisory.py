"""Backward-compatible command entry point for GitHub Actions."""

from security_brief.app import main


if __name__ == "__main__":
    raise SystemExit(main())
