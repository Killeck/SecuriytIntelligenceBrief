# Copyright © 2026 John-Helge Gantz. All rights reserved.
# Proprietary and confidential. See LICENSE.

"""Backward-compatible command entry point for GitHub Actions."""

from security_brief.app import main


if __name__ == "__main__":
    raise SystemExit(main())
