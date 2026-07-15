# Copyright © 2026 John-Helge Gantz. All rights reserved.
#
# Proprietary and confidential.
# Unauthorised use, copying, modification or distribution is prohibited.
# See the LICENSE file at the repository root for complete terms.

"""Backward-compatible command entry point for GitHub Actions."""

from security_brief.app import main


if __name__ == "__main__":
    raise SystemExit(main())
