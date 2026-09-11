"""Allow ``python -m kmcs``."""

from __future__ import annotations

from kmcs.main import main

if __name__ == "__main__":
    raise SystemExit(main())
