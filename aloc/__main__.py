"""Run AILatch through the legacy ``python -m aloc`` entry point."""

import sys

from ailatch.cli import main


if __name__ == "__main__":
    sys.exit(main())
