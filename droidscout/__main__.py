"""Позволяет запускать `python -m droidscout`."""

import sys

from .main import main

if __name__ == "__main__":
    sys.exit(main())
