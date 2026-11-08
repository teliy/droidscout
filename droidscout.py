"""Запускалка DroidScout из корня репозитория: `python droidscout.py`."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from droidscout.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
