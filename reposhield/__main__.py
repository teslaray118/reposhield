"""
Module execution entry point (python -m reposhield ...)
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
