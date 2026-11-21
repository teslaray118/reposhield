#!/usr/bin/env python3
"""
RepoShield (v1.0.0) Backward-Compatibility Launcher and Public API Re-exporter.
Allows running directly as:
    python reposhield.py scan .
    python reposhield.py check .
    python reposhield.py watch .
    python reposhield.py test
And importing directly from reposhield.py.
"""

import sys
import os

# Add package root to sys.path so reposhield package is always discoverable
here = os.path.dirname(os.path.abspath(__file__))
if here not in sys.path:
    sys.path.insert(0, here)

from reposhield.engine import (
    VERSION,
    extract_file_info,
    get_project_files,
    resolve_import_target,
    build_dependency_graph,
    get_transitive_dependents,
    check_project_integrity,
    generate_ai_remediation_prompt,
    run_scan,
    run_check,
    run_watch,
    run_tests,
)
from reposhield.cli import main

__version__ = VERSION
__all__ = [
    "VERSION",
    "extract_file_info",
    "get_project_files",
    "resolve_import_target",
    "build_dependency_graph",
    "get_transitive_dependents",
    "check_project_integrity",
    "generate_ai_remediation_prompt",
    "run_scan",
    "run_check",
    "run_watch",
    "run_tests",
    "main",
]

if __name__ == "__main__":
    sys.exit(main())
