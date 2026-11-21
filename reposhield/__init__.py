"""
RepoShield: AST-Based Python Dependency & Regression Sentinel
Version 1.0.0
"""

from .engine import (
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
from .cli import main

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
