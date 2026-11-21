"""
RepoShield Command Line Interface (v1.0.0)
"""

import sys
from pathlib import Path
from .engine import (
    VERSION,
    run_scan,
    run_check,
    run_watch,
    run_tests,
)


def print_help():
    print(f"RepoShield Sentinel v{VERSION} — Python AST Dependency & Regression Sentinel")
    print("Usage: reposhield [command] [target_directory]")
    print("")
    print("Commands:")
    print("  scan   [path]    Scan repository and print dependency blueprint (default: .)")
    print("  check  [path]    Audit repository for broken imports, missing methods, and contract violations")
    print("  watch  [path]    Watch project for live file saves and generate instant AI remediation prompts")
    print("  test             Execute built-in unit and regression test suite")
    print("  --version        Print version string")
    print("  --help, -h       Show this help message")
    print("")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        print_help()
        return 0

    cmd = argv[0].lower()
    target = argv[1] if len(argv) > 1 else "."

    if cmd in ("--version", "-v", "version"):
        print(f"reposhield {VERSION}")
        return 0
    elif cmd in ("--help", "-h", "help"):
        print_help()
        return 0
    elif cmd == "scan":
        run_scan(target)
        return 0
    elif cmd == "check":
        return run_check(target)
    elif cmd == "watch":
        return run_watch(target)
    elif cmd == "test":
        return run_tests()
    else:
        print(f"Error: Unknown command '{cmd}'.")
        print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
