# RepoShield 🛡️

**AST-Based Python Dependency, Regression, and Contract Sentinel for AI-Assisted Development**

[![CI](https://github.com/teslaray118/reposhield/actions/workflows/ci.yml/badge.svg)](https://github.com/teslaray118/reposhield/actions/workflows/ci.yml)
[![Python Versions](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://pypi.org/project/reposhield/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(pure%20stdlib)-green.svg)](https://github.com/teslaray118/reposhield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

RepoShield is a lightweight, zero-dependency static analysis tool designed to catch cross-file contract breaks, missing symbols, and API regressions before code reaches production. Built especially for workflows where AI coding assistants (ChatGPT, Claude, Copilot, Cursor) edit individual files without repository-wide awareness.

---

## The Problem

When AI coding assistants update code, they frequently rewrite or rename a function in one file without updating the downstream files that depend on it. This causes silent runtime failures (`ImportError`, `AttributeError`, signature mismatches) that linters often miss.

RepoShield acts as a repository sentinel: it maps all cross-file dependencies using Python's native Abstract Syntax Tree (AST), audits public interfaces, and—when an edit introduces a regression—generates an instant, copy-pasteable remediation prompt for your AI model to fix it cleanly.

---

## Key Features

- **Zero Runtime Dependencies**: 100% pure Python standard library. No external binaries or heavy frameworks.
- **Python Scope Resolution**: Lexical scope pre-analysis properly isolates function-local assignments, nested functions, and class scopes according to Python semantics.
- **Recursive C3 MRO**: Accurately resolves inherited methods, method overrides, and call signatures across multi-level and multiple inheritance hierarchies.
- **Smart Module Resolution**: First-class support for `src/` directory layouts, nested packages, and PEP 420 namespace packages.
- **Dynamic Provenance Tracking**: Statically resolves literal `importlib.import_module()` and `getattr()` calls, with safe provenance invalidation on variable reassignment.
- **Wildcard Export Validation**: Statically parses module `__all__` lists, tuples, concatenations, and appends to detect missing symbols while reporting conservative uncertainty for dynamic expressions.
- **Debounced Watch Mode**: Resilient filesystem watcher designed for atomic editor saves (VS Code, PyCharm, Vim) with temp file filtering.
- **Instant AI Recovery Prompts**: Generates concise, context-aware remediation instructions ready to paste into any AI model.

---

## Installation

### From PyPI (Recommended)
```bash
pip install reposhield
```

### Standalone (No Install Required)
RepoShield can also be run directly from source without installation:
```bash
git clone https://github.com/teslaray118/reposhield.git
cd reposhield
python reposhield.py --help
```

---

## Quick Start

### 1. Scan Repository Blueprint
Map all Python modules, definitions, and cross-file dependencies:
```bash
reposhield scan .
```

### 2. Audit Code Integrity
Audit your project for broken contracts, missing exports, or signature mismatches:
```bash
reposhield check .
```

### 3. Active Watch Mode (Real-Time Sentinel)
Monitor your project for file saves while coding with AI:
```bash
reposhield watch .
```
When an edit removes or breaks a symbol needed by another file, RepoShield immediately alerts you:
```text
🚨 REGRESSION DETECTED: Code saved, but cross-file connections broke!
💥 CASUALTY: 'school.py' needs 'deliver_water()' from pipes.py, but it was REMOVED.

👉 SEND THIS REMEDIATION PROMPT TO YOUR AI:
"Your update broke existing connections. The following functions must remain available:
- 'deliver_water' (required by school.py)
Please update pipes.py to preserve backward compatibility while adding your new features."
```

### 4. Run Test Suite
Run all 65 built-in regression tests:
```bash
reposhield test
```
Or via standard unittest discovery:
```bash
python -m unittest discover -s tests
```

---

## CLI Reference

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `reposhield scan` | `[path]` | Scan repository and print dependency blueprint (default: `.`) |
| `reposhield check` | `[path]` | Audit repository for contract breaks and return non-zero on error |
| `reposhield watch` | `[path]` | Start continuous filesystem sentinel with AI prompt generation |
| `reposhield test` | | Execute the complete 65-test verification suite |
| `reposhield --version` | | Display installed version |
| `reposhield --help` | | Show usage instructions |

---

## Diagnostic Categories

RepoShield standardizes all findings with confidence levels and severities:

- **`SYNTAX_ERROR`** (*Critical / Confirmed*): File contains malformed Python syntax preventing parsing.
- **`BROKEN_CONTRACT`** (*Critical / Confirmed*): Imported function, class, or symbol was removed, renamed, or missing from `__all__`.
- **`SIGNATURE_MISMATCH`** (*Critical / Confirmed*): Call arguments violate positional, keyword, or positional-only parameter constraints.
- **`UNRESOLVED_IMPORT`** (*Warning / Uncertain*): Target module cannot be verified locally; may be third-party or runtime-constructed.
- **`CONDITIONAL_IMPORT`** (*Info / Uncertain*): Import is guarded by `try...except ImportError` or `if sys.platform` checks.
- **`DYNAMIC_IMPORT`** (*Info / Uncertain*): Module loaded via non-literal dynamic expression.
- **`AMBIGUOUS_IMPORT`** (*Warning / Uncertain*): Multiple local files share the same candidate module name.

---

## Known Limitations

RepoShield is a **static analyzer**, not a dynamic execution runtime:
- **Runtime Metaprogramming**: Attributes generated dynamically via `setattr()` or `__getattr__` without static clues cannot be guaranteed.
- **Unbounded Dynamic Imports**: Dynamic imports with runtime-constructed strings (e.g. `import_module(f"plugins.{get_env()}")`) are flagged with an informational warning rather than validated.
- **Untyped Container Contents**: Does not infer runtime element types inside arbitrary containers or untyped dictionary lookups.

---

## Security

RepoShield **never executes analyzed project code**. All scans are conducted purely via AST parsing of source text, ensuring safe execution even on untrusted repositories.

---

## Contributing & Testing

1. Fork and clone the repository.
2. Run the test suite:
   ```bash
   python reposhield.py test
   ```
3. Submit a pull request with regression tests covering any proposed improvements.

---

## Author & Acknowledgements

Created by **Tesla Ray** (16-year-old student from Kenya).

---

## License

This project is licensed under the [MIT License](LICENSE).
