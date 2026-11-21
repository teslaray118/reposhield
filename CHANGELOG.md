# Changelog

All notable changes to RepoShield are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-20

### Added
- **Production Package Architecture**: Structured into installable `reposhield` package (`cli.py`, `engine.py`, `__main__.py`) with root `reposhield.py` backward-compatibility launcher.
- **PyPI Packaging**: Full standard `pyproject.toml` configuration with console entry point `reposhield`.
- **Lexical Scope Pre-Analysis**: Python-compliant symbol resolution treating assignments in function bodies as local throughout, preventing false resolution against module-level imports.
- **Class Scope Isolation**: Methods no longer incorrectly inherit free variables from enclosing class bodies.
- **Recursive C3 MRO**: Complete Python Method Resolution Order supporting multi-level inheritance, multiple inheritance diamonds, method overrides, and signature propagation across files.
- **Advanced `__all__` Export Resolution**: Evaluates literal lists, tuples, additions (`+`), `append()`, `extend()`, and `+=`, with conservative uncertainty for dynamic expressions.
- **Provenance Invalidation**: Variable reassignment (`module = None`) explicitly purges dynamic module and instance provenance.
- **Cross-Platform Debounced Watcher**: Atomic file save handling, settling windows, and temp file filtering.
- **Modular Test Suite**: 65 comprehensive unit and regression tests runnable via `reposhield test` or `python -m unittest discover -s tests`.
- **GitHub Actions CI**: Automated multi-OS matrix testing across Ubuntu, Windows, and macOS on Python 3.8 through 3.13.

## [0.3.0] - 2026-11-20
- Lexical scoping, wildcard import resolution, `src/` layout support, async method signatures.

## [0.2.2] - 2026-11-20
- Dynamic `importlib` tracking, literal `getattr()`, conditional import distinction.

## [0.2.1] - 2026-11-20
- Multi-file regression sentinel, AST module resolution, argument signature verification.

## [0.1.0] - 2026-11-19
- Initial prototype: AST dependency mapper and broken import checker.
