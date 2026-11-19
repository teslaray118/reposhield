# 🛡️ RepoShield

**AI Code Safety & Cross-File Dependency Sentinel**  
*Catch silent regressions before AI-generated code breaks your production systems.*

---

## 🚨 The Problem

Modern AI models are incredible at writing code, but they suffer from **context isolation**. When you ask an AI to update or refactor a file, it only sees what you give it. 

It rewrites that single file cleanly, but it has no map of the codebase. A function rename or missing export in `utils.py` silently breaks `billing.py`, `dashboard.py`, and `api.py`. The code compiles in isolation, but crashes in production.

## 💡 The Solution

**RepoShield** is a zero-dependency static analysis engine built on Python's Abstract Syntax Tree (`ast`). It builds a live cross-file dependency graph of your project and acts as a safety barrier between AI code and your repository:

1. **Dependency Mapping**: Automatically indexes every function, class, and cross-file import.
2. **Contract Enforcement**: Detects when an edit removes or breaks a symbol needed by downstream files.
3. **Automated AI Remediation**: Generates precise, copy-pasteable prompts to force the AI model to fix its regressions while preserving backward compatibility.
![RepoShield Live Sentinel](demo.png)

---

## 🚀 Quickstart

RepoShield uses only Python's standard library—no heavy dependencies, no complex setup.

### 1. Scan your project blueprint
```bash
python reposhield.py scan .
