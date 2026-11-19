#!/usr/bin/env python3
"""
🛡️ REPOSHIELD — AI Code Safety & Dependency Sentinel (v0.2.0)
Zero-dependency static analysis engine built on Python's Abstract Syntax Tree (ast).
Guards against silent cross-file regressions introduced by AI coding models.
"""

import ast
import os
import sys
import time
import hashlib
import argparse
import unittest
from collections import defaultdict, deque

BANNER = """
======================================================
  🛡️  REPOSHIELD — AI Code Safety & Impact Sentinel
======================================================
"""

# Common standard library names fallback for all Python versions
STDLIB_MODULES = getattr(sys, "stdlib_module_names", frozenset({
    "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii",
    "bisect", "builtins", "calendar", "cmath", "collections", "contextlib",
    "copy", "csv", "ctypes", "datetime", "decimal", "difflib", "dis",
    "email", "enum", "errno", "faulthandler", "fcntl", "fnmatch", "fractions",
    "functools", "gc", "getopt", "getpass", "gettext", "glob", "gzip",
    "hashlib", "heapq", "hmac", "html", "http", "imaplib", "inspect",
    "io", "itertools", "json", "keyword", "linecache", "locale", "logging",
    "math", "mimetypes", "mmap", "multiprocessing", "netrc", "numbers",
    "operator", "os", "pathlib", "pickle", "pkgutil", "platform", "pprint",
    "queue", "random", "re", "resource", "sched", "secrets", "select",
    "selectors", "shelve", "shutil", "signal", "site", "socket", "sqlite3",
    "ssl", "stat", "statistics", "string", "struct", "subprocess", "sys",
    "sysconfig", "tarfile", "tempfile", "termios", "textwrap", "threading",
    "time", "timeit", "traceback", "types", "typing", "unittest", "urllib",
    "uuid", "warnings", "weakref", "xml", "zipfile", "zipimport", "zlib"
}))

IGNORE_DIRS = frozenset({
    ".git", "__pycache__", "venv", ".venv", "env", ".env", "node_modules",
    ".pytest_cache", ".mypy_cache", ".tox", "build", "dist", ".idea", ".vscode"
})

IGNORE_EXTENSIONS = (
    ".pyc", ".pyo", ".pyd", ".tmp", ".swp", ".swo", "~", ".bak"
)


def compute_file_hash(filepath):
    """Compute SHA-256 of file content to detect real modifications."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def parse_function_signature(func_node):
    """Extract parameters, defaults, and counts from a FunctionDef node."""
    args = func_node.args
    pos_args = [a.arg for a in args.args]
    defaults_count = len(args.defaults)
    required_count = len(pos_args) - defaults_count

    required_args = pos_args[:required_count]
    optional_args = pos_args[required_count:]

    kwonly_args = [a.arg for a in args.kwonlyargs]
    kw_defaults = args.kw_defaults or []
    required_kwonly = [
        arg.arg for arg, default in zip(args.kwonlyargs, kw_defaults) if default is None
    ]

    return {
        "name": func_node.name,
        "line": func_node.lineno,
        "all_params": pos_args,
        "required_params": required_args,
        "optional_params": optional_args,
        "has_varargs": args.vararg is not None,
        "has_kwargs": args.kwarg is not None,
        "kwonly_params": kwonly_args,
        "required_kwonly": required_kwonly,
    }


def extract_file_info(filepath):
    """
    Extract exports, signatures, classes, imports, and calls from a Python file.
    Preserves exact backward-compatible keys: valid, error, definitions, imports.
    """
    result = {
        "valid": False,
        "error": None,
        "error_line": None,
        "definitions": set(),
        "signatures": {},
        "classes": {},
        "imports": [],
        "calls": [],
        "wildcard_imports": set(),
        "hash": None,
    }

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        result["hash"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        tree = ast.parse(content, filename=filepath)
        result["valid"] = True
    except SyntaxError as e:
        result["error"] = f"Syntax error at line {e.lineno}: {e.msg}"
        result["error_line"] = e.lineno
        return result
    except UnicodeDecodeError as e:
        result["error"] = f"Encoding error: {str(e)}"
        return result
    except Exception as e:
        result["error"] = f"Parse failure: {str(e)}"
        return result

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            result["definitions"].add(node.name)
            result["signatures"][node.name] = parse_function_signature(node)
        elif isinstance(node, ast.ClassDef):
            result["definitions"].add(node.name)
            class_methods = set()
            class_signatures = {}
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    class_methods.add(item.name)
                    class_signatures[item.name] = parse_function_signature(item)
            bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
            result["classes"][node.name] = {
                "line": node.lineno,
                "methods": class_methods,
                "signatures": class_signatures,
                "bases": bases,
            }
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result["definitions"].add(target.id)
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            result["definitions"].add(elt.id)

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            level = node.level  # 0: absolute, 1+: relative (. or ..)
            for alias in node.names:
                if alias.name == "*":
                    result["wildcard_imports"].add(mod)
                result["imports"].append({
                    "module": mod,
                    "level": level,
                    "name": alias.name,
                    "asname": alias.asname or alias.name,
                    "line": node.lineno,
                })
        elif isinstance(node, ast.Import):
            for alias in node.names:
                result["imports"].append({
                    "module": alias.name,
                    "level": 0,
                    "name": "*",
                    "asname": alias.asname or alias.name,
                    "line": node.lineno,
                })
        elif isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name:
                kw_args = [kw.arg for kw in node.keywords if kw.arg is not None]
                result["calls"].append({
                    "name": func_name,
                    "line": node.lineno,
                    "pos_count": len(node.args),
                    "kw_args": kw_args,
                })

    return result


def get_project_files(target_dir):
    """
    Enumerate all valid Python project files.
    Calculates relative path, module dotted name, mtime, and sha256.
    """
    target_dir = os.path.abspath(target_dir)
    py_files = {}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for f in files:
            if not f.endswith(".py"):
                continue
            if any(f.endswith(ext) for ext in IGNORE_EXTENSIONS) or f.startswith(".#"):
                continue
            if f == "reposhield.py":
                continue

            full_path = os.path.abspath(os.path.join(root, f))
            rel_path = os.path.relpath(full_path, target_dir).replace("\\", "/")

            parts = rel_path[:-3].split("/")
            if parts[-1] == "__init__":
                mod_name = ".".join(parts[:-1]) if len(parts) > 1 else ""
            else:
                mod_name = ".".join(parts)

            py_files[full_path] = {
                "rel_path": rel_path,
                "mod_name": mod_name,
                "base_name": os.path.splitext(f)[0],
                "mtime": os.path.getmtime(full_path),
                "is_pkg": f == "__init__.py",
            }
    return py_files


def resolve_import_target(consumer_mod, import_info, module_map):
    """
    Resolve an imported module to a project file.
    Supports absolute imports, relative imports, and flat root layout.
    """
    mod = import_info.get("module", "")
    level = import_info.get("level", 0)

    # 1. Relative import resolution
    if level > 0:
        consumer_parts = consumer_mod.split(".") if consumer_mod else []
        if len(consumer_parts) >= level:
            base_pkg = consumer_parts[:-level]
            target_parts = base_pkg + ([mod] if mod else [])
            resolved = ".".join(p for p in target_parts if p)
            if resolved in module_map:
                return module_map[resolved]
        return None

    # 2. Direct exact match in module map
    if mod in module_map:
        return module_map[mod]

    # 3. Leading package match
    mod_parts = mod.split(".")
    for i in range(len(mod_parts), 0, -1):
        candidate = ".".join(mod_parts[:i])
        if candidate in module_map:
            return module_map[candidate]

    # 4. Fallback base_name match (flat layout projects)
    target_base = mod_parts[0] if mod_parts else ""
    for path, meta in module_map.items():
        if meta.get("base_name") == target_base or meta.get("mod_name") == target_base:
            return meta

    return None


def build_dependency_graph(target_dir):
    """
    Build complete dependency graph with symbol tracking and consumers.
    Backward-compatible return signature: (file_data, consumers)
    """
    py_files = get_project_files(target_dir)
    file_data = {}
    module_map = {}

    for path, meta in py_files.items():
        info = extract_file_info(path)
        info.update(meta)
        file_data[path] = info
        if meta["mod_name"]:
            module_map[meta["mod_name"]] = info
        module_map[meta["base_name"]] = info

    consumers = defaultdict(list)

    for path, info in file_data.items():
        if not info["valid"]:
            continue
        for imp in info["imports"]:
            mod_str = imp["module"]
            root_mod = mod_str.split(".")[0] if mod_str else ""

            # Skip stdlib imports
            if imp.get("level", 0) == 0 and root_mod in STDLIB_MODULES and root_mod not in module_map:
                continue

            target_meta = resolve_import_target(info["mod_name"], imp, module_map)
            if target_meta:
                target_key = target_meta["base_name"]
                consumers[target_key].append({
                    "consumer_path": path,
                    "consumer_rel": info["rel_path"],
                    "consumer_mod": info["mod_name"],
                    "target_path": target_meta["rel_path"],
                    "name": imp["name"],
                    "asname": imp["asname"],
                    "line": imp["line"],
                    "is_wildcard": imp["name"] == "*",
                })
            else:
                if not root_mod.startswith("_") and root_mod not in STDLIB_MODULES:
                    consumers[root_mod].append({
                        "consumer_path": path,
                        "consumer_rel": info["rel_path"],
                        "consumer_mod": info["mod_name"],
                        "target_path": None,
                        "name": imp["name"],
                        "asname": imp["asname"],
                        "line": imp["line"],
                        "unresolved_module": True,
                        "is_wildcard": imp["name"] == "*",
                    })

    return file_data, dict(consumers)


def get_transitive_dependents(changed_base, consumers, file_data):
    """Find all directly and indirectly affected files using BFS."""
    direct = set()
    transitive = set()
    visited = set()
    queue = deque([changed_base])

    is_first = True
    while queue:
        curr = queue.popleft()
        if curr in visited:
            continue
        visited.add(curr)

        for dep in consumers.get(curr, []):
            consumer_rel = dep["consumer_rel"]
            consumer_base = os.path.splitext(os.path.basename(consumer_rel))[0]

            if is_first:
                direct.add(consumer_rel)
            else:
                if consumer_rel not in direct:
                    transitive.add(consumer_rel)

            if consumer_base not in visited:
                queue.append(consumer_base)
        is_first = False

    return direct, transitive


def check_project_integrity(target_dir):
    """
    Perform deep static analysis on the project.
    Detects syntax errors, missing symbols, and parameter mismatches.
    Returns: (errors, warnings, stats)
    """
    file_data, consumers = build_dependency_graph(target_dir)
    errors = []
    warnings = []
    symbol_count = 0
    dependency_count = 0

    for path, info in file_data.items():
        if not info["valid"]:
            errors.append({
                "severity": "CRITICAL",
                "type": "SYNTAX_ERROR",
                "file": info["rel_path"],
                "line": info.get("error_line", 1),
                "message": info["error"],
            })
        else:
            symbol_count += len(info["definitions"])

    for mod, user_list in consumers.items():
        matching = [p for p, d in file_data.items() if d["base_name"] == mod or d["mod_name"] == mod]
        if not matching:
            for u in user_list:
                if u.get("unresolved_module"):
                    warnings.append({
                        "severity": "WARNING",
                        "type": "EXTERNAL_OR_UNRESOLVED",
                        "file": u["consumer_rel"],
                        "line": u["line"],
                        "message": f"Module '{mod}' could not be resolved locally (external or missing package).",
                    })
            continue

        target_path = matching[0]
        target_info = file_data[target_path]
        if not target_info["valid"]:
            continue

        for u in user_list:
            dependency_count += 1
            sym = u["name"]
            if sym == "*":
                warnings.append({
                    "severity": "WARNING",
                    "type": "WILDCARD_IMPORT",
                    "file": u["consumer_rel"],
                    "line": u["line"],
                    "message": f"Wildcard import 'from {mod} import *' limits static analysis accuracy.",
                })
                continue

            if sym not in target_info["definitions"]:
                errors.append({
                    "severity": "CRITICAL",
                    "type": "BROKEN_CONTRACT",
                    "file": u["consumer_rel"],
                    "line": u["line"],
                    "target_file": target_info["rel_path"],
                    "symbol": sym,
                    "message": f"'{u['consumer_rel']}' (line {u['line']}) expects '{sym}' from '{target_info['rel_path']}', but it was REMOVED.",
                })
            else:
                consumer_info = file_data.get(u["consumer_path"])
                target_sig = target_info["signatures"].get(sym)
                if consumer_info and target_sig and not target_sig["has_varargs"] and not target_sig["has_kwargs"]:
                    for call in consumer_info.get("calls", []):
                        if call["name"] in (sym, u["asname"]):
                            pos_count = call["pos_count"]
                            req_len = len(target_sig["required_params"])
                            all_len = len(target_sig["all_params"])

                            if pos_count < req_len:
                                errors.append({
                                    "severity": "CRITICAL",
                                    "type": "SIGNATURE_MISMATCH",
                                    "file": u["consumer_rel"],
                                    "line": call["line"],
                                    "target_file": target_info["rel_path"],
                                    "symbol": sym,
                                    "message": f"Call to '{sym}()' in '{u['consumer_rel']}' passes {pos_count} args, but definition in '{target_info['rel_path']}' requires at least {req_len}: ({', '.join(target_sig['required_params'])}).",
                                })
                            elif pos_count > all_len:
                                errors.append({
                                    "severity": "CRITICAL",
                                    "type": "SIGNATURE_MISMATCH",
                                    "file": u["consumer_rel"],
                                    "line": call["line"],
                                    "target_file": target_info["rel_path"],
                                    "symbol": sym,
                                    "message": f"Call to '{sym}()' in '{u['consumer_rel']}' passes {pos_count} args, but definition accepts at most {all_len}.",
                                })

    stats = {
        "files_scanned": len(file_data),
        "symbols_indexed": symbol_count,
        "dependencies_mapped": dependency_count,
        "critical_errors": len([e for e in errors if e["severity"] == "CRITICAL"]),
        "warnings": len(warnings),
    }

    return errors, warnings, stats


def generate_ai_remediation_prompt(changed_file, broken_items, direct_deps, transitive_deps=None):
    """Generate concise, actionable prompts for AI models to fix regressions."""
    symbols = sorted(list(set(b.get("symbol") for b in broken_items if b.get("symbol"))))
    direct_str = ", ".join(sorted(direct_deps)) if direct_deps else "downstream files"
    transitive_str = f" (transitive impact: {', '.join(sorted(transitive_deps))})" if transitive_deps else ""

    prompt = (
        f'🚨 REGRESSION ALERT for `{changed_file}`:\n'
        f'Your recent update broke backward compatibility with existing files: {direct_str}{transitive_str}.\n\n'
        f'Required fixes:\n'
    )
    for sym in symbols:
        prompt += f'- Preserve or restore public symbol: `{sym}`\n'
    for b in broken_items:
        if b.get("type") == "SIGNATURE_MISMATCH":
            prompt += f'- Signature conflict: {b["message"]}\n'
        elif b.get("type") == "SYNTAX_ERROR":
            prompt += f'- Syntax error at line {b.get("line")}: {b.get("message")}\n'

    prompt += (
        f'\nPlease update `{changed_file}` to preserve these contracts while retaining any new functionality.'
    )
    return prompt


def run_scan(target_dir):
    print(f"\n📂 Scanning project at: {os.path.abspath(target_dir)}")
    file_data, consumers = build_dependency_graph(target_dir)

    print(f"📄 Found {len(file_data)} Python source files.\n")
    print("📦 EXPORTED DEFINITIONS:")
    for path, info in sorted(file_data.items(), key=lambda x: x[1]["rel_path"]):
        if not info["valid"]:
            print(f"  • {info['rel_path']}: ⚠️ {info['error']}")
            continue
        defs = sorted(list(info["definitions"]))
        preview = ", ".join(defs[:8]) + (" ..." if len(defs) > 8 else "")
        print(f"  • {info['rel_path']}: {preview if preview else '(no exports)'}")

    print("\n🔗 CROSS-FILE DEPENDENCIES:")
    has_dep = False
    for mod, user_list in consumers.items():
        matching = [p for p, d in file_data.items() if d["base_name"] == mod or d["mod_name"] == mod]
        if matching:
            has_dep = True
            for u in user_list:
                sym_desc = f"'{u['name']}'" if u["name"] != "*" else "all symbols (*)"
                print(f"  • {u['consumer_rel']} (line {u['line']}) imports {sym_desc} from '{matching[0].split(os.sep)[-1]}'")
    if not has_dep:
        print("  • No internal cross-file dependencies found.")

    errors, warnings, stats = check_project_integrity(target_dir)
    print("\n📊 SUMMARY STATS:")
    print(f"  • Source files scanned:   {stats['files_scanned']}")
    print(f"  • Exported definitions:   {stats['symbols_indexed']}")
    print(f"  • Dependencies mapped:    {stats['dependencies_mapped']}")
    print(f"  • Critical errors:        {stats['critical_errors']}")
    print(f"  • Advisory warnings:      {stats['warnings']}")
    print("\n✅ Scan complete.")
    return stats


def run_check(target_dir):
    print(f"\n🔍 Checking integrity of project at: {os.path.abspath(target_dir)}")
    errors, warnings, stats = check_project_integrity(target_dir)

    if warnings:
        print("\n⚠️  ADVISORY WARNINGS:")
        for w in warnings:
            print(f"  • [{w['type']}] {w['file']} (line {w['line']}): {w['message']}")

    if errors:
        print("\n🚨 CRITICAL REGRESSIONS DETECTED:")
        for err in errors:
            print(f"  • [{err['type']}] {err['file']} (line {err['line']}): {err['message']}")

        print(f"\n❌ FAILED: {len(errors)} critical issues detected.")
        return False

    print(f"\n🎉 ALL DEPENDENCIES CONNECTED & HEALTHY!")
    print(f"   ({stats['files_scanned']} files scanned, {stats['dependencies_mapped']} dependency contracts verified)")
    return True


def run_watch(target_dir):
    print(BANNER)
    print(f"👀 RepoShield Sentinel v0.2.0 is watching: {os.path.abspath(target_dir)}")
    print("👉 Edit & save files. RepoShield will alert you if an AI code change breaks downstream code.\n")
    print("Press Ctrl+C to stop.\n" + "-" * 54)

    file_hashes = {}
    py_files = get_project_files(target_dir)
    for p in py_files:
        file_hashes[p] = compute_file_hash(p)

    while True:
        try:
            time.sleep(0.8)
            current_files = get_project_files(target_dir)
            current_paths = set(current_files.keys())
            previous_paths = set(file_hashes.keys())

            deleted = previous_paths - current_paths
            added = current_paths - previous_paths

            changed_path = None
            for p in current_paths:
                new_hash = compute_file_hash(p)
                if p not in file_hashes or new_hash != file_hashes[p]:
                    changed_path = p
                    file_hashes[p] = new_hash
                    break

            for p in deleted:
                del file_hashes[p]

            if deleted:
                for del_p in deleted:
                    curr_time = time.strftime('%H:%M:%S')
                    del_rel = os.path.relpath(del_p, target_dir)
                    print(f"\n[{curr_time}] 🗑️  File deleted: {del_rel}")
                    run_check(target_dir)
                continue

            if added:
                for add_p in added:
                    file_hashes[add_p] = compute_file_hash(add_p)

            if changed_path:
                rel = os.path.relpath(changed_path, target_dir)
                curr_time = time.strftime('%H:%M:%S')
                print(f"\n[{curr_time}] 💾 File change detected: {rel}")

                file_data, consumers = build_dependency_graph(target_dir)
                errors, warnings, stats = check_project_integrity(target_dir)

                target_info = file_data.get(changed_path)
                changed_base = os.path.splitext(os.path.basename(changed_path))[0]
                direct_deps, transitive_deps = get_transitive_dependents(changed_base, consumers, file_data)

                relevant_errors = [
                    e for e in errors
                    if e.get("file") == rel or e.get("target_file") == rel
                ]

                if relevant_errors:
                    print(f"🚨 REGRESSION DETECTED: Changes in '{rel}' introduced breaking issues!")
                    for err in relevant_errors:
                        print(f"💥 CASUALTY: {err['message']}")

                    if direct_deps:
                        print(f"👥 DIRECT DEPENDENTS: {', '.join(sorted(direct_deps))}")
                    if transitive_deps:
                        print(f"🌊 TRANSITIVE IMPACT: {', '.join(sorted(transitive_deps))}")

                    prompt = generate_ai_remediation_prompt(
                        rel, relevant_errors, direct_deps, transitive_deps
                    )
                    print("\n👉 COPY & SEND THIS REMEDIATION PROMPT TO THE AI:")
                    print("-" * 54)
                    print(prompt)
                    print("-" * 54 + "\n")
                else:
                    print(f"✅ Safe save: '{rel}' intact, all cross-file dependencies satisfied.")

        except KeyboardInterrupt:
            print("\n👋 RepoShield Sentinel stopped.")
            sys.exit(0)


# ==========================================
# 🧪 BUILT-IN AUTOMATED TEST SUITE
# ==========================================

class TestRepoShieldEngine(unittest.TestCase):
    """Test suite validating all RepoShield static analysis capabilities."""

    def setUp(self):
        import tempfile
        self.test_dir = tempfile.TemporaryDirectory()
        self.root = self.test_dir.name

    def tearDown(self):
        self.test_dir.cleanup()

    def test_water_distribution_baseline(self):
        """Verify backward compatibility on the original water distribution demo."""
        pipes_code = """
def supply_water(household_id, liters):
    return f"Supplying {liters}L"

def deliver_water(household_id, volume_liters, pressure_psi=0.0):
    return f"Delivering {volume_liters}L at {pressure_psi} PSI"
"""
        village_code = """
from pipes import supply_water
print(supply_water(1, 50))
"""
        school_code = """
from pipes import deliver_water
print(deliver_water("Dorms", 500, 45.0))
"""
        with open(os.path.join(self.root, "pipes.py"), "w") as f:
            f.write(pipes_code)
        with open(os.path.join(self.root, "village.py"), "w") as f:
            f.write(village_code)
        with open(os.path.join(self.root, "school.py"), "w") as f:
            f.write(school_code)

        errors, warnings, stats = check_project_integrity(self.root)
        self.assertEqual(len(errors), 0, "Water demo should pass with 0 errors")
        self.assertEqual(stats["files_scanned"], 3)
        self.assertEqual(stats["dependencies_mapped"], 2)

    def test_detect_missing_import_symbol(self):
        """Verify detection when an imported function is removed."""
        with open(os.path.join(self.root, "pipes.py"), "w") as f:
            f.write("def supply_water(h, l): pass\n")
        with open(os.path.join(self.root, "school.py"), "w") as f:
            f.write("from pipes import deliver_water\n")

        errors, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(e["type"] == "BROKEN_CONTRACT" for e in errors))

    def test_detect_syntax_error(self):
        """Verify detection of syntax errors."""
        with open(os.path.join(self.root, "broken.py"), "w") as f:
            f.write("def bad_syntax(:\n")

        errors, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(e["type"] == "SYNTAX_ERROR" for e in errors))

    def test_signature_parameter_mismatch(self):
        """Verify detection when caller passes too few arguments for required parameters."""
        with open(os.path.join(self.root, "pipes.py"), "w") as f:
            f.write("def deliver(house, liters, pressure): pass\n")
        with open(os.path.join(self.root, "caller.py"), "w") as f:
            f.write("from pipes import deliver\ndeliver(1)\n")

        errors, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(e["type"] == "SIGNATURE_MISMATCH" for e in errors))

    def test_circular_imports_resilience(self):
        """Verify circular imports do not crash analysis or BFS impact traversal."""
        with open(os.path.join(self.root, "mod_a.py"), "w") as f:
            f.write("import mod_b\ndef func_a(): pass\n")
        with open(os.path.join(self.root, "mod_b.py"), "w") as f:
            f.write("import mod_a\ndef func_b(): pass\n")

        errors, warnings, stats = check_project_integrity(self.root)
        self.assertEqual(len(errors), 0)

    def test_nested_packages_and_relative_imports(self):
        """Verify package resolution and relative imports."""
        pkg_dir = os.path.join(self.root, "pkg")
        os.makedirs(pkg_dir)
        with open(os.path.join(pkg_dir, "__init__.py"), "w") as f:
            f.write("from .util import helper\n")
        with open(os.path.join(pkg_dir, "util.py"), "w") as f:
            f.write("def helper(): pass\n")

        errors, _, stats = check_project_integrity(self.root)
        self.assertEqual(len(errors), 0)


def run_tests():
    print(BANNER)
    print("🧪 Running RepoShield Automated Test Suite (unittest)...")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRepoShieldEngine)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


def main():
    parser = argparse.ArgumentParser(description="RepoShield — AI Code Safety & Dependency Sentinel")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    p_scan = subparsers.add_parser("scan", help="Scan repository and map dependencies")
    p_scan.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current directory)")

    p_check = subparsers.add_parser("check", help="Check for syntax or broken import regressions")
    p_check.add_argument("path", nargs="?", default=".", help="Directory to check (default: current directory)")

    p_watch = subparsers.add_parser("watch", help="Watch project live on save")
    p_watch.add_argument("path", nargs="?", default=".", help="Directory to watch (default: current directory)")

    p_test = subparsers.add_parser("test", help="Run automated test suite")

    args = parser.parse_args()

    target = getattr(args, "path", ".")
    if args.command == "scan":
        run_scan(target)
    elif args.command == "check":
        healthy = run_check(target)
        sys.exit(0 if healthy else 1)
    elif args.command == "watch":
        run_watch(target)
    elif args.command == "test":
        success = run_tests()
        sys.exit(0 if success else 1)
    else:
        run_scan(target)
        healthy = run_check(target)
        sys.exit(0 if healthy else 1)


if __name__ == "__main__":
    main()
