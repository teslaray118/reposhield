#!/usr/bin/env python3
"""
🛡️ REPOSHIELD — AI Code Safety & Dependency Sentinel (v0.2.1)
Zero-dependency static analysis engine built on Python's Abstract Syntax Tree (ast).
Guards against silent cross-file regressions introduced by AI coding models.
"""

import argparse
import ast
import hashlib
import os
import sys
import time
from collections import defaultdict, deque

BANNER = """
======================================================
  🛡️  REPOSHIELD — AI Code Safety & Impact Sentinel
======================================================
"""

IGNORE_DIRS = frozenset({
    ".git", "__pycache__", "venv", ".venv", "env", ".env", "node_modules",
    ".pytest_cache", ".mypy_cache", ".tox", "build", "dist", ".idea", ".vscode"
})

IGNORE_EXTENSIONS = (
    ".pyc", ".pyo", ".pyd", ".tmp", ".swp", ".swo", "~", ".bak"
)

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


def compute_file_hash(filepath):
    """Compute SHA-256 of file content to detect real modifications."""
    try:
        with open(filepath, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (OSError, PermissionError):
        return None


def parse_function_signature(func_node):
    """Extract parameters, defaults, and argument types from a FunctionDef node."""
    args = func_node.args
    posonly = [a.arg for a in getattr(args, "posonlyargs", [])]
    pos = [a.arg for a in args.args]
    positional = posonly + pos
    defaults = args.defaults or []
    required_count = len(positional) - len(defaults)
    required_pos = positional[:required_count]
    optional_pos = positional[required_count:]

    kwonly = [a.arg for a in args.kwonlyargs]
    kw_defaults = args.kw_defaults or []
    required_kw = [
        arg.arg for arg, d in zip(args.kwonlyargs, kw_defaults) if d is None
    ]
    optional_kw = [
        arg.arg for arg, d in zip(args.kwonlyargs, kw_defaults) if d is not None
    ]

    return {
        "name": func_node.name,
        "line": func_node.lineno,
        "posonly_args": posonly,
        "pos_args": pos,
        "all_pos": positional,
        "all_params": pos,  # backward compatibility
        "required_params": [p for p in required_pos if p in pos],
        "optional_params": [p for p in optional_pos if p in pos],
        "required_pos": required_pos,
        "optional_pos": optional_pos,
        "kwonly_params": kwonly,
        "required_kwonly": required_kw,
        "optional_kwonly": optional_kw,
        "has_varargs": args.vararg is not None,
        "vararg": args.vararg.arg if args.vararg else None,
        "has_kwargs": args.kwarg is not None,
        "kwarg": args.kwarg.arg if args.kwarg else None,
    }


class _InfoVisitor(ast.NodeVisitor):
    def __init__(self, result):
        self.r = result
        self.module_aliases = {}
        self.symbol_aliases = {}
        self.scope = []

    def visit_FunctionDef(self, node):
        if not self.scope:
            self.r["definitions"].add(node.name)
            self.r["signatures"][node.name] = parse_function_signature(node)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        if not self.scope:
            self.r["definitions"].add(node.name)
            methods, signatures = set(), {}
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods.add(item.name)
                    signatures[item.name] = parse_function_signature(item)
            bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
            self.r["classes"][node.name] = {
                "line": node.lineno,
                "methods": methods,
                "signatures": signatures,
                "bases": bases,
            }
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Assign(self, node):
        if not self.scope:
            for t in node.targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        self.r["definitions"].add(n.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if not self.scope and isinstance(node.target, ast.Name):
            self.r["definitions"].add(node.target.id)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.module_aliases[local] = alias.name if alias.asname else alias.name.split(".")[0]
            self.r["imports"].append({
                "type": "module",
                "module": alias.name,
                "level": 0,
                "name": None,
                "asname": local,
                "line": node.lineno,
            })

    def visit_ImportFrom(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if not self.scope and alias.name != "*":
                self.r["definitions"].add(local)
            item = {
                "type": "from",
                "module": node.module or "",
                "level": node.level,
                "name": alias.name,
                "asname": local,
                "line": node.lineno,
            }
            self.r["imports"].append(item)
            if alias.name == "*":
                self.r["wildcard_imports"].add(node.module or "")
            else:
                self.symbol_aliases[local] = (node.module or "", alias.name, node.level)

    def _dotted(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            p = self._dotted(node.value)
            return p + "." + node.attr if p else None
        return None

    def visit_Call(self, node):
        dotted = self._dotted(node.func)
        local_name = node.func.id if isinstance(node.func, ast.Name) else None
        target = None

        if local_name and local_name in self.symbol_aliases:
            mod, sym, level = self.symbol_aliases[local_name]
            target = {
                "kind": "symbol",
                "module": mod,
                "symbol": sym,
                "level": level,
                "local": local_name,
            }
        elif dotted:
            first, _, tail = dotted.partition(".")
            if first in self.module_aliases and tail:
                target = {
                    "kind": "module",
                    "module": self.module_aliases[first],
                    "symbol": tail,
                    "level": 0,
                    "local": first,
                }
            elif local_name and local_name in self.symbol_aliases:
                mod, sym, level = self.symbol_aliases[local_name]
                target = {
                    "kind": "symbol",
                    "module": mod,
                    "symbol": sym,
                    "level": level,
                    "local": local_name,
                }

        if target:
            pos_args = [x for x in node.args if not isinstance(x, ast.Starred)]
            has_star = any(isinstance(x, ast.Starred) for x in node.args)
            keywords = [k.arg for k in node.keywords]
            has_double_star = any(k.arg is None for k in node.keywords)

            self.r["calls"].append({
                "target": target,
                "name": target["symbol"],
                "line": node.lineno,
                "pos_count": len(pos_args),
                "has_star_args": has_star,
                "keywords": keywords,
                "has_double_star": has_double_star,
            })
        self.generic_visit(node)


def extract_file_info(filepath):
    """
    Extract exports, signatures, classes, imports, and calls from a Python file.
    Preserves backward-compatible return dictionary keys.
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
        _InfoVisitor(result).visit(tree)
    except SyntaxError as e:
        result["error"] = f"Syntax error at line {e.lineno}: {e.msg}"
        result["error_line"] = e.lineno
    except (OSError, UnicodeError) as e:
        result["error"] = f"Could not read file: {e}"
    except Exception as e:
        result["error"] = f"Parse failure: {e}"
    return result


def get_project_files(target_dir):
    """Enumerate valid Python source files excluding virtualenvs and cache dirs."""
    target_dir = os.path.abspath(target_dir)
    found = {}
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS and not d.startswith("."))
        for name in sorted(files):
            if not name.endswith(".py") or name.startswith(".#") or name.endswith(IGNORE_EXTENSIONS):
                continue
            path = os.path.abspath(os.path.join(root, name))
            rel = os.path.relpath(path, target_dir).replace(os.sep, "/")
            parts = rel[:-3].split("/")
            module_parts = parts[:-1] if parts[-1] == "__init__" else parts
            mod = ".".join(module_parts)
            found[path] = {
                "rel_path": rel,
                "mod_name": mod,
                "module_id": mod or "__root__",
                "base_name": "__init__" if name == "__init__.py" else name[:-3],
                "mtime": os.path.getmtime(path),
                "is_pkg": name == "__init__.py",
            }
    return found


def _module_index(module_map):
    index = defaultdict(list)
    for key, val in module_map.items():
        vals = val if isinstance(val, list) else [val]
        for item in vals:
            if not isinstance(item, dict):
                continue
            mod = item.get("module_id", item.get("mod_name", key))
            if item not in index[mod]:
                index[mod].append(item)
    return index


def _consumer_package(consumer_mod, module_map):
    idx = _module_index(module_map)
    for mod, vals in idx.items():
        if any(v.get("mod_name") == consumer_mod or v.get("module_id") == consumer_mod for v in vals):
            return mod.rpartition(".")[0]
    return consumer_mod.rpartition(".")[0]


def resolve_import_target(consumer_mod, import_info, module_map):
    """
    Resolve an imported module to a project file record.
    Unresolved or ambiguous cases return None.
    """
    idx = _module_index(module_map)
    mod = import_info.get("module", "") or ""
    level = import_info.get("level", 0)

    if level:
        pkg = _consumer_package(consumer_mod, module_map)
        parts = pkg.split(".") if pkg else []
        if level - 1 > len(parts):
            return None
        base = parts[:len(parts) - (level - 1)] if level > 1 else parts
        full = ".".join(base + ([mod] if mod else []))
    else:
        full = mod

    if full:
        exact = idx.get(full, [])
        if len(exact) == 1:
            return exact[0]
        if len(exact) > 1:
            return None

    name = import_info.get("name")
    if name and name != "*":
        candidate = (full + "." + name).strip(".")
        matches = idx.get(candidate, [])
        if len(matches) == 1:
            return matches[0]

    return None


def build_dependency_graph(target_dir):
    """
    Build dependency graph tracking imported symbols and consumers.
    Returns: (file_data, consumers)
    """
    py_files = get_project_files(target_dir)
    file_data = {}
    module_candidates = defaultdict(list)

    for path, meta in py_files.items():
        info = extract_file_info(path)
        info.update(meta)
        file_data[path] = info
        module_candidates[meta["module_id"]].append(info)

    module_map = {
        m: (vals[0] if len(vals) == 1 else vals)
        for m, vals in module_candidates.items()
    }
    consumers = defaultdict(list)

    for path, info in file_data.items():
        if not info["valid"]:
            continue
        for imp in info["imports"]:
            target = None
            if imp.get("type") == "from" and imp.get("name") not in (None, "*"):
                base_target = resolve_import_target(
                    info["module_id"],
                    {"module": imp.get("module", ""), "level": imp.get("level", 0), "name": None},
                    module_map
                )
                if base_target:
                    candidate_id = (base_target.get("module_id", "") + "." + imp["name"]).strip(".")
                    candidate = module_candidates.get(candidate_id, [])
                    if len(candidate) == 1:
                        target = candidate[0]
                        imp = dict(imp, name="*module*")

            if target is None:
                target = resolve_import_target(info["module_id"], imp, module_map)

            rec = {
                "consumer_path": path,
                "consumer_rel": info["rel_path"],
                "consumer_mod": info["module_id"],
                "target_path": target.get("rel_path") if target else None,
                "target_module": target.get("module_id") if target else None,
                "name": imp.get("name"),
                "asname": imp.get("asname"),
                "line": imp.get("line"),
                "level": imp.get("level", 0),
                "module": imp.get("module", ""),
                "import_type": imp.get("type", "from"),
                "is_wildcard": imp.get("name") == "*",
            }

            if imp.get("type") == "module":
                requested = imp["module"] if imp.get("asname") != imp["module"].split(".")[0] else imp["module"].split(".")[0]
                candidates = _module_index(module_map).get(requested, [])
                target = candidates[0] if len(candidates) == 1 else None
                rec.update(
                    target_path=target.get("rel_path") if target else None,
                    target_module=target.get("module_id") if target else None,
                    name="*",
                    imported_module=imp["module"],
                    asname=imp["asname"],
                )

            if target:
                consumers[target["module_id"]].append(rec)
            else:
                root = imp.get("module", "").split(".")[0]
                if root and root not in STDLIB_MODULES:
                    rec["unresolved_module"] = True
                    consumers["?" + imp.get("module", "")].append(rec)

    return file_data, dict(consumers)


def _find_file_by_identifier(identifier, file_data):
    if identifier in file_data:
        return identifier
    matches = [
        p for p, d in file_data.items()
        if identifier in (d.get("module_id"), d.get("mod_name"), d.get("base_name"))
    ]
    return matches[0] if len(matches) == 1 else None


def get_transitive_dependents(changed_base, consumers, file_data):
    """Find all direct and indirect downstream dependents using BFS traversal."""
    start_file = _find_file_by_identifier(changed_base, file_data)
    start_mod = file_data[start_file].get("module_id") if start_file else changed_base
    direct, transitive = set(), set()
    seen_mods = {start_mod}
    queue = deque([(start_mod, 0)])

    while queue:
        current, depth = queue.popleft()
        for rec in consumers.get(current, []):
            rel = rec.get("consumer_rel")
            if not rel:
                continue
            (direct if depth == 0 else transitive).add(rel)
            consumer = file_data.get(rec.get("consumer_path"))
            cm = consumer.get("module_id") if consumer else rec.get("consumer_mod")
            if cm and cm not in seen_mods:
                seen_mods.add(cm)
                queue.append((cm, depth + 1))

    transitive.difference_update(direct)
    return direct, transitive


def _call_error(sig, call):
    name = sig["name"]
    args = call["pos_count"]
    kws = [x for x in call["keywords"] if x is not None]
    posonly = set(sig["posonly_args"])
    posnames = sig["all_pos"]

    if not call["has_star_args"] and not sig["has_varargs"] and args > len(posnames):
        return f"Too many positional arguments for {name}(): accepts at most {len(posnames)}, got {args}."

    filled = set(posnames[:args])
    if len(kws) != len(set(kws)):
        return f"Duplicate keyword argument in call to {name}()."

    for kw in kws:
        if kw in posonly:
            return f"Positional-only parameter '{kw}' passed by keyword to {name}()."
        if kw in filled:
            return f"Multiple values for parameter '{kw}' in call to {name}()."
        if not sig["has_kwargs"] and kw not in sig["pos_args"] and kw not in sig["kwonly_params"]:
            return f"Unexpected keyword argument '{kw}' for {name}()."

    if not call["has_double_star"]:
        required_pos = [] if call["has_star_args"] else sig["required_pos"]
        for p in required_pos:
            if p not in filled and p not in kws:
                return f"Missing required argument '{p}' for {name}()."
        for p in sig["required_kwonly"]:
            if p not in kws:
                return f"Missing required keyword-only argument '{p}' for {name}()."

    return None


def check_project_integrity(target_dir):
    """
    Perform deep static analysis across the repository.
    Detects syntax errors, missing exports, and argument signature mismatches.
    Returns: (errors, warnings, stats)
    """
    file_data, consumers = build_dependency_graph(target_dir)
    errors, warnings, seen = [], [], set()

    for path, info in file_data.items():
        if not info["valid"]:
            errors.append({
                "severity": "CRITICAL",
                "type": "SYNTAX_ERROR",
                "file": info["rel_path"],
                "line": info.get("error_line") or 1,
                "message": info["error"],
            })

    by_rel = {d["rel_path"]: d for d in file_data.values()}

    for _, records in consumers.items():
        for rec in records:
            if rec.get("unresolved_module"):
                warnings.append({
                    "severity": "WARNING",
                    "type": "UNRESOLVED_IMPORT",
                    "file": rec["consumer_rel"],
                    "line": rec["line"],
                    "message": f"Could not resolve '{rec.get('module', rec.get('imported_module', '?'))}' locally; may be external, dynamic, or ambiguous.",
                })
                continue

            target = by_rel.get(rec.get("target_path"))
            if not target or not target.get("valid"):
                continue

            sym = rec.get("name")
            if rec.get("import_type") == "module" or sym in (None, "*", "*module*"):
                continue

            if sym not in target["definitions"]:
                key = (rec["consumer_rel"], rec["line"], target["rel_path"], sym)
                if key not in seen:
                    seen.add(key)
                    errors.append({
                        "severity": "CRITICAL",
                        "type": "BROKEN_CONTRACT",
                        "file": rec["consumer_rel"],
                        "line": rec["line"],
                        "target_file": target["rel_path"],
                        "symbol": sym,
                        "message": f"'{rec['consumer_rel']}' imports '{sym}' from '{target['rel_path']}', but that symbol is not defined there.",
                    })
                continue

            sig = target["signatures"].get(sym)
            if not sig:
                continue

            consumer = file_data.get(rec.get("consumer_path"))
            if not consumer:
                continue

            for call in consumer["calls"]:
                target_ref = call.get("target") or {}
                if target_ref.get("symbol") != sym:
                    continue

                call_target = resolve_import_target(
                    consumer.get("module_id"),
                    {"module": target_ref.get("module", ""), "level": target_ref.get("level", 0), "name": sym},
                    {d["module_id"]: d for d in file_data.values()}
                )
                if not call_target or call_target.get("rel_path") != target.get("rel_path"):
                    continue

                msg = _call_error(sig, call)
                if msg:
                    key = (consumer["rel_path"], call["line"], msg)
                    if key not in seen:
                        seen.add(key)
                        errors.append({
                            "severity": "CRITICAL",
                            "type": "SIGNATURE_MISMATCH",
                            "file": consumer["rel_path"],
                            "line": call["line"],
                            "target_file": target["rel_path"],
                            "symbol": sym,
                            "message": msg,
                        })

    stats = {
        "files_scanned": len(file_data),
        "symbols_indexed": sum(len(d["definitions"]) for d in file_data.values()),
        "dependencies_mapped": sum(len(v) for k, v in consumers.items() if not k.startswith("?")),
        "critical_errors": len(errors),
        "warnings": len(warnings),
    }
    return errors, warnings, stats


def generate_ai_remediation_prompt(changed_file, broken_items, direct_deps, transitive_deps=None):
    """Generate concise, actionable prompts for AI models to fix regressions."""
    symbols = sorted({b.get("symbol") for b in broken_items if b.get("symbol")})
    prompt = [
        f"RepoShield found potential regressions after changes to `{changed_file}`.",
        "Please make the smallest corrective change that preserves existing public interfaces and backward compatibility. Do not rewrite unrelated code.",
        "Review these diagnostics and affected files:",
    ]
    prompt.extend(
        f"- {b.get('type', 'ISSUE')} at {b.get('file', changed_file)}:{b.get('line', '?')}: {b.get('message', 'No details')}"
        for b in broken_items
    )
    if symbols:
        prompt.append("Required symbols to preserve or restore: " + ", ".join(f"`{s}`" for s in symbols))
    if direct_deps:
        prompt.append("Directly affected files: " + ", ".join(sorted(direct_deps)))
    if transitive_deps:
        prompt.append("Potentially affected downstream files: " + ", ".join(sorted(transitive_deps)))
    prompt.append("Treat uncertain static-analysis findings cautiously, keep any requested new functionality, and explain the exact fix.")
    return "\n".join(prompt)


def run_scan(target_dir):
    print(f"\n📂 Scanning project at: {os.path.abspath(target_dir)}")
    file_data, consumers = build_dependency_graph(target_dir)
    print(f"📄 Found {len(file_data)} Python source files.\n📦 PROJECT MODULES:")
    for path, info in sorted(file_data.items(), key=lambda x: x[1]["rel_path"]):
        print(f"  • {info['rel_path']} [{info['module_id']}]: " + (", ".join(sorted(info["definitions"])[:8]) or "(no exports)"))
        if not info["valid"]:
            print(f"    ⚠️ {info['error']}")

    print("\n🔗 CROSS-FILE DEPENDENCIES:")
    for module, records in sorted(consumers.items()):
        for rec in records:
            if rec.get("target_path"):
                label = rec.get("name") or rec.get("imported_module") or "module"
                print(f"  • {rec['consumer_rel']}:{rec['line']} -> {label} from {rec['target_path']}")
            elif rec.get("unresolved_module"):
                print(f"  • ⚠️ Unresolved/ambiguous: {rec['consumer_rel']}:{rec['line']} imports {rec.get('module', '?')}")

    errors, warnings, stats = check_project_integrity(target_dir)
    print(f"\n📊 SUMMARY: {stats['files_scanned']} files, {stats['dependencies_mapped']} dependencies, {len(errors)} errors, {len(warnings)} warnings")
    return stats


def run_check(target_dir):
    print(f"\n🔍 Checking project: {os.path.abspath(target_dir)}")
    errors, warnings, stats = check_project_integrity(target_dir)
    for w in warnings:
        print(f"⚠️ WARNING {w['file']}:{w['line']}: {w['message']}")
    for e in errors:
        print(f"🚨 ERROR {e['file']}:{e['line']}: {e['message']}")
    print(f"\n{'❌ Issues found' if errors else '✅ No confirmed issues found'} ({stats['files_scanned']} files, {stats['dependencies_mapped']} dependencies)")
    return not errors


def run_watch(target_dir):
    root = os.path.abspath(target_dir)
    print(BANNER)
    print(f"👀 Watching {root}. Press Ctrl+C to stop.")
    previous = {p: compute_file_hash(p) for p in get_project_files(root)}
    previous_data, previous_consumers = build_dependency_graph(root)

    try:
        while True:
            time.sleep(0.6)
            current_files = get_project_files(root)
            current = {p: compute_file_hash(p) for p in current_files}
            deleted = set(previous) - set(current)
            added = set(current) - set(previous)
            changed = {p for p in set(current) & set(previous) if current[p] != previous[p]}

            if added or deleted or changed:
                file_data, consumers = build_dependency_graph(root)
                for p in sorted(deleted):
                    rel = os.path.relpath(p, root).replace(os.sep, "/")
                    mod = os.path.splitext(rel)[0].replace("/", ".")
                    if mod.endswith(".__init__"):
                        mod = mod[:-9]
                    old_meta = previous_data.get(p)
                    old_mod = old_meta.get("module_id") if old_meta else mod
                    direct, transitive = get_transitive_dependents(old_mod, previous_consumers, previous_data)
                    print(f"\n🗑️ DELETED: {rel}")
                    if direct or transitive:
                        print("Potential consumers: " + ", ".join(sorted(direct | transitive)))
                        prompt = generate_ai_remediation_prompt(
                            rel,
                            [{"type": "DELETED_DEPENDENCY", "file": rel, "line": "?", "message": "The dependency file was deleted; imports targeting it may no longer resolve."}],
                            direct,
                            transitive
                        )
                        print("\n👉 COPY & SEND THIS PROMPT TO YOUR AI:\n" + prompt)
                    else:
                        run_check(root)

                for p in sorted(added | changed):
                    rel = os.path.relpath(p, root).replace(os.sep, "/")
                    print(f"\n💾 FILE {'ADDED' if p in added else 'CHANGED'}: {rel}")
                    errors, warnings, stats = check_project_integrity(root)
                    rel_errors = [e for e in errors if e.get("file") == rel or e.get("target_file") == rel]
                    if rel_errors:
                        module = current_files[p].get("module_id")
                        direct, transitive = get_transitive_dependents(module, consumers, file_data)
                        for e in rel_errors:
                            print(f"🚨 {e['file']}:{e['line']}: {e['message']}")
                        print("\n👉 COPY & SEND THIS PROMPT TO YOUR AI:\n" + generate_ai_remediation_prompt(rel, rel_errors, direct, transitive))
                    else:
                        print("✅ No confirmed broken connection detected.")

            previous = current
            previous_data, previous_consumers = build_dependency_graph(root)
    except KeyboardInterrupt:
        print("\n👋 RepoShield stopped.")


def run_tests():
    import unittest
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestRepoShieldEngine)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


class TestRepoShieldEngine(__import__('unittest').TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, content):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_water_distribution_baseline(self):
        self.write("pipes.py", "def supply_water(household_id, liters): pass\ndef deliver_water(household_id, volume_liters, pressure_psi=0): pass\n")
        self.write("school.py", "from pipes import deliver_water\ndeliver_water('Dorms', 500, pressure_psi=45)\n")
        self.write("village.py", "from pipes import supply_water\nsupply_water(1, 50)\n")
        e, _, s = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertEqual(s['dependencies_mapped'], 2)

    def test_missing_symbol(self):
        self.write("pipes.py", "def okay(): pass\n")
        self.write("use.py", "from pipes import missing\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(x['type'] == 'BROKEN_CONTRACT' for x in e))

    def test_syntax_error(self):
        self.write("bad.py", "def broken(:\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(x['type'] == 'SYNTAX_ERROR' for x in e))

    def test_keyword_arguments_and_defaults(self):
        self.write("api.py", "def f(a, b=2, *, c, d=4): pass\n")
        self.write("ok.py", "from api import f\nf(1, c=3)\nf(a=1, c=3, d=4)\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_invalid_keyword_and_missing_required(self):
        self.write("api.py", "def f(a, *, c): pass\n")
        self.write("bad.py", "from api import f\nf(a=1, wrong=2)\nf(1)\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertGreaterEqual(len(e), 2)

    def test_varargs_kwargs(self):
        self.write("api.py", "def f(a, *args, **kwargs): pass\n")
        self.write("use.py", "from api import f\nf(1, 2, 3, any=4)\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_duplicate_filenames(self):
        self.write("a/pipes.py", "def one(): pass\n")
        self.write("b/pipes.py", "def two(): pass\n")
        self.write("a/use.py", "from a.pipes import one\none()\n")
        self.write("b/use.py", "from b.pipes import two\ntwo()\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_from_package_import_submodule(self):
        self.write("pkg/__init__.py", "")
        self.write("pkg/child.py", "def f(): pass\n")
        self.write("use.py", "from pkg import child\nchild.f()\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_nested_and_relative_init(self):
        self.write("pkg/__init__.py", "from .sub.mod import helper\n")
        self.write("pkg/sub/__init__.py", "")
        self.write("pkg/sub/mod.py", "def helper(): pass\n")
        self.write("pkg/use.py", "from . import helper\nhelper()\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_alias_module_and_function_calls(self):
        self.write("api.py", "def f(x, *, y): pass\n")
        self.write("use.py", "import api as a\nfrom api import f as g\na.f(1, y=2)\ng(1, y=2)\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_positional_only(self):
        self.write("api.py", "def f(a, /, b): pass\n")
        self.write("use.py", "from api import f\nf(a=1, b=2)\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertTrue(any('Positional-only' in x['message'] for x in e))

    def test_transitive_impact_and_cycles(self):
        self.write("a.py", "def f(): pass\n")
        self.write("b.py", "from a import f\nimport c\n")
        self.write("c.py", "import b\n")
        data, cons = build_dependency_graph(self.root)
        d, t = get_transitive_dependents("a", cons, data)
        self.assertIn("b.py", d)
        self.assertIn("c.py", t)

    def test_deleted_dependency_detection_as_prompt(self):
        self.write("a.py", "def f(): pass\n")
        self.write("b.py", "from a import f\n")
        data, cons = build_dependency_graph(self.root)
        d, t = get_transitive_dependents("a", cons, data)
        p = generate_ai_remediation_prompt("a.py", [{"type": "DELETED_DEPENDENCY", "file": "a.py", "message": "deleted"}], d, t)
        self.assertIn("b.py", p)

    def test_renamed_dependency_reports_old_consumer(self):
        self.write("old.py", "def f(): pass\n")
        self.write("use.py", "from old import f\n")
        data, cons = build_dependency_graph(self.root)
        d, _ = get_transitive_dependents("old", cons, data)
        os.rename(os.path.join(self.root, "old.py"), os.path.join(self.root, "new.py"))
        errors, warnings, _ = check_project_integrity(self.root)
        self.assertIn("use.py", d)
        self.assertTrue(any(w['type'] == 'UNRESOLVED_IMPORT' for w in warnings))

    def test_commands_exist(self):
        for n in (
            "compute_file_hash", "parse_function_signature", "extract_file_info",
            "get_project_files", "resolve_import_target", "build_dependency_graph",
            "get_transitive_dependents", "check_project_integrity",
            "generate_ai_remediation_prompt", "run_scan", "run_check",
            "run_watch", "run_tests", "main"
        ):
            self.assertTrue(callable(globals()[n]))


def main():
    parser = argparse.ArgumentParser(description="RepoShield — AI Code Safety & Dependency Sentinel")
    subs = parser.add_subparsers(dest="command")

    for cmd, help_txt in (
        ("scan", "Map Python modules and dependencies"),
        ("check", "Check syntax, imports, and call compatibility"),
        ("watch", "Watch file changes and show remediation prompts"),
    ):
        p = subs.add_parser(cmd, help=help_txt)
        p.add_argument("path", nargs="?", default=".")

    subs.add_parser("test", help="Run built-in automated test suite")
    args = parser.parse_args()

    if args.command == "test":
        sys.exit(0 if run_tests() else 1)

    target = getattr(args, "path", ".")
    if args.command == "scan":
        run_scan(target)
    elif args.command == "watch":
        run_watch(target)
    else:
        sys.exit(0 if run_check(target) else 1)


if __name__ == "__main__":
    main()
