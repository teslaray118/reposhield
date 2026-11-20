#!/usr/bin/env python3
"""
🛡️ REPOSHIELD — AI Code Safety & Dependency Sentinel (v0.2.2)
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
    ".pyc", ".pyo", ".pyd", ".tmp", ".swp", ".swo", "~", ".bak", ".crdownload"
)

STDLIB_MODULES = getattr(sys, "stdlib_module_names", frozenset({
    "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii",
    "bisect", "builtins", "calendar", "cmath", "collections", "contextlib",
    "copy", "csv", "ctypes", "datetime", "decimal", "difflib", "dis",
    "email", "enum", "errno", "faulthandler", "fcntl", "fnmatch", "fractions",
    "functools", "gc", "getopt", "getpass", "gettext", "glob", "gzip",
    "hashlib", "heapq", "hmac", "html", "http", "imaplib", "importlib", "inspect",
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


def _extract_str_constant(node):
    """Safely extract string literal from AST node across Python versions."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if sys.version_info < (3, 8) and hasattr(ast, "Str") and isinstance(node, ast.Str):
        return node.s
    return None


def compute_file_hash(filepath, retries=2):
    """Compute SHA-256 of file content to detect real modifications, with retry for atomic saves."""
    for attempt in range(retries + 1):
        try:
            with open(filepath, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except (OSError, PermissionError):
            if attempt < retries:
                time.sleep(0.04)
            else:
                return None
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
        self.dynamic_importers = set()
        self.scope = []
        self.condition_stack = []

    def visit_If(self, node):
        self.condition_stack.append("if")
        for item in node.body:
            self.visit(item)
        for item in node.orelse:
            self.visit(item)
        self.condition_stack.pop()

    def visit_Try(self, node):
        is_import_guard = False
        for handler in node.handlers:
            if handler.type is None:
                is_import_guard = True
            elif isinstance(handler.type, ast.Name) and handler.type.id in ("ImportError", "ModuleNotFoundError", "Exception"):
                is_import_guard = True
            elif isinstance(handler.type, ast.Tuple):
                for elt in handler.type.elts:
                    if isinstance(elt, ast.Name) and elt.id in ("ImportError", "ModuleNotFoundError", "Exception"):
                        is_import_guard = True

        tag = "try_except" if is_import_guard else "try"
        self.condition_stack.append(tag)
        for item in node.body:
            self.visit(item)
        for handler in node.handlers:
            self.visit(handler)
        for item in node.orelse:
            self.visit(item)
        for item in node.finalbody:
            self.visit(item)
        self.condition_stack.pop()

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

    def _dotted(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            p = self._dotted(node.value)
            return p + "." + node.attr if p else None
        return None

    def visit_Assign(self, node):
        if not self.scope:
            for t in node.targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        self.r["definitions"].add(n.id)
        if isinstance(node.value, ast.Call):
            dotted = self._dotted(node.value.func)
            local_func = node.value.func.id if isinstance(node.value.func, ast.Name) else None
            is_dyn = (local_func in self.dynamic_importers) or (dotted == "importlib.import_module")
            if is_dyn and node.value.args:
                mod_str = _extract_str_constant(node.value.args[0])
                if mod_str:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.module_aliases[target.id] = mod_str
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if not self.scope and isinstance(node.target, ast.Name):
            self.r["definitions"].add(node.target.id)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            self.module_aliases[local] = alias.name if alias.asname else alias.name.split(".")[0]
            if alias.name == "importlib":
                self.module_aliases[local] = "importlib"
            self.r["imports"].append({
                "type": "module",
                "module": alias.name,
                "level": 0,
                "name": None,
                "asname": local,
                "line": node.lineno,
                "is_conditional": bool(self.condition_stack),
                "condition_type": self.condition_stack[-1] if self.condition_stack else None,
                "is_dynamic": False,
                "is_literal": True,
            })

    def visit_ImportFrom(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if not self.scope and alias.name != "*":
                self.r["definitions"].add(local)
            if node.module == "importlib" and alias.name == "import_module":
                self.dynamic_importers.add(local)
            item = {
                "type": "from",
                "module": node.module or "",
                "level": node.level,
                "name": alias.name,
                "asname": local,
                "line": node.lineno,
                "is_conditional": bool(self.condition_stack),
                "condition_type": self.condition_stack[-1] if self.condition_stack else None,
                "is_dynamic": False,
                "is_literal": True,
            }
            self.r["imports"].append(item)
            if alias.name == "*":
                self.r["wildcard_imports"].add(node.module or "")
            else:
                self.symbol_aliases[local] = (node.module or "", alias.name, node.level)

    def visit_Call(self, node):
        dotted = self._dotted(node.func)
        local_name = node.func.id if isinstance(node.func, ast.Name) else None

        # 1. Dynamic imports: importlib.import_module(...) or aliased
        is_dynamic = False
        if local_name and (local_name in self.dynamic_importers or local_name == "__import__"):
            is_dynamic = True
        elif dotted == "importlib.import_module":
            is_dynamic = True
        elif dotted:
            parts = dotted.split(".")
            if parts[0] in self.module_aliases and self.module_aliases[parts[0]] == "importlib" and parts[1:] == ["import_module"]:
                is_dynamic = True

        if is_dynamic and node.args:
            mod_str = _extract_str_constant(node.args[0])
            self.r["imports"].append({
                "type": "dynamic",
                "module": mod_str or "<dynamic>",
                "level": 0,
                "name": None,
                "asname": None,
                "line": node.lineno,
                "is_conditional": bool(self.condition_stack),
                "condition_type": self.condition_stack[-1] if self.condition_stack else None,
                "is_dynamic": True,
                "is_literal": mod_str is not None,
            })

        # 2. getattr(obj, "attr") calls
        if local_name == "getattr" and len(node.args) >= 2:
            target_obj = node.args[0]
            attr_arg = node.args[1]
            attr_str = _extract_str_constant(attr_arg)
            obj_name = target_obj.id if isinstance(target_obj, ast.Name) else None
            self.r["getattr_calls"].append({
                "line": node.lineno,
                "object": obj_name,
                "attr": attr_str,
                "has_literal_attr": attr_str is not None,
                "is_conditional": bool(self.condition_stack),
            })

        # 3. Regular function calls to mapped symbols
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


def extract_file_info(filepath, retries=2):
    """
    Extract exports, signatures, classes, imports, and calls from a Python file.
    Preserves backward-compatible return dictionary keys with atomic save retries.
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
        "getattr_calls": [],
        "wildcard_imports": set(),
        "hash": None,
    }
    content = None
    for attempt in range(retries + 1):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            break
        except (OSError, PermissionError):
            if attempt < retries:
                time.sleep(0.04)
            else:
                result["error"] = "File temporarily locked or unavailable during save"
                return result
        except UnicodeDecodeError as e:
            result["error"] = f"Encoding error: {e}"
            return result
        except Exception as e:
            result["error"] = f"Could not read file: {e}"
            return result

    if content is None:
        return result

    result["hash"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    try:
        tree = ast.parse(content, filename=filepath)
        result["valid"] = True
        _InfoVisitor(result).visit(tree)
    except SyntaxError as e:
        result["error"] = f"Syntax error at line {e.lineno}: {e.msg}"
        result["error_line"] = e.lineno
    except Exception as e:
        result["error"] = f"Parse failure: {e}"
    return result


def get_project_files(target_dir):
    """Enumerate valid Python source files excluding virtualenvs, cache dirs, and editor temp files."""
    target_dir = os.path.abspath(target_dir)
    found = {}
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS and not d.startswith("."))
        for name in sorted(files):
            # Skip non-python files, hidden files, editor swap/temp files, and backups
            if (not name.endswith(".py")
                or name.startswith((".", "#", "~"))
                or any(name.endswith(ext) for ext in IGNORE_EXTENSIONS)
                or ".tmp" in name
                or ".swp" in name
                or name.endswith("~")):
                continue
            path = os.path.abspath(os.path.join(root, name))
            try:
                mtime = os.path.getmtime(path)
            except (OSError, PermissionError):
                continue
            rel = os.path.relpath(path, target_dir).replace(os.sep, "/")
            parts = rel[:-3].split("/")
            module_parts = parts[:-1] if parts[-1] == "__init__" else parts
            mod = ".".join(module_parts)
            found[path] = {
                "rel_path": rel,
                "mod_name": mod,
                "module_id": mod or "__root__",
                "base_name": "__init__" if name == "__init__.py" else name[:-3],
                "mtime": mtime,
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
    if name and name not in ("*", "*dynamic*"):
        candidate = (full + "." + name).strip(".")
        matches = idx.get(candidate, [])
        if len(matches) == 1:
            return matches[0]

    return None


def build_dependency_graph(target_dir):
    """
    Build dependency graph tracking imported symbols, conditional status, and consumers.
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
            is_dynamic = imp.get("is_dynamic", False)
            is_conditional = imp.get("is_conditional", False)

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
                "is_conditional": is_conditional,
                "condition_type": imp.get("condition_type"),
                "is_dynamic": is_dynamic,
                "is_literal": imp.get("is_literal", True),
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

            if is_dynamic:
                if imp.get("is_literal") and imp.get("module"):
                    target = resolve_import_target(info["module_id"], {"module": imp["module"], "level": 0}, module_map)
                    if target:
                        rec.update(
                            target_path=target.get("rel_path"),
                            target_module=target.get("module_id"),
                            name="*dynamic*",
                        )
                        consumers[target["module_id"]].append(rec)
                    else:
                        root = imp.get("module", "").split(".")[0]
                        if root and root not in STDLIB_MODULES:
                            rec["unresolved_module"] = True
                            consumers["?" + imp.get("module", "")].append(rec)
                else:
                    rec["unresolved_module"] = True
                    consumers["?<dynamic>"].append(rec)
            elif target:
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
    Distinguishes confirmed errors from conditional and dynamic warnings.
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
                mod_name = rec.get("module", rec.get("imported_module", "?"))
                if rec.get("is_dynamic"):
                    if not rec.get("is_literal"):
                        warnings.append({
                            "severity": "WARNING",
                            "type": "DYNAMIC_IMPORT",
                            "file": rec["consumer_rel"],
                            "line": rec["line"],
                            "message": f"Dynamic import at line {rec['line']} uses runtime-constructed module name and cannot be statically verified.",
                        })
                    else:
                        warnings.append({
                            "severity": "WARNING",
                            "type": "DYNAMIC_IMPORT",
                            "file": rec["consumer_rel"],
                            "line": rec["line"],
                            "message": f"Dynamic import '{mod_name}' at line {rec['line']} could not be resolved locally; may be dynamic plugin or external.",
                        })
                elif rec.get("is_conditional"):
                    warnings.append({
                        "severity": "WARNING",
                        "type": "CONDITIONAL_IMPORT",
                        "file": rec["consumer_rel"],
                        "line": rec["line"],
                        "message": f"Conditional import '{mod_name}' at line {rec['line']} could not be resolved locally; may be platform-specific or optional.",
                    })
                else:
                    warnings.append({
                        "severity": "WARNING",
                        "type": "UNRESOLVED_IMPORT",
                        "file": rec["consumer_rel"],
                        "line": rec["line"],
                        "message": f"Could not resolve '{mod_name}' locally; may be external, dynamic, or ambiguous.",
                    })
                continue

            target = by_rel.get(rec.get("target_path"))
            if not target or not target.get("valid"):
                continue

            sym = rec.get("name")
            if rec.get("import_type") == "module" or sym in (None, "*", "*module*", "*dynamic*"):
                continue

            if sym not in target["definitions"]:
                if rec.get("is_conditional"):
                    warnings.append({
                        "severity": "WARNING",
                        "type": "CONDITIONAL_IMPORT",
                        "file": rec["consumer_rel"],
                        "line": rec["line"],
                        "target_file": target["rel_path"],
                        "symbol": sym,
                        "message": f"Conditional dependency '{sym}' in '{rec['consumer_rel']}' (line {rec['line']}) not found in '{target['rel_path']}'; may be platform-specific or guarded by fallback.",
                    })
                else:
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

    # Check getattr calls against resolved modules where known
    for path, info in file_data.items():
        if not info["valid"]:
            continue
        for g in info.get("getattr_calls", []):
            obj = g.get("object")
            attr = g.get("attr")
            if not obj or not attr or not g.get("has_literal_attr"):
                continue
            # Check if obj was tracked as an alias of a local module
            for imp in info["imports"]:
                if imp.get("asname") == obj or (imp.get("type") == "dynamic" and imp.get("module")):
                    mod_name = imp.get("module")
                    target = resolve_import_target(
                        info["module_id"],
                        {"module": mod_name, "level": 0},
                        {d["module_id"]: d for d in file_data.values()}
                    )
                    if target and target.get("valid") and attr not in target["definitions"]:
                        warnings.append({
                            "severity": "WARNING",
                            "type": "DYNAMIC_ATTRIBUTE",
                            "file": info["rel_path"],
                            "line": g["line"],
                            "message": f"Call getattr({obj}, '{attr}') targets '{target['rel_path']}', but attribute '{attr}' is not defined there.",
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
                cond = " (conditional)" if rec.get("is_conditional") else ""
                dyn = " (dynamic)" if rec.get("is_dynamic") else ""
                print(f"  • {rec['consumer_rel']}:{rec['line']} -> {label} from {rec['target_path']}{cond}{dyn}")
            elif rec.get("unresolved_module"):
                kind = "Dynamic" if rec.get("is_dynamic") else ("Conditional" if rec.get("is_conditional") else "Unresolved/ambiguous")
                print(f"  • ⚠️ {kind}: {rec['consumer_rel']}:{rec['line']} imports {rec.get('module', '?')}")

    errors, warnings, stats = check_project_integrity(target_dir)
    print(f"\n📊 SUMMARY: {stats['files_scanned']} files, {stats['dependencies_mapped']} dependencies, {len(errors)} errors, {len(warnings)} warnings")
    return stats


def run_check(target_dir):
    print(f"\n🔍 Checking project: {os.path.abspath(target_dir)}")
    errors, warnings, stats = check_project_integrity(target_dir)
    for w in warnings:
        print(f"⚠️ WARNING [{w['type']}] {w['file']}:{w['line']}: {w['message']}")
    for e in errors:
        print(f"🚨 ERROR [{e['type']}] {e['file']}:{e['line']}: {e['message']}")
    print(f"\n{'❌ Issues found' if errors else '✅ No confirmed issues found'} ({stats['files_scanned']} files, {stats['dependencies_mapped']} dependencies, {len(warnings)} warnings)")
    return not errors


def run_watch(target_dir):
    root = os.path.abspath(target_dir)
    print(BANNER)
    print(f"👀 Watching {root}. Press Ctrl+C to stop.")
    previous = {p: compute_file_hash(p) for p in get_project_files(root)}
    previous_data, previous_consumers = build_dependency_graph(root)

    try:
        while True:
            time.sleep(0.5)
            current_files = get_project_files(root)
            current = {p: compute_file_hash(p) for p in current_files}
            deleted = set(previous) - set(current)
            added = set(current) - set(previous)
            changed = {p for p in set(current) & set(previous) if current[p] != previous[p]}

            if added or deleted or changed:
                # Settle delay for atomic save file-renames
                time.sleep(0.08)
                current_files = get_project_files(root)
                current = {p: compute_file_hash(p) for p in current_files}
                deleted = set(previous) - set(current)
                added = set(current) - set(previous)
                changed = {p for p in set(current) & set(previous) if current[p] != previous[p]}

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

    # === NEW v0.2.2 TESTS ===

    def test_conditional_dependencies_both_exist(self):
        self.write("win_utils.py", "def get_info(): return 'win'\n")
        self.write("nix_utils.py", "def get_info(): return 'nix'\n")
        self.write("main.py", (
            "import sys\n"
            "if sys.platform == 'win32':\n"
            "    from win_utils import get_info\n"
            "else:\n"
            "    from nix_utils import get_info\n"
            "get_info()\n"
        ))
        e, w, s = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertEqual(s['critical_errors'], 0)

    def test_conditional_dependency_one_missing_reports_warning_not_critical(self):
        self.write("win_utils.py", "def get_info(): return 'win'\n")
        self.write("main.py", (
            "import sys\n"
            "if sys.platform == 'win32':\n"
            "    from win_utils import get_info\n"
            "else:\n"
            "    from nix_utils import get_info\n"
            "get_info()\n"
        ))
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)  # No critical breaking error!
        self.assertTrue(any(item['type'] == 'CONDITIONAL_IMPORT' for item in w))

    def test_unconditional_dependency_missing_is_critical(self):
        self.write("api.py", "def existing(): pass\n")
        self.write("main.py", "from api import missing_func\nmissing_func()\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(item['type'] == 'BROKEN_CONTRACT' and item['severity'] == 'CRITICAL' for item in e))

    def test_nested_conditional_imports(self):
        self.write("fallback.py", "def run(): pass\n")
        self.write("app.py", (
            "has_feature = True\n"
            "is_debug = False\n"
            "if has_feature:\n"
            "    if is_debug:\n"
            "        from debug_tools import inspector\n"
            "    else:\n"
            "        from fallback import run\n"
        ))
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(item['type'] == 'CONDITIONAL_IMPORT' for item in w))

    def test_try_except_importerror_optional_dependency(self):
        self.write("fallback_accel.py", "def accelerate(): return 1\n")
        self.write("service.py", (
            "try:\n"
            "    from c_speedups import accelerate\n"
            "except (ImportError, ModuleNotFoundError):\n"
            "    from fallback_accel import accelerate\n"
            "accelerate()\n"
        ))
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)  # Missing c_speedups must NOT cause a critical failure
        self.assertTrue(any(item['type'] == 'CONDITIONAL_IMPORT' for item in w))

    def test_dynamic_import_literal_local_module_resolves(self):
        self.write("plugins/reports.py", "def generate(): return True\n")
        self.write("main.py", (
            "import importlib\n"
            "reports = importlib.import_module('plugins.reports')\n"
        ))
        e, w, s = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertGreaterEqual(s['dependencies_mapped'], 1)

    def test_dynamic_import_missing_local_reports_warning(self):
        self.write("main.py", (
            "import importlib\n"
            "mod = importlib.import_module('nonexistent_plugin_xyz')\n"
        ))
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(item['type'] == 'DYNAMIC_IMPORT' for item in w))

    def test_dynamic_import_aliased_import_module(self):
        self.write("plugins/analytics.py", "def track(): pass\n")
        self.write("main.py", (
            "from importlib import import_module as load_module\n"
            "analytics = load_module('plugins.analytics')\n"
        ))
        e, w, s = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertGreaterEqual(s['dependencies_mapped'], 1)

    def test_dynamic_import_runtime_constructed_name_reports_warning(self):
        self.write("main.py", (
            "import importlib\n"
            "name = 'plugins.' + 'custom'\n"
            "plugin = importlib.import_module(name)\n"
        ))
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(item['type'] == 'DYNAMIC_IMPORT' for item in w))

    def test_getattr_known_and_unknown_attribute(self):
        self.write("plugins/reports.py", "def generate_report(): pass\n")
        self.write("main.py", (
            "import importlib\n"
            "module = importlib.import_module('plugins.reports')\n"
            "ok_fn = getattr(module, 'generate_report')\n"
            "bad_fn = getattr(module, 'missing_function_xyz')\n"
        ))
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(item['type'] == 'DYNAMIC_ATTRIBUTE' for item in w))

    def test_watch_atomic_save_and_temp_files_ignored(self):
        self.write("service.py", "def ping(): pass\n")
        self.write("service.py.tmp", "def broken(:\n")
        self.write(".#service.py", "def broken(:\n")
        self.write("service.py~", "def broken(:\n")
        self.write("service.py.swp", "def broken(:\n")
        files = get_project_files(self.root)
        self.assertEqual(len(files), 1)
        self.assertTrue(list(files.keys())[0].endswith("service.py"))


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
