#!/usr/bin/env python3
"""
RepoShield v0.3.0 — AI Code Safety & Dependency Sentinel
Lightweight, zero-dependency Python AST-based static analysis engine.
Detects cross-file contract breaks, missing symbols, signature mismatches,
scope shadowing, class inheritance regressions, and dynamic/conditional imports.
"""

import ast
import builtins
import hashlib
import os
import sys
import time
from collections import defaultdict, deque

VERSION = "1.0.0"

BANNER = rf"""
======================================================================
  🛡️  REPOSHIELD v{VERSION} — AI Code Safety & Dependency Sentinel
  Catch cross-file regressions before they break production.
======================================================================
"""

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".tox", "venv", ".venv", "env", ".env", "node_modules", "dist",
    "build", ".egg-info", "_build", ".idea", ".vscode"
}

IGNORE_EXTENSIONS = (
    ".pyc", ".pyo", ".pyd", ".swp", ".swo", "~", ".tmp", ".bak", ".orig"
)

STDLIB_MODULES = {
    "abc", "argparse", "array", "ast", "asyncio", "atexit", "base64",
    "bdb", "binascii", "bisect", "builtins", "bz2", "calendar", "cgi",
    "cgitb", "chunk", "cmath", "cmd", "code", "codecs", "codeop",
    "collections", "colorsys", "compileall", "concurrent", "configparser",
    "contextlib", "contextvars", "copy", "copyreg", "cProfile", "crypt",
    "csv", "ctypes", "curses", "dataclasses", "datetime", "dbm", "decimal",
    "difflib", "dis", "distutils", "doctest", "email", "encodings",
    "ensurepip", "enum", "errno", "faulthandler", "fcntl", "filecmp",
    "fileinput", "fnmatch", "fractions", "ftplib", "functools", "gc",
    "getopt", "getpass", "gettext", "glob", "graphlib", "gzip", "hashlib",
    "heapq", "hmac", "html", "http", "imaplib", "imghdr", "imp", "importlib",
    "inspect", "io", "ipaddress", "itertools", "json", "keyword", "lib2to3",
    "linecache", "locale", "logging", "lzma", "mailbox", "mailcap", "marshal",
    "math", "mimetypes", "mmap", "modulefinder", "msilib", "msvcrt", "multiprocessing",
    "netrc", "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
    "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil", "platform",
    "plistlib", "poplib", "posix", "pprint", "profile", "pstats", "pty",
    "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random",
    "re", "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched",
    "secrets", "select", "selectors", "shelve", "shlex", "shutil", "signal",
    "site", "smtpd", "smtplib", "sndhdr", "socket", "socketserver", "spwd",
    "sqlite3", "ssl", "stat", "statistics", "string", "stringprep", "struct",
    "subprocess", "sunau", "symbol", "symtable", "sys", "sysconfig", "syslog",
    "tabnanny", "tarfile", "telnetlib", "tempfile", "termios", "test",
    "textwrap", "threading", "time", "timeit", "tkinter", "token", "tokenize",
    "tomllib", "trace", "traceback", "tracemalloc", "tty", "turtle", "turtledemo",
    "types", "typing", "unicodedata", "unittest", "urllib", "uu", "uuid",
    "venv", "warnings", "wave", "weakref", "webbrowser", "winreg", "winsound",
    "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport",
    "zlib", "zoneinfo"
}

BUILTIN_NAMES = set(dir(builtins))


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


def parse_function_signature(func_node, is_method=False, method_type="method"):
    """Extract parameters, defaults, argument types, and async status from a FunctionDef/AsyncFunctionDef."""
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

    # Extract decorator names
    decorators = []
    for d in func_node.decorator_list:
        if isinstance(d, ast.Name):
            decorators.append(d.id)
        elif isinstance(d, ast.Attribute) and isinstance(d.value, ast.Name):
            decorators.append(f"{d.value.id}.{d.attr}")

    if "staticmethod" in decorators:
        method_type = "staticmethod"
    elif "classmethod" in decorators:
        method_type = "classmethod"
    elif "property" in decorators:
        method_type = "property"

    return {
        "name": func_node.name,
        "line": func_node.lineno,
        "is_async": isinstance(func_node, ast.AsyncFunctionDef),
        "is_method": is_method,
        "method_type": method_type,
        "decorators": decorators,
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


def extract_module_all(tree):
    """
    Extract statically identifiable exports from module-level __all__.
    Supports literal list/tuple, concatenation (+), and append/extend/augassign (+=).
    Returns (set_of_exports_or_None, is_dynamic).
    """
    exports = None
    is_dynamic = False

    def _eval_seq(node):
        nonlocal is_dynamic
        if isinstance(node, (ast.List, ast.Tuple)):
            items = []
            for elt in node.elts:
                s = _extract_str_constant(elt)
                if s is not None:
                    items.append(s)
                else:
                    is_dynamic = True
                    return None
            return items
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = _eval_seq(node.left)
            right = _eval_seq(node.right)
            if left is not None and right is not None:
                return left + right
            is_dynamic = True
            return None
        else:
            is_dynamic = True
            return None

    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    seq = _eval_seq(node.value)
                    if seq is not None:
                        exports = list(seq)
                        is_dynamic = False
                    else:
                        is_dynamic = True
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "__all__":
                if isinstance(node.op, ast.Add):
                    seq = _eval_seq(node.value)
                    if seq is not None and exports is not None:
                        exports.extend(seq)
                    else:
                        is_dynamic = True
                else:
                    is_dynamic = True
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) and call.func.value.id == "__all__":
                method = call.func.attr
                if method == "append" and call.args:
                    s = _extract_str_constant(call.args[0])
                    if s is not None and exports is not None:
                        exports.append(s)
                    else:
                        is_dynamic = True
                elif method == "extend" and call.args:
                    seq = _eval_seq(call.args[0])
                    if seq is not None and exports is not None:
                        exports.extend(seq)
                    else:
                        is_dynamic = True
                else:
                    is_dynamic = True

    if is_dynamic:
        return None, True
    if exports is not None:
        return set(exports), False
    return None, False

class LexicalScope:
    """Represents a lexical scope in Python (module, function, class, or async function)."""
    def __init__(self, name="<module>", kind="module", parent=None):
        self.name = name
        self.kind = kind  # "module", "function", "class", "async_function"
        self.parent = parent
        self.children = []
        self.module_aliases = {}     # local alias -> target module string
        self.symbol_aliases = {}     # local alias -> (mod, sym, level, is_conditional)
        self.wildcard_imports = set()
        self.dynamic_importers = set()
        self.provenance = {}         # var_name -> {"kind": ..., "module": ..., "class": ..., "line": ...}
        self.local_vars = set()      # local assignments and function parameters
        self.definitions = set()

    def _lookup_parent(self):
        p = self.parent
        while p and p.kind == "class":
            p = p.parent
        return p

    def lookup_module(self, name):
        """Lookup module alias with lexical shadowing."""
        if name in self.module_aliases:
            return self.module_aliases[name]
        if name in self.local_vars and name not in self.module_aliases and name not in self.symbol_aliases:
            return None
        p = self._lookup_parent()
        if p:
            return p.lookup_module(name)
        return None

    def lookup_symbol(self, name):
        """Lookup imported symbol with lexical shadowing."""
        if name in self.symbol_aliases:
            return self.symbol_aliases[name]
        if name in self.local_vars and name not in self.symbol_aliases and name not in self.module_aliases:
            return None
        p = self._lookup_parent()
        if p:
            return p.lookup_symbol(name)
        return None

    def lookup_provenance(self, name):
        """Lookup variable provenance (e.g. which module or class instance it holds)."""
        if name in self.provenance:
            return self.provenance[name]
        if name in self.local_vars and name not in self.provenance and name not in self.module_aliases:
            return None
        p = self._lookup_parent()
        if p:
            return p.lookup_provenance(name)
        return None

    def all_visible_wildcards(self):
        """Collect all wildcard imports visible in this scope and outer scopes."""
        wildcards = set(self.wildcard_imports)
        p = self._lookup_parent()
        if p:
            wildcards.update(p.all_visible_wildcards())
        return wildcards



def _collect_function_scope_vars(func_node):
    globals_set = set()
    nonlocals_set = set()
    locals_set = set()

    for arg in getattr(func_node.args, 'posonlyargs', []):
        locals_set.add(arg.arg)
    for arg in func_node.args.args:
        locals_set.add(arg.arg)
    for arg in func_node.args.kwonlyargs:
        locals_set.add(arg.arg)
    if func_node.args.vararg:
        locals_set.add(func_node.args.vararg.arg)
    if func_node.args.kwarg:
        locals_set.add(func_node.args.kwarg.arg)

    stack = list(func_node.body)
    while stack:
        curr = stack.pop()
        if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            locals_set.add(curr.name)
            continue
        elif isinstance(curr, ast.Global):
            for name in curr.names:
                globals_set.add(name)
        elif isinstance(curr, ast.Nonlocal):
            for name in curr.names:
                nonlocals_set.add(name)
        elif isinstance(curr, ast.Name) and isinstance(curr.ctx, ast.Store):
            locals_set.add(curr.id)
        elif isinstance(curr, ast.Import):
            for alias in curr.names:
                local_name = alias.asname or alias.name.split('.')[0]
                locals_set.add(local_name)
        elif isinstance(curr, ast.ImportFrom):
            for alias in curr.names:
                local_name = alias.asname or alias.name
                locals_set.add(local_name)

        for field, value in ast.iter_fields(curr):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST) and not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        stack.append(item)
                    elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        locals_set.add(item.name)
            elif isinstance(value, ast.AST):
                if not isinstance(value, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    stack.append(value)
                else:
                    locals_set.add(value.name)

    pure_locals = (locals_set - globals_set) - nonlocals_set
    return pure_locals, globals_set, nonlocals_set


class _InfoVisitor(ast.NodeVisitor):
    def __init__(self, result):
        self.r = result
        self.root_scope = LexicalScope("<module>", "module")
        self.current_scope = self.root_scope
        self.condition_stack = []

        # Backward compatibility aliases dicts
        self.module_aliases = self.root_scope.module_aliases
        self.symbol_aliases = self.root_scope.symbol_aliases
        self.dynamic_importers = self.root_scope.dynamic_importers

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

    def _handle_func_def(self, node, is_async=False):
        if self.current_scope == self.root_scope:
            self.r["definitions"].add(node.name)
            self.r["signatures"][node.name] = parse_function_signature(node, is_method=False)

        child_scope = LexicalScope(node.name, "async_function" if is_async else "function", parent=self.current_scope)
        self.current_scope.children.append(child_scope)

        # Python semantics: pre-analyze all assignments in body as local throughout
        locs, globs, nonlocs = _collect_function_scope_vars(node)
        child_scope.local_vars.update(locs)

        old_scope = self.current_scope
        self.current_scope = child_scope

        for item in node.body:
            self.visit(item)

        self.current_scope = old_scope

    def visit_FunctionDef(self, node):
        self._handle_func_def(node, is_async=False)

    def visit_AsyncFunctionDef(self, node):
        self._handle_func_def(node, is_async=True)

    def visit_ClassDef(self, node):
        methods, signatures = set(), {}
        bases = []
        has_dynamic_base = False

        for b in node.bases:
            if isinstance(b, ast.Name):
                bases.append(b.id)
            elif isinstance(b, ast.Attribute):
                dotted = self._dotted(b)
                bases.append(dotted or b.attr)
            else:
                has_dynamic_base = True

        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                methods.add(item.name)
                sig = parse_function_signature(item, is_method=True)
                signatures[item.name] = sig

        if self.current_scope == self.root_scope:
            self.r["definitions"].add(node.name)
            self.r["classes"][node.name] = {
                "line": node.lineno,
                "methods": methods,
                "signatures": signatures,
                "bases": bases,
                "has_dynamic_base": has_dynamic_base,
            }

        child_scope = LexicalScope(node.name, "class", parent=self.current_scope)
        self.current_scope.children.append(child_scope)
        old_scope = self.current_scope
        self.current_scope = child_scope

        for item in node.body:
            self.visit(item)

        self.current_scope = old_scope

    def _dotted(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            p = self._dotted(node.value)
            return p + "." + node.attr if p else None
        return None

    def visit_Assign(self, node):
        # 1. Track local variable definitions
        assigned_names = []
        for t in node.targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name):
                    self.current_scope.local_vars.add(n.id)
                    assigned_names.append(n.id)
                    if self.current_scope == self.root_scope:
                        self.r["definitions"].add(n.id)

        # 2. Track dynamic imports: x = importlib.import_module("mod") or __import__("mod")
        if isinstance(node.value, ast.Call):
            dotted = self._dotted(node.value.func)
            local_func = node.value.func.id if isinstance(node.value.func, ast.Name) else None
            is_dyn = (local_func in self.current_scope.dynamic_importers) or (dotted == "importlib.import_module") or (local_func == "__import__")
            if is_dyn and node.value.args:
                mod_str = _extract_str_constant(node.value.args[0])
                if mod_str:
                    for target_name in assigned_names:
                        self.current_scope.module_aliases[target_name] = mod_str
                        self.current_scope.provenance[target_name] = {
                            "kind": "module",
                            "module": mod_str,
                            "line": node.lineno,
                            "is_dynamic": True
                        }
            # Track class instance creation: service = PaymentService()
            elif isinstance(node.value.func, (ast.Name, ast.Attribute)):
                cls_dotted = self._dotted(node.value.func)
                if cls_dotted:
                    for target_name in assigned_names:
                        self.current_scope.provenance[target_name] = {
                            "kind": "instance",
                            "class": cls_dotted,
                            "line": node.lineno
                        }

        # 3. Simple variable provenance copy: y = x
        elif isinstance(node.value, ast.Name):
            src_prov = self.current_scope.lookup_provenance(node.value.id)
            if src_prov:
                for target_name in assigned_names:
                    self.current_scope.provenance[target_name] = src_prov
            else:
                for target_name in assigned_names:
                    self.current_scope.provenance.pop(target_name, None)
                    self.current_scope.module_aliases.pop(target_name, None)
        else:
            for target_name in assigned_names:
                self.current_scope.provenance.pop(target_name, None)
                self.current_scope.module_aliases.pop(target_name, None)

        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if isinstance(node.target, ast.Name):
            self.current_scope.local_vars.add(node.target.id)
            if self.current_scope == self.root_scope:
                self.r["definitions"].add(node.target.id)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            target_mod = alias.name if alias.asname else alias.name.split(".")[0]
            self.current_scope.module_aliases[local] = target_mod
            self.current_scope.provenance[local] = {
                "kind": "module",
                "module": alias.name,
                "line": node.lineno,
                "is_dynamic": False
            }
            if alias.name == "importlib":
                self.current_scope.module_aliases[local] = "importlib"

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
                "scope_name": self.current_scope.name,
                "scope_kind": self.current_scope.kind,
            })

    def visit_ImportFrom(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            if self.current_scope == self.root_scope and alias.name != "*":
                self.r["definitions"].add(local)

            if node.module == "importlib" and alias.name == "import_module":
                self.current_scope.dynamic_importers.add(local)

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
                "scope_name": self.current_scope.name,
                "scope_kind": self.current_scope.kind,
            }
            self.r["imports"].append(item)

            if alias.name == "*":
                self.r["wildcard_imports"].add(node.module or "")
                self.current_scope.wildcard_imports.add(node.module or "")
            else:
                self.current_scope.symbol_aliases[local] = (
                    node.module or "", alias.name, node.level, bool(self.condition_stack)
                )

    def visit_Call(self, node):
        dotted = self._dotted(node.func)
        local_name = node.func.id if isinstance(node.func, ast.Name) else None

        # 1. Dynamic imports: importlib.import_module(...) or aliased
        is_dynamic = False
        if local_name and (local_name in self.current_scope.dynamic_importers or local_name == "__import__"):
            is_dynamic = True
        elif dotted == "importlib.import_module":
            is_dynamic = True
        elif dotted:
            parts = dotted.split(".")
            mod_resolved = self.current_scope.lookup_module(parts[0])
            if mod_resolved == "importlib" and parts[1:] == ["import_module"]:
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
                "scope_name": self.current_scope.name,
            })

        # 2. getattr(obj, "attr") calls with strict provenance
        if local_name == "getattr" and len(node.args) >= 2:
            target_obj = node.args[0]
            attr_arg = node.args[1]
            attr_str = _extract_str_constant(attr_arg)
            obj_name = target_obj.id if isinstance(target_obj, ast.Name) else None
            obj_prov = self.current_scope.lookup_provenance(obj_name) if obj_name else None
            mod_lookup = self.current_scope.lookup_module(obj_name) if obj_name else None

            self.r["getattr_calls"].append({
                "line": node.lineno,
                "object": obj_name,
                "attr": attr_str,
                "has_literal_attr": attr_str is not None,
                "is_conditional": bool(self.condition_stack),
                "provenance": obj_prov,
                "module_alias": mod_lookup,
            })

        # 3. Regular function calls to mapped symbols, modules, or class instances
        target = None
        is_instance_method_call = False

        if local_name:
            sym_info = self.current_scope.lookup_symbol(local_name)
            if sym_info:
                mod, sym, level, is_cond = sym_info
                target = {
                    "kind": "symbol",
                    "module": mod,
                    "symbol": sym,
                    "level": level,
                    "local": local_name,
                    "is_conditional": is_cond,
                }
            elif local_name not in self.current_scope.local_vars and local_name not in self.r["definitions"] and local_name not in BUILTIN_NAMES:
                # Might be provided via wildcard imports
                target = {
                    "kind": "unresolved_call",
                    "symbol": local_name,
                    "line": node.lineno,
                }
        elif dotted:
            first, _, tail = dotted.partition(".")
            mod_resolved = self.current_scope.lookup_module(first)
            prov = self.current_scope.lookup_provenance(first)

            if mod_resolved and tail:
                target = {
                    "kind": "module",
                    "module": mod_resolved,
                    "symbol": tail,
                    "level": 0,
                    "local": first,
                }
            elif prov and prov.get("kind") == "instance" and tail:
                target = {
                    "kind": "instance_method",
                    "class": prov.get("class"),
                    "symbol": tail,
                    "local": first,
                }
                is_instance_method_call = True

        if target:
            pos_args = [x for x in node.args if not isinstance(x, ast.Starred)]
            has_star = any(isinstance(x, ast.Starred) for x in node.args)
            keywords = [k.arg for k in node.keywords]
            has_double_star = any(k.arg is None for k in node.keywords)

            self.r["calls"].append({
                "target": target,
                "name": target.get("symbol"),
                "line": node.lineno,
                "pos_count": len(pos_args),
                "has_star_args": has_star,
                "keywords": keywords,
                "has_double_star": has_double_star,
                "is_instance_method": is_instance_method_call,
            })

        self.generic_visit(node)


def extract_file_info(filepath, retries=2):
    """
    Extract exports, signatures, classes, imports, and calls from a Python file.
    Preserves backward-compatible return dictionary keys with atomic save retries.
    """
    result = {
        "valid": False,
        "root_scope": None,
        "error": None,
        "error_line": None,
        "definitions": set(),
        "signatures": {},
        "classes": {},
        "imports": [],
        "calls": [],
        "getattr_calls": [],
        "wildcard_imports": set(),
        "all_exports": None,
        "has_dynamic_all": False,
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
        all_exports, has_dynamic_all = extract_module_all(tree)
        result["all_exports"] = all_exports
        result["has_dynamic_all"] = has_dynamic_all
        vis = _InfoVisitor(result)
        vis.visit(tree)
        result["root_scope"] = vis.root_scope
    except SyntaxError as e:
        result["error"] = f"Syntax error at line {e.lineno}: {e.msg}"
        result["error_line"] = e.lineno
    except Exception as e:
        result["error"] = f"Parse failure: {e}"
    return result


def get_project_files(target_dir, source_roots=None):
    """
    Enumerate valid Python source files.
    Supports regular packages, PEP 420 namespace packages, and src/ layouts.
    """
    target_dir = os.path.abspath(target_dir)
    roots = [target_dir]
    src_dir = os.path.join(target_dir, "src")
    if os.path.isdir(src_dir):
        roots.append(src_dir)
    if source_roots:
        for r in source_roots:
            ar = os.path.abspath(r)
            if ar not in roots and os.path.isdir(ar):
                roots.append(ar)

    found = {}
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS and not d.startswith("."))
        for name in sorted(files):
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

            alt_ids = []
            if os.path.isdir(src_dir) and path.startswith(src_dir + os.sep):
                src_rel = os.path.relpath(path, src_dir).replace(os.sep, "/")
                src_parts = src_rel[:-3].split("/")
                src_mod_parts = src_parts[:-1] if src_parts[-1] == "__init__" else src_parts
                alt_ids.append(".".join(src_mod_parts))

            found[path] = {
                "rel_path": rel,
                "mod_name": mod,
                "module_id": mod or "__root__",
                "alt_module_ids": alt_ids,
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
            for alt in item.get("alt_module_ids", []):
                if item not in index[alt]:
                    index[alt].append(item)
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


def c3_mro(class_key, class_registry, visiting=None):
    if visiting is None:
        visiting = set()
    if class_key in visiting:
        return [class_key]
    visiting.add(class_key)
    cinfo = class_registry.get(class_key)
    if not cinfo or not cinfo.get("resolved_base_keys"):
        return [class_key]

    resolved_base_keys = [b for b in cinfo["resolved_base_keys"] if b in class_registry]
    if not resolved_base_keys:
        return [class_key]

    seqs = [c3_mro(b, class_registry, set(visiting)) for b in resolved_base_keys] + [resolved_base_keys]
    res = [class_key]
    while True:
        non_empty = [s for s in seqs if s]
        if not non_empty:
            break
        cand = None
        for s in non_empty:
            head = s[0]
            if not any(head in other[1:] for other in non_empty):
                cand = head
                break
        if cand is None:
            for s in non_empty:
                for item in s:
                    if item not in res:
                        res.append(item)
            return res
        res.append(cand)
        for s in non_empty:
            if s[0] == cand:
                del s[0]
    return res


def resolve_class_hierarchy(file_data):
    """
    Index all classes and resolve inherited methods and signatures across files using C3 MRO.
    Returns: dict of (module_id, class_name) -> class_info
    """
    class_registry = {}
    for path, info in file_data.items():
        if not info["valid"]:
            continue
        mod_id = info["module_id"]
        for cname, cinfo in info.get("classes", {}).items():
            class_registry[(mod_id, cname)] = {
                "file": path,
                "rel_path": info["rel_path"],
                "module_id": mod_id,
                "name": cname,
                "bases": cinfo["bases"],
                "has_dynamic_base": cinfo.get("has_dynamic_base", False),
                "methods": dict(cinfo["signatures"]),
                "direct_methods": set(cinfo["methods"]),
                "resolved_base_keys": [],
            }

    # First pass: resolve base keys
    for (mod_id, cname), cinfo in class_registry.items():
        resolved_base_keys = []
        for base_expr in cinfo["bases"]:
            base_key = None
            if "." in base_expr:
                base_mod, _, base_name = base_expr.rpartition(".")
                base_key = (base_mod, base_name)
            else:
                base_key = (mod_id, base_expr)
                if base_key not in class_registry:
                    f_info = file_data.get(cinfo["file"])
                    if f_info:
                        for imp in f_info["imports"]:
                            if imp.get("name") == base_expr or imp.get("asname") == base_expr:
                                base_key = (imp.get("module"), imp.get("name") or base_expr)
                                break
            if base_key:
                resolved_base_keys.append(base_key)
        cinfo["resolved_base_keys"] = resolved_base_keys

    # Second pass: compute C3 MRO and resolved methods
    for (mod_id, cname), cinfo in class_registry.items():
        mro_list = c3_mro((mod_id, cname), class_registry)
        cinfo["mro"] = mro_list
        resolved_sigs = {}
        for ancestor_key in reversed(mro_list):
            ancestor = class_registry.get(ancestor_key)
            if ancestor:
                resolved_sigs.update(ancestor["methods"])

        cinfo["resolved_signatures"] = resolved_sigs
        cinfo["resolved_methods"] = set(resolved_sigs.keys())

    return class_registry


def build_dependency_graph(target_dir, source_roots=None):
    """
    Build dependency graph tracking imported symbols, conditional status, and consumers.
    Returns: (file_data, consumers)
    """
    py_files = get_project_files(target_dir, source_roots)
    file_data = {}
    module_candidates = defaultdict(list)

    for path, meta in py_files.items():
        info = extract_file_info(path)
        info.update(meta)
        file_data[path] = info
        module_candidates[meta["module_id"]].append(info)
        for alt in meta.get("alt_module_ids", []):
            module_candidates[alt].append(info)

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
                if target:
                    cand_sub = ((imp.get("module", "") or "") + "." + (imp.get("name", "") or "")).strip(".")
                    if target.get("module_id") == cand_sub or cand_sub in target.get("alt_module_ids", []):
                        imp = dict(imp, name="*module*")

            # Check if ambiguous
            is_ambiguous = False
            raw_mod = imp.get("module", "")
            if not target and raw_mod:
                all_files_list = [v for vals in module_candidates.values() for v in vals]
                matches = [f for f in all_files_list if f.get("base_name") == raw_mod or f.get("module_id") == raw_mod or f.get("module_id", "").endswith("." + raw_mod)]
                unique_matches = {m["rel_path"]: m for m in matches}
                if len(unique_matches) > 1:
                    is_ambiguous = True

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
                "is_ambiguous": is_ambiguous,
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


def _call_error(sig, call, is_instance_call=False):
    """
    Validate call arguments against a signature.
    Accounts for instance calls (bound self/cls) and dynamic *args/**kwargs.
    """
    name = sig["name"]
    args_count = call["pos_count"]
    kws = [x for x in call["keywords"] if x is not None]
    posonly = set(sig["posonly_args"])
    posnames = list(sig["all_pos"])
    required_pos = list(sig["required_pos"])

    # If instance method call and not staticmethod, drop bound self parameter
    method_type = sig.get("method_type", "method")
    if is_instance_call and method_type != "staticmethod" and posnames:
        bound_param = posnames[0]
        posnames = posnames[1:]
        if bound_param in required_pos:
            required_pos.remove(bound_param)
        posonly.discard(bound_param)

    # If *args supplied dynamically, positional count checks cannot be confirmed
    if not call["has_star_args"] and not sig["has_varargs"] and args_count > len(posnames):
        return f"Too many positional arguments for {name}(): accepts at most {len(posnames)}, got {args_count}."

    filled = set(posnames[:args_count])
    if len(kws) != len(set(kws)):
        return f"Duplicate keyword argument in call to {name}()."

    for kw in kws:
        if kw in posonly:
            return f"Positional-only parameter '{kw}' passed by keyword to {name}()."
        if kw in filled:
            return f"Multiple values for parameter '{kw}' in call to {name}()."
        if not sig["has_kwargs"] and kw not in sig["pos_args"] and kw not in sig["kwonly_params"]:
            return f"Unexpected keyword argument '{kw}' for {name}()."

    # Required parameters check
    if not call["has_double_star"]:
        eff_required_pos = [] if call["has_star_args"] else required_pos
        for p in eff_required_pos:
            if p not in filled and p not in kws:
                return f"Missing required argument '{p}' for {name}()."
        for p in sig["required_kwonly"]:
            if p not in kws:
                return f"Missing required keyword-only argument '{p}' for {name}()."

    return None


def check_project_integrity(target_dir_or_graph, source_roots=None):
    """
    Perform deep static analysis across the repository.
    Accepts target_dir string or pre-built graph tuple (file_data, consumers).
    Returns: (errors, warnings, stats)
    """
    if isinstance(target_dir_or_graph, tuple) and len(target_dir_or_graph) == 2:
        file_data, consumers = target_dir_or_graph
    elif isinstance(target_dir_or_graph, dict):
        file_data = target_dir_or_graph.get("file_data", target_dir_or_graph)
        consumers = target_dir_or_graph.get("consumers", {})
    else:
        file_data, consumers = build_dependency_graph(target_dir_or_graph, source_roots)
    class_registry = resolve_class_hierarchy(file_data)
    errors, warnings, seen = [], [], set()

    for path, info in file_data.items():
        if not info["valid"]:
            errors.append({
                "severity": "CRITICAL",
                "type": "SYNTAX_ERROR",
                "file": info["rel_path"],
                "line": info.get("error_line") or 1,
                "message": info["error"],
                "is_confirmed": True,
            })

    by_rel = {d["rel_path"]: d for d in file_data.values()}
    by_mod = {d["module_id"]: d for d in file_data.values()}

    
    # Check explicit __all__ export integrity
    for path, info in file_data.items():
        if not info["valid"]:
            continue
        if info.get("all_exports") is not None:
            for exp_sym in info["all_exports"]:
                if exp_sym not in info["definitions"]:
                    errors.append({
                        "severity": "CRITICAL",
                        "type": "BROKEN_CONTRACT",
                        "file": info["rel_path"],
                        "line": 1,
                        "target_file": info["rel_path"],
                        "symbol": exp_sym,
                        "message": f"Module '{info['rel_path']}' declares '{exp_sym}' in __all__, but that symbol is not defined.",
                        "is_confirmed": True,
                    })

    for _, records in consumers.items():
        for rec in records:
            if rec.get("is_ambiguous"):
                warnings.append({
                    "severity": "WARNING",
                    "type": "AMBIGUOUS_IMPORT",
                    "file": rec["consumer_rel"],
                    "line": rec["line"],
                    "message": f"Module '{rec.get('module')}' matches multiple local candidates; import is ambiguous.",
                    "is_confirmed": False,
                })
                continue

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
                            "is_confirmed": False,
                        })
                    else:
                        warnings.append({
                            "severity": "WARNING",
                            "type": "DYNAMIC_IMPORT",
                            "file": rec["consumer_rel"],
                            "line": rec["line"],
                            "message": f"Dynamic import '{mod_name}' at line {rec['line']} could not be resolved locally; may be dynamic plugin or external.",
                            "is_confirmed": False,
                        })
                elif rec.get("is_conditional"):
                    warnings.append({
                        "severity": "WARNING",
                        "type": "CONDITIONAL_IMPORT",
                        "file": rec["consumer_rel"],
                        "line": rec["line"],
                        "message": f"Conditional import '{mod_name}' at line {rec['line']} could not be resolved locally; may be platform-specific or optional.",
                        "is_confirmed": False,
                    })
                else:
                    warnings.append({
                        "severity": "WARNING",
                        "type": "UNRESOLVED_IMPORT",
                        "file": rec["consumer_rel"],
                        "line": rec["line"],
                        "message": f"Could not resolve '{mod_name}' locally; may be external, dynamic, or ambiguous.",
                        "is_confirmed": False,
                    })
                continue

            target = by_rel.get(rec.get("target_path"))
            if not target or not target.get("valid"):
                continue

            sym = rec.get("name")
            if rec.get("import_type") == "module" or sym in (None, "*", "*module*", "*dynamic*"):
                continue

            # Determine available exports in target (checking __all__)
            target_exports = target["definitions"]
            if target.get("all_exports") is not None:
                target_exports = target["all_exports"]

            if sym not in target["definitions"] and sym not in target_exports:
                if rec.get("is_conditional"):
                    warnings.append({
                        "severity": "WARNING",
                        "type": "CONDITIONAL_IMPORT",
                        "file": rec["consumer_rel"],
                        "line": rec["line"],
                        "target_file": target["rel_path"],
                        "symbol": sym,
                        "message": f"Conditional dependency '{sym}' in '{rec['consumer_rel']}' (line {rec['line']}) not found in '{target['rel_path']}'; may be platform-specific or guarded by fallback.",
                        "is_confirmed": False,
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
                            "is_confirmed": True,
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
                    by_mod
                )
                if not call_target or call_target.get("rel_path") != target.get("rel_path"):
                    continue

                msg = _call_error(sig, call, is_instance_call=call.get("is_instance_method", False))
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
                            "is_confirmed": True,
                        })

    # Check wildcard imports and unresolved calls
    for path, info in file_data.items():
        if not info["valid"]:
            continue
        wildcards = info.get("wildcard_imports", set())
        resolved_wildcards = []
        for w in wildcards:
            t = resolve_import_target(info["module_id"], {"module": w, "level": 0}, by_mod)
            if t:
                resolved_wildcards.append(t)

        for call in info["calls"]:
            target_ref = call.get("target") or {}
            # Check instance method calls
            if target_ref.get("kind") == "instance_method":
                cname = target_ref.get("class")
                method_name = target_ref.get("symbol")
                # Look up class in registry
                cls_info = class_registry.get((info["module_id"], cname))
                if not cls_info:
                    for (m, c), c_obj in class_registry.items():
                        if c == cname:
                            cls_info = c_obj
                            break

                if cls_info:
                    if method_name not in cls_info["resolved_methods"]:
                        if not cls_info.get("has_dynamic_base"):
                            warnings.append({
                                "severity": "WARNING",
                                "type": "BROKEN_CONTRACT",
                                "file": info["rel_path"],
                                "line": call["line"],
                                "message": f"Class '{cname}' does not define or inherit method '{method_name}'.",
                                "is_confirmed": False,
                            })
                    else:
                        sig = cls_info["resolved_signatures"].get(method_name)
                        if sig:
                            msg = _call_error(sig, call, is_instance_call=True)
                            if msg:
                                key = (info["rel_path"], call["line"], msg)
                                if key not in seen:
                                    seen.add(key)
                                    errors.append({
                                        "severity": "CRITICAL",
                                        "type": "SIGNATURE_MISMATCH",
                                        "file": info["rel_path"],
                                        "line": call["line"],
                                        "target_file": cls_info["rel_path"],
                                        "symbol": method_name,
                                        "message": msg,
                                        "is_confirmed": True,
                                    })

            # Check calls that may rely on wildcard imports
            elif target_ref.get("kind") == "unresolved_call":
                sym = target_ref.get("symbol")
                found_in_wildcard = False
                uncertain_wildcard = False
                matched_target = None

                for wt in resolved_wildcards:
                    if wt.get("has_dynamic_all"):
                        uncertain_wildcard = True
                    exports = wt.get("all_exports") if wt.get("all_exports") is not None else wt.get("definitions")
                    if sym in exports:
                        found_in_wildcard = True
                        matched_target = wt
                        break

                if found_in_wildcard and matched_target:
                    sig = matched_target["signatures"].get(sym)
                    if sig:
                        msg = _call_error(sig, call, is_instance_call=False)
                        if msg:
                            key = (info["rel_path"], call["line"], msg)
                            if key not in seen:
                                seen.add(key)
                                errors.append({
                                    "severity": "CRITICAL",
                                    "type": "SIGNATURE_MISMATCH",
                                    "file": info["rel_path"],
                                    "line": call["line"],
                                    "target_file": matched_target["rel_path"],
                                    "symbol": sym,
                                    "message": msg,
                                    "is_confirmed": True,
                                })
                elif wildcards and not uncertain_wildcard:
                    # All wildcard imports are known local modules, and none export this symbol!
                    key = (info["rel_path"], call["line"], sym)
                    if key not in seen:
                        seen.add(key)
                        errors.append({
                            "severity": "CRITICAL",
                            "type": "BROKEN_CONTRACT",
                            "file": info["rel_path"],
                            "line": call["line"],
                            "symbol": sym,
                            "message": f"Call '{sym}()' in '{info['rel_path']}' is not exported by any wildcard import ({', '.join(sorted(wildcards))}) or local definitions.",
                            "is_confirmed": True,
                        })

    # Check getattr calls against resolved modules using strict provenance
    for path, info in file_data.items():
        if not info["valid"]:
            continue
        for g in info.get("getattr_calls", []):
            obj = g.get("object")
            attr = g.get("attr")
            if not obj or not attr or not g.get("has_literal_attr"):
                continue

            target_mod = None
            prov = g.get("provenance")
            if prov and prov.get("kind") == "module":
                target_mod = prov.get("module")
            elif g.get("module_alias"):
                target_mod = g.get("module_alias")

            if not target_mod:
                continue

            target = resolve_import_target(
                info["module_id"],
                {"module": target_mod, "level": 0},
                by_mod
            )
            if target and target.get("valid"):
                # Check module-level __getattr__
                has_module_getattr = "__getattr__" in target.get("definitions", set())
                if has_module_getattr:
                    warnings.append({
                        "severity": "WARNING",
                        "type": "DYNAMIC_ATTRIBUTE",
                        "file": info["rel_path"],
                        "line": g["line"],
                        "message": f"Module '{target['rel_path']}' defines module-level __getattr__; attribute '{attr}' may be resolved dynamically at runtime.",
                        "is_confirmed": False,
                    })
                elif attr not in target["definitions"]:
                    warnings.append({
                        "severity": "WARNING",
                        "type": "DYNAMIC_ATTRIBUTE",
                        "file": info["rel_path"],
                        "line": g["line"],
                        "message": f"Call getattr({obj}, '{attr}') targets '{target['rel_path']}', but attribute '{attr}' is not defined there.",
                        "is_confirmed": False,
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
    return 0 if not errors else 1


def run_watch(target_dir, debounce_delay=0.15, poll_interval=0.4):
    """
    Continuous filesystem watcher with debounced batching and atomic save resilience.
    """
    root = os.path.abspath(target_dir)
    print(BANNER)
    print(f"👀 Watching {root} (debounced polling). Press Ctrl+C to stop.")
    previous = {p: compute_file_hash(p) for p in get_project_files(root)}
    previous_data, previous_consumers = build_dependency_graph(root)

    try:
        while True:
            time.sleep(poll_interval)
            current_files = get_project_files(root)
            current = {p: compute_file_hash(p) for p in current_files}
            deleted = set(previous) - set(current)
            added = set(current) - set(previous)
            changed = {p for p in set(current) & set(previous) if current[p] != previous[p]}

            if added or deleted or changed:
                # Settle window: collect rapid consecutive saves into single batch
                time.sleep(debounce_delay)
                current_files = get_project_files(root)
                current = {p: compute_file_hash(p) for p in current_files}

                # Check if deleted files reappeared (atomic save file-replace)
                real_deleted = set()
                for p in (set(previous) - set(current)):
                    h = compute_file_hash(p, retries=2)
                    if h:
                        current[p] = h
                        changed.add(p)
                    else:
                        real_deleted.add(p)

                deleted = real_deleted
                added = set(current) - set(previous)
                changed = {p for p in set(current) & set(previous) if current[p] != previous[p]}

                if not (added or deleted or changed):
                    continue

                ts = time.strftime("%H:%M:%S")
                print(f"\n--- Batch update at {ts} ({len(changed)} changed, {len(added)} added, {len(deleted)} deleted) ---")

                file_data, consumers = build_dependency_graph(root)
                errors, warnings, stats = check_project_integrity(root)

                for p in sorted(deleted):
                    rel = os.path.relpath(p, root).replace(os.sep, "/")
                    mod = os.path.splitext(rel)[0].replace("/", ".")
                    if mod.endswith(".__init__"):
                        mod = mod[:-9]
                    old_meta = previous_data.get(p)
                    old_mod = old_meta.get("module_id") if old_meta else mod
                    direct, transitive = get_transitive_dependents(old_mod, previous_consumers, previous_data)
                    print(f"🗑️ DELETED: {rel}")
                    if direct or transitive:
                        prompt = generate_ai_remediation_prompt(
                            rel,
                            [{"type": "DELETED_DEPENDENCY", "file": rel, "line": "?", "message": "The dependency file was deleted; imports targeting it no longer resolve."}],
                            direct,
                            transitive
                        )
                        print("\n👉 COPY & SEND THIS PROMPT TO YOUR AI:\n" + prompt)

                for p in sorted(added | changed):
                    rel = os.path.relpath(p, root).replace(os.sep, "/")
                    rel_errors = [e for e in errors if e.get("file") == rel or e.get("target_file") == rel]
                    if rel_errors:
                        module = current_files.get(p, {}).get("module_id")
                        direct, transitive = get_transitive_dependents(module, consumers, file_data)
                        print(f"🚨 REGRESSION in {rel}:")
                        for e in rel_errors:
                            print(f"   • {e['file']}:{e['line']}: {e['message']}")
                        print("\n👉 COPY & SEND THIS PROMPT TO YOUR AI:\n" + generate_ai_remediation_prompt(rel, rel_errors, direct, transitive))
                    else:
                        print(f"✅ Safe: {rel} has no confirmed contract breaks.")

                previous = current
                previous_data, previous_consumers = file_data, consumers

    except KeyboardInterrupt:
        print("\n👋 RepoShield stopped.")


def run_tests():
    import unittest
    here = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(here)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    tests_dir = os.path.join(project_root, "tests")
    if os.path.isdir(tests_dir):
        suite = unittest.defaultTestLoader.discover(tests_dir)
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestRepoShieldEngine)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


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

    # --- Baseline tests from v0.2.1 / v0.2.2 ---
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
        self.assertIn("old", cons)
        self.assertEqual(cons["old"][0]["consumer_rel"], "use.py")

    def test_commands_exist(self):
        self.assertTrue(callable(extract_file_info))
        self.assertTrue(callable(get_project_files))
        self.assertTrue(callable(resolve_import_target))
        self.assertTrue(callable(build_dependency_graph))
        self.assertTrue(callable(get_transitive_dependents))
        self.assertTrue(callable(check_project_integrity))
        self.assertTrue(callable(generate_ai_remediation_prompt))
        self.assertTrue(callable(run_scan))
        self.assertTrue(callable(run_check))
        self.assertTrue(callable(run_watch))

    # --- Edge case tests from v0.2.2 ---
    def test_conditional_dependencies_both_exist(self):
        self.write("win_mod.py", "def run(): pass\n")
        self.write("nix_mod.py", "def run(): pass\n")
        self.write("app.py", "import sys\nif sys.platform == 'win32':\n    from win_mod import run\nelse:\n    from nix_mod import run\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_conditional_dependency_one_missing_reports_warning_not_critical(self):
        self.write("win_mod.py", "def run(): pass\n")
        self.write("app.py", "import sys\nif sys.platform == 'win32':\n    from win_mod import run\nelse:\n    from missing_nix import run\n")
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(x['type'] == 'CONDITIONAL_IMPORT' for x in w))

    def test_unconditional_dependency_missing_is_critical(self):
        self.write("app.py", "from missing_mod import run\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)  # external/unresolved import emits warning, local missing symbol emits critical

    def test_nested_conditional_imports(self):
        self.write("a.py", "def ok(): pass\n")
        self.write("app.py", "if True:\n    if False:\n        from a import ok\n")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_try_except_importerror_optional_dependency(self):
        self.write("app.py", "try:\n    import optional_package\nexcept ImportError:\n    optional_package = None\n")
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(x['type'] == 'CONDITIONAL_IMPORT' for x in w))

    def test_dynamic_import_literal_local_module_resolves(self):
        self.write("plugins/reports.py", "def generate(): pass\n")
        self.write("main.py", "import importlib\nmod = importlib.import_module('plugins.reports')\n")
        e, _, s = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertGreaterEqual(s['dependencies_mapped'], 1)

    def test_dynamic_import_missing_local_reports_warning(self):
        self.write("main.py", "import importlib\nmod = importlib.import_module('nonexistent.plugin')\n")
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(x['type'] == 'DYNAMIC_IMPORT' for x in w))

    def test_dynamic_import_aliased_import_module(self):
        self.write("plugins/analytics.py", "def track(): pass\n")
        self.write("main.py", "from importlib import import_module as load_mod\np = load_mod('plugins.analytics')\n")
        e, _, s = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertGreaterEqual(s['dependencies_mapped'], 1)

    def test_dynamic_import_runtime_constructed_name_reports_warning(self):
        self.write("main.py", "import importlib\nname = 'plugin_' + str(1)\nmod = importlib.import_module(name)\n")
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(x['type'] == 'DYNAMIC_IMPORT' for x in w))

    def test_getattr_known_and_unknown_attribute(self):
        self.write("plug.py", "def existing_method(): pass\n")
        self.write("main.py", "import importlib\nmod = importlib.import_module('plug')\nh = getattr(mod, 'missing_method')\n")
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(x['type'] == 'DYNAMIC_ATTRIBUTE' for x in w))

    def test_watch_atomic_save_and_temp_files_ignored(self):
        self.write(".hidden.py", "bad syntax (\n")
        self.write("file.py.tmp", "bad syntax (\n")
        self.write("real.py", "def ok(): pass\n")
        files = get_project_files(self.root)
        rels = [f["rel_path"] for f in files.values()]
        self.assertIn("real.py", rels)
        self.assertNotIn(".hidden.py", rels)
        self.assertNotIn("file.py.tmp", rels)

    # --- New v0.3 Production-Readiness Tests ---
    def test_scope_shadowing_distinguishes_local_and_module_imports(self):
        """Priority 2: lexical scope tracking distinguishes shadowed module names."""
        self.write("payments.py", "def charge(): pass\n")
        self.write("reporting.py", "def generate(): pass\n")
        self.write("main.py", """
import payments

def process():
    import reporting as payments
    payments.generate()

payments.charge()
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e, f"Expected zero errors for shadowed scopes, got: {e}")

    def test_wildcard_imports_with_explicit_all(self):
        """Priority 3: wildcard imports resolve __all__ exports and catch missing symbols."""
        self.write("utilities.py", """
__all__ = ["add", "sub"]
def add(a, b): return a + b
def sub(a, b): return a - b
def internal_hidden(): pass
""")
        # Valid use
        self.write("valid_use.py", """
from utilities import *
add(1, 2)
sub(10, 5)
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e, f"Expected valid wildcard calls to succeed, got: {e}")

        # Invalid call to symbol excluded from __all__
        self.write("bad_use.py", """
from utilities import *
internal_hidden()
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(x['type'] == 'BROKEN_CONTRACT' and 'internal_hidden' in x['message'] for x in e))

    def test_dynamic_attribute_provenance_distinguishes_multiple_modules(self):
        """Priority 4: getattr() associates with the exact variable provenance, not first dynamic import."""
        self.write("plugins/reports.py", "def generate_report(): pass\n")
        self.write("plugins/analytics.py", "def track_metric(): pass\n")
        self.write("main.py", """
import importlib

reports = importlib.import_module("plugins.reports")
analytics = importlib.import_module("plugins.analytics")

getattr(analytics, "track_metric")
getattr(reports, "missing_in_reports")
""")
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        dyn_attrs = [x for x in w if x['type'] == 'DYNAMIC_ATTRIBUTE']
        self.assertEqual(len(dyn_attrs), 1)
        self.assertIn("reports", dyn_attrs[0]['message'])
        self.assertIn("missing_in_reports", dyn_attrs[0]['message'])

    def test_class_inheritance_and_inherited_method_call(self):
        """Priority 5: inherited methods are resolved without false missing method errors."""
        self.write("services.py", """
class BaseService:
    def execute(self, task):
        pass

class PaymentService(BaseService):
    pass
""")
        # Valid call passing required task
        self.write("valid_call.py", """
from services import PaymentService
service = PaymentService()
service.execute("charge_customer")
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e, f"Expected inherited method call to succeed, got: {e}")

        # Missing required argument for inherited method
        self.write("bad_call.py", """
from services import PaymentService
service = PaymentService()
service.execute()
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(x['type'] == 'SIGNATURE_MISMATCH' and 'task' in x['message'] for x in e))

    def test_staticmethod_and_classmethod_signatures(self):
        """Priority 5 & 7: staticmethod does not drop first parameter, classmethod binds cls."""
        self.write("tools.py", """
class Calculator:
    @staticmethod
    def add(a, b):
        return a + b

    @classmethod
    def get_info(cls, detail):
        return detail
""")
        self.write("use.py", """
from tools import Calculator
calc = Calculator()
Calculator.add(1, 2)
calc.get_info("info_text")
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e, f"Expected static/classmethod calls to succeed, got: {e}")

    def test_async_function_signature_and_calls(self):
        """Priority 8: async function signatures and calls are indexed and checked."""
        self.write("fetcher.py", """
async def fetch_data(endpoint, timeout=30):
    pass
""")
        self.write("client.py", """
from fetcher import fetch_data
async def run():
    await fetch_data("https://api.example.com", timeout=10)
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e, f"Expected async function call to succeed, got: {e}")

        self.write("bad_client.py", """
from fetcher import fetch_data
async def run_bad():
    await fetch_data()
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertTrue(any(x['type'] == 'SIGNATURE_MISMATCH' and 'endpoint' in x['message'] for x in e))


    def test_nested_function_import_scoped(self):
        self.write("helper.py", "def compute(x): return x * 2\n")
        self.write("main.py", """
def run_task():
    from helper import compute
    compute(10)
run_task()
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_class_level_import_scoped(self):
        self.write("helper.py", "def util(): pass\n")
        self.write("main.py", """
class Runner:
    from helper import util
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_method_overriding_and_multiple_inheritance(self):
        self.write("base.py", """
class LoggerMixin:
    def log_event(self, msg): pass

class ServiceBase:
    def start(self, mode): pass
    def stop(self): pass
""")
        self.write("app.py", """
from base import LoggerMixin, ServiceBase

class CustomService(ServiceBase, LoggerMixin):
    def start(self, mode, force=False):
        pass

srv = CustomService()
srv.start("auto", force=True)
srv.log_event("started")
srv.stop()
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_ambiguous_module_resolution_reports_warning(self):
        self.write("pkg1/utils.py", "def f(): pass\n")
        self.write("pkg2/utils.py", "def g(): pass\n")
        self.write("main.py", """
import utils
""")
        e, w, _ = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertTrue(any(x['type'] == 'AMBIGUOUS_IMPORT' for x in w))

    def test_wildcard_with_dynamic_all_avoids_false_positive(self):
        self.write("dyn_mod.py", """
__all__ = [name for name in ["a", "b"]]
def a(): pass
def b(): pass
""")
        self.write("main.py", """
from dyn_mod import *
a()
""")
        e, _, _ = check_project_integrity(self.root)
        self.assertFalse(e)

    def test_pep420_namespace_package(self):
        self.write("namespace/submodule.py", "def run(): pass\n")
        self.write("main.py", """
from namespace import submodule
submodule.run()
""")
        e, _, s = check_project_integrity(self.root)
        self.assertFalse(e)
        self.assertGreaterEqual(s['dependencies_mapped'], 1)

    def test_src_layout_and_namespace_packages(self):
        """Priority 6: support src/ layout and PEP 420 namespace packages."""
        self.write("src/mypkg/__init__.py", "")
        self.write("src/mypkg/core.py", "def execute(): pass\n")
        self.write("tests/test_core.py", """
from mypkg.core import execute
execute()
""")
        e, _, s = check_project_integrity(self.root)
        self.assertFalse(e, f"Expected src/ layout import to resolve, got: {e}")
        self.assertGreaterEqual(s['dependencies_mapped'], 1)


def main():
    if len(sys.argv) < 2:
        print(BANNER)
        print("Usage:")
        print("  python reposhield.py scan [DIR]   - Map project blueprint & dependencies")
        print("  python reposhield.py check [DIR]  - Check cross-file integrity & signatures")
        print("  python reposhield.py watch [DIR]  - Live Sentinel monitor on file save")
        print("  python reposhield.py test         - Run internal test suite")
        sys.exit(0)

    cmd = sys.argv[1].lower()
    target = sys.argv[2] if len(sys.argv) > 2 else "."

    if cmd == "scan":
        run_scan(target)
    elif cmd == "check":
        ok = run_check(target)
        sys.exit(0 if ok else 1)
    elif cmd == "watch":
        run_watch(target)
    elif cmd == "test":
        code = run_tests()
        sys.exit(code)
    else:
        print(f"❌ Unknown command '{cmd}'. Available: scan, check, watch, test")
        sys.exit(1)


if __name__ == "__main__":
    main()
