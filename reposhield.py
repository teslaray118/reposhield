import ast
import os
import sys
import time
import argparse

BANNER = """
======================================================
  🛡️  REPOSHIELD — AI Code Safety & Impact Sentinel
======================================================
"""

def extract_file_info(filepath):
    result = {
        "valid": False,
        "error": None,
        "definitions": set(),
        "imports": []
    }
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            code = f.read()
        tree = ast.parse(code, filename=filepath)
        result["valid"] = True
    except SyntaxError as e:
        result["error"] = f"Syntax error at line {e.lineno}: {e.msg}"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            result["definitions"].add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result["definitions"].add(target.id)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                result["imports"].append({
                    "module": mod,
                    "name": alias.name,
                    "asname": alias.asname or alias.name,
                    "line": node.lineno
                })
        elif isinstance(node, ast.Import):
            for alias in node.names:
                result["imports"].append({
                    "module": alias.name,
                    "name": "*",
                    "asname": alias.asname or alias.name,
                    "line": node.lineno
                })
    return result

def get_project_files(target_dir):
    ignore_dirs = {".git", "__pycache__", "venv", ".venv", "env", "node_modules", ".pytest_cache"}
    py_files = {}
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for f in files:
            if f.endswith(".py") and f != "reposhield.py":
                full_path = os.path.abspath(os.path.join(root, f))
                rel_path = os.path.relpath(full_path, target_dir)
                mod_name = os.path.splitext(os.path.basename(f))[0]
                py_files[full_path] = {
                    "rel_path": rel_path,
                    "mod_name": mod_name,
                    "mtime": os.path.getmtime(full_path)
                }
    return py_files

def build_dependency_graph(target_dir):
    py_files = get_project_files(target_dir)
    file_data = {}
    for path, meta in py_files.items():
        info = extract_file_info(path)
        info.update(meta)
        file_data[path] = info

    consumers = {}
    for path, info in file_data.items():
        if not info["valid"]:
            continue
        for imp in info["imports"]:
            mod = imp["module"].split(".")[0]
            if mod not in consumers:
                consumers[mod] = []
            consumers[mod].append({
                "consumer_path": path,
                "consumer_rel": info["rel_path"],
                "name": imp["name"],
                "line": imp["line"]
            })
    return file_data, consumers

def run_scan(target_dir):
    print(f"\n📂 Scanning project at: {os.path.abspath(target_dir)}")
    file_data, consumers = build_dependency_graph(target_dir)

    print(f"📄 Found {len(file_data)} Python source files.\n")
    print("📦 EXPORTED DEFINITIONS:")
    for path, info in file_data.items():
        defs = sorted(list(info["definitions"])) if info["valid"] else [f"⚠️ {info['error']}"]
        print(f"  • {info['rel_path']}: {', '.join(defs[:6])}{' ...' if len(defs) > 6 else ''}")

    print("\n🔗 CROSS-FILE DEPENDENCIES:")
    has_dep = False
    for mod, user_list in consumers.items():
        matching = [p for p, d in file_data.items() if d["mod_name"] == mod]
        if matching:
            has_dep = True
            for u in user_list:
                print(f"  • {u['consumer_rel']} (line {u['line']}) imports '{u['name']}' from '{mod}.py'")
    if not has_dep:
        print("  • No internal cross-file dependencies found.")
    print("\n✅ Scan complete.")

def run_check(target_dir):
    print(f"\n🔍 Checking integrity of project at: {os.path.abspath(target_dir)}")
    file_data, consumers = build_dependency_graph(target_dir)
    errors = []

    for path, info in file_data.items():
        if not info["valid"]:
            errors.append(f"❌ Syntax Error in '{info['rel_path']}': {info['error']}")

    for mod, user_list in consumers.items():
        matching = [p for p, d in file_data.items() if d["mod_name"] == mod]
        if not matching:
            continue
        target_info = file_data[matching[0]]
        if not target_info["valid"]:
            continue
        for u in user_list:
            if u["name"] != "*" and u["name"] not in target_info["definitions"]:
                errors.append(
                    f"🚨 Broken Contract: '{u['consumer_rel']}' needs '{u['name']}' from '{mod}.py', but it does not exist!"
                )

    if errors:
        print("\n⚠️ ISSUES FOUND:")
        for err in errors:
            print(f"  {err}")
        return False
    else:
        print("🎉 ALL DEPENDENCIES CONNECTED & HEALTHY!")
        return True

def run_watch(target_dir):
    print(BANNER)
    print(f"👀 RepoShield Sentinel is watching: {os.path.abspath(target_dir)}")
    print("👉 Edit & save files. RepoShield will alert you if an AI code change breaks downstream code.\n")
    print("Press Ctrl+C to stop.\n" + "-" * 54)

    file_meta = get_project_files(target_dir)

    while True:
        try:
            time.sleep(1)
            current_meta = get_project_files(target_dir)
            changed_path = None

            for path, meta in current_meta.items():
                if path not in file_meta:
                    changed_path = path
                    break
                elif meta["mtime"] > file_meta[path]["mtime"]:
                    changed_path = path
                    break

            file_meta = current_meta

            if changed_path:
                rel = os.path.relpath(changed_path, target_dir)
                curr_time = time.strftime('%H:%M:%S')
                print(f"\n[{curr_time}] 💾 File change detected: {rel}")

                file_data, consumers = build_dependency_graph(target_dir)
                target_info = file_data.get(changed_path)

                if target_info and not target_info["valid"]:
                    print(f"🚨 SYNTAX ERROR in '{rel}': {target_info['error']}")
                    mod_name = target_info["mod_name"]
                    downstream = consumers.get(mod_name, [])
                    if downstream:
                        affected = ", ".join(set(d["consumer_rel"] for d in downstream))
                        print(f"💥 DOWNSTREAM IMPACT: {affected} will fail immediately!")
                        print("\n👉 COPY & SEND THIS PROMPT TO THE AI:")
                        print(f'   "Your update to {rel} has a syntax error: {target_info["error"]}. This breaks downstream files ({affected}). Please fix the syntax while keeping the implementation intact."\n')
                    continue

                mod_name = os.path.splitext(os.path.basename(changed_path))[0]
                downstream = consumers.get(mod_name, [])
                broken_deps = []
                for d in downstream:
                    if d["name"] != "*" and d["name"] not in target_info["definitions"]:
                        broken_deps.append(d)

                if broken_deps:
                    print(f"🚨 REGRESSION DETECTED: Changes in '{rel}' broke dependent files!")
                    for b in broken_deps:
                        print(f"💥 CASUALTY: '{b['consumer_rel']}' expects '{b['name']}()' from {rel}, but it was removed!")

                    missing_str = ", ".join(sorted(list(set(f"'{b['name']}'" for b in broken_deps))))
                    affected_str = ", ".join(sorted(list(set(b["consumer_rel"] for b in broken_deps))))
                    print("\n👉 COPY & SEND THIS PROMPT TO THE AI:")
                    print(f'   "Your update to {rel} broke existing connections. The following functions/exports must remain available: {missing_str} (needed by {affected_str}). Please update {rel} to preserve backward compatibility while adding your new features."\n')
                else:
                    print(f"✅ Safe save: '{rel}' intact, all cross-file dependencies satisfied.")

        except KeyboardInterrupt:
            print("\n👋 RepoShield Sentinel stopped.")
            sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="RepoShield — AI Code Safety & Dependency Sentinel")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    p_scan = subparsers.add_parser("scan", help="Scan repository and map dependencies")
    p_scan.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current directory)")

    p_check = subparsers.add_parser("check", help="Check for syntax or broken import regressions")
    p_check.add_argument("path", nargs="?", default=".", help="Directory to check (default: current directory)")

    p_watch = subparsers.add_parser("watch", help="Watch project live on save")
    p_watch.add_argument("path", nargs="?", default=".", help="Directory to watch (default: current directory)")

    args = parser.parse_args()

    target = getattr(args, "path", ".")
    if args.command == "scan":
        run_scan(target)
    elif args.command == "check":
        run_check(target)
    elif args.command == "watch":
        run_watch(target)
    else:
        run_scan(target)
        run_check(target)

if __name__ == "__main__":
    main()
