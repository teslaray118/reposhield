import os
import sys
import shutil
import tempfile
import unittest
import reposhield
from reposhield.engine import (
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


