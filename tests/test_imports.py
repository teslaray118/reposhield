import os
import shutil
import tempfile
import unittest
from reposhield.engine import extract_file_info, build_dependency_graph, check_project_integrity


class TestImports(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_absolute_and_relative_imports(self):
        pkg_dir = os.path.join(self.test_dir, "mypkg")
        sub_dir = os.path.join(pkg_dir, "sub")
        os.makedirs(sub_dir)

        with open(os.path.join(pkg_dir, "__init__.py"), "w") as f:
            f.write("# pkg init")
        with open(os.path.join(pkg_dir, "core.py"), "w") as f:
            f.write("def helper(): pass")
        with open(os.path.join(sub_dir, "__init__.py"), "w") as f:
            f.write("# sub init")
        with open(os.path.join(sub_dir, "worker.py"), "w") as f:
            f.write("from ..core import helper\nhelper()")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_pep420_namespace_packages(self):
        ns_dir = os.path.join(self.test_dir, "namespace_pkg", "component")
        os.makedirs(ns_dir)
        with open(os.path.join(ns_dir, "service.py"), "w") as f:
            f.write("def compute(): pass")
        with open(os.path.join(self.test_dir, "main.py"), "w") as f:
            f.write("from namespace_pkg.component.service import compute\ncompute()")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_src_layout(self):
        src_dir = os.path.join(self.test_dir, "src", "app")
        os.makedirs(src_dir)
        with open(os.path.join(src_dir, "__init__.py"), "w") as f:
            f.write("# init")
        with open(os.path.join(src_dir, "db.py"), "w") as f:
            f.write("def connect(): pass")
        with open(os.path.join(src_dir, "main.py"), "w") as f:
            f.write("from app.db import connect\nconnect()")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_wildcard_with_explicit_all_detects_missing(self):
        with open(os.path.join(self.test_dir, "exports.py"), "w") as f:
            f.write("__all__ = ['alpha', 'beta']\ndef alpha(): pass\n# beta missing")
        with open(os.path.join(self.test_dir, "consumer.py"), "w") as f:
            f.write("from exports import *")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        beta_err = [d for d in errors if d.get("symbol") == "beta"]
        self.assertTrue(len(beta_err) >= 1)

    def test_wildcard_with_concatenation_and_append_in_all(self):
        with open(os.path.join(self.test_dir, "dyn_all.py"), "w") as f:
            f.write("__all__ = ['a'] + ['b']\n__all__.append('c')\n__all__ += ['d']\ndef a(): pass\ndef b(): pass\ndef c(): pass\n# d missing")
        with open(os.path.join(self.test_dir, "consumer.py"), "w") as f:
            f.write("from dyn_all import *")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        d_err = [d for d in errors if d.get("symbol") == "d"]
        self.assertTrue(len(d_err) >= 1)

    def test_wildcard_with_dynamic_all_avoids_false_positive(self):
        with open(os.path.join(self.test_dir, "dyn.py"), "w") as f:
            f.write("__all__ = [x for x in ['alpha']]\ndef alpha(): pass")
        with open(os.path.join(self.test_dir, "consumer.py"), "w") as f:
            f.write("from dyn import *")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])


if __name__ == "__main__":
    unittest.main()
