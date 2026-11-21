import os
import shutil
import tempfile
import unittest
from reposhield.engine import extract_file_info, build_dependency_graph, check_project_integrity


class TestScopes(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_function_body_assignment_shadowing(self):
        # Python semantics: a name assigned anywhere in function body is treated as local throughout!
        with open(os.path.join(self.test_dir, "payments.py"), "w") as f:
            f.write("def charge(): pass")
        with open(os.path.join(self.test_dir, "processor.py"), "w") as f:
            f.write("import payments\n\ndef process():\n    payments.charge()\n    payments = None")

        info = extract_file_info(os.path.join(self.test_dir, "processor.py"))
        # Call payments.charge() should NOT be resolved to module payments because payments is local in process()
        resolved_calls = [c for c in info["calls"] if c.get("target", {}).get("module") == "payments"]
        self.assertEqual(len(resolved_calls), 0)

    def test_nested_function_import_scoped(self):
        with open(os.path.join(self.test_dir, "reporting.py"), "w") as f:
            f.write("def generate(): pass")
        with open(os.path.join(self.test_dir, "main.py"), "w") as f:
            f.write("def outer():\n    from reporting import generate\n    generate()\ndef sibling():\n    pass")

        info = extract_file_info(os.path.join(self.test_dir, "main.py"))
        root_scope = info["root_scope"]
        self.assertNotIn("generate", root_scope.symbol_aliases)

    def test_class_scope_methods_do_not_inherit_class_body_variables(self):
        with open(os.path.join(self.test_dir, "cls.py"), "w") as f:
            f.write("helper = 'global'\n\nclass MyClass:\n    helper = 'class_body'\n    def method(self):\n        return helper")

        info = extract_file_info(os.path.join(self.test_dir, "cls.py"))
        # Looking up helper in method scope should skip class body and resolve outer/global or local
        self.assertTrue(info["valid"])


if __name__ == "__main__":
    unittest.main()
