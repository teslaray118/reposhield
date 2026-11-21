import os
import shutil
import tempfile
import unittest
from reposhield.engine import extract_file_info, build_dependency_graph, check_project_integrity


class TestDynamic(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_provenance_invalidation_on_reassignment(self):
        # Critical test: module = import_module(...) followed by module = None must invalidate provenance!
        file_path = os.path.join(self.test_dir, "dyn.py")
        with open(file_path, "w") as f:
            f.write(
                "import importlib\n"
                "module = importlib.import_module('plugins.reports')\n"
                "module = None\n"
                "getattr(module, 'missing_method')\n"
            )

        info = extract_file_info(file_path)
        getattr_calls = info["getattr_calls"]
        self.assertEqual(len(getattr_calls), 1)
        # Provenance must be None because module was reassigned to None
        self.assertIsNone(getattr_calls[0]["provenance"])

    def test_dynamic_import_literal_local_resolves(self):
        with open(os.path.join(self.test_dir, "plugin.py"), "w") as f:
            f.write("def run(): pass")
        with open(os.path.join(self.test_dir, "main.py"), "w") as f:
            f.write("import importlib\nmod = importlib.import_module('plugin')")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_try_except_conditional_import_is_warning_not_critical(self):
        with open(os.path.join(self.test_dir, "optional.py"), "w") as f:
            f.write("try:\n    import non_existent_library\nexcept ImportError:\n    non_existent_library = None")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])


if __name__ == "__main__":
    unittest.main()
