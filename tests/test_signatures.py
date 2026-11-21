import os
import shutil
import tempfile
import unittest
from reposhield.engine import build_dependency_graph, check_project_integrity


class TestSignatures(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_positional_and_keyword_arguments(self):
        with open(os.path.join(self.test_dir, "service.py"), "w") as f:
            f.write("def configure(host, port=8080, timeout=30): pass")
        with open(os.path.join(self.test_dir, "client.py"), "w") as f:
            f.write("from service import configure\nconfigure('localhost', port=9000)")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_missing_required_argument_detected(self):
        with open(os.path.join(self.test_dir, "service.py"), "w") as f:
            f.write("def process(item, count): pass")
        with open(os.path.join(self.test_dir, "client.py"), "w") as f:
            f.write("from service import process\nprocess('apple')")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        err = [d for d in errors if d["type"] == "SIGNATURE_MISMATCH" and "Missing required" in d["message"]]
        self.assertTrue(len(err) >= 1)

    def test_unexpected_keyword_argument_detected(self):
        with open(os.path.join(self.test_dir, "service.py"), "w") as f:
            f.write("def save(data): pass")
        with open(os.path.join(self.test_dir, "client.py"), "w") as f:
            f.write("from service import save\nsave('test', extra_flag=True)")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        err = [d for d in errors if d["type"] == "SIGNATURE_MISMATCH" and "Unexpected keyword" in d["message"]]
        self.assertTrue(len(err) >= 1)

    def test_varargs_and_kwargs_avoid_false_mismatch(self):
        with open(os.path.join(self.test_dir, "service.py"), "w") as f:
            f.write("def dispatch(*args, **kwargs): pass")
        with open(os.path.join(self.test_dir, "client.py"), "w") as f:
            f.write("from service import dispatch\ndispatch(1, 2, 3, mode='fast', flag=True)")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_async_function_signature(self):
        with open(os.path.join(self.test_dir, "async_mod.py"), "w") as f:
            f.write("async def fetch(url, retries=3): pass")
        with open(os.path.join(self.test_dir, "consumer.py"), "w") as f:
            f.write("from async_mod import fetch\nasync def run():\n    await fetch('https://example.com')")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])


if __name__ == "__main__":
    unittest.main()
