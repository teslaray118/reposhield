import os
import shutil
import tempfile
import unittest
from reposhield.engine import get_project_files, compute_file_hash


class TestWatcher(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_temporary_files_are_ignored(self):
        with open(os.path.join(self.test_dir, "valid.py"), "w") as f:
            f.write("x = 1")
        with open(os.path.join(self.test_dir, "valid.py.tmp"), "w") as f:
            f.write("temp")
        with open(os.path.join(self.test_dir, ".valid.py.swp"), "w") as f:
            f.write("swap")
        with open(os.path.join(self.test_dir, "valid.py~"), "w") as f:
            f.write("backup")

        files = get_project_files(self.test_dir)
        basenames = [os.path.basename(f) for f in files]
        self.assertEqual(basenames, ["valid.py"])

    def test_file_hash_changes_on_modification(self):
        filepath = os.path.join(self.test_dir, "test.py")
        with open(filepath, "w") as f:
            f.write("a = 1")
        h1 = compute_file_hash(filepath)
        with open(filepath, "w") as f:
            f.write("a = 2")
        h2 = compute_file_hash(filepath)
        self.assertNotEqual(h1, h2)


if __name__ == "__main__":
    unittest.main()
