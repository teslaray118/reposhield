import os
import shutil
import tempfile
import unittest
from reposhield.engine import build_dependency_graph, check_project_integrity


class TestInheritance(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_three_level_recursive_inheritance(self):
        with open(os.path.join(self.test_dir, "classes.py"), "w") as f:
            f.write(
                "class A:\n"
                "    def execute(self, task):\n"
                "        pass\n\n"
                "class B(A):\n"
                "    pass\n\n"
                "class C(B):\n"
                "    pass\n"
            )
        with open(os.path.join(self.test_dir, "caller.py"), "w") as f:
            f.write("from classes import C\nobj = C()\nobj.execute('build')")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_method_overriding_and_c3_mro(self):
        with open(os.path.join(self.test_dir, "mro.py"), "w") as f:
            f.write(
                "class A:\n"
                "    def run(self, x):\n"
                "        pass\n\n"
                "class B(A):\n"
                "    def run(self, x, y):\n"
                "        pass\n\n"
                "class C(B):\n"
                "    pass\n"
            )
        with open(os.path.join(self.test_dir, "consumer.py"), "w") as f:
            f.write("from mro import C\ninst = C()\ninst.run(1, 2)")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_multiple_inheritance_diamond(self):
        with open(os.path.join(self.test_dir, "diamond.py"), "w") as f:
            f.write(
                "class Base:\n"
                "    def ping(self):\n"
                "        pass\n\n"
                "class Left(Base):\n"
                "    def ping(self):\n"
                "        pass\n\n"
                "class Right(Base):\n"
                "    pass\n\n"
                "class Child(Left, Right):\n"
                "    pass\n"
            )
        with open(os.path.join(self.test_dir, "user.py"), "w") as f:
            f.write("from diamond import Child\nc = Child()\nc.ping()")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])


if __name__ == "__main__":
    unittest.main()
