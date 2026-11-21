import os
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
from reposhield.cli import main


class TestCompatibility(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_public_api_exports_exist(self):
        expected_exports = [
            "VERSION",
            "extract_file_info",
            "get_project_files",
            "resolve_import_target",
            "build_dependency_graph",
            "get_transitive_dependents",
            "check_project_integrity",
            "generate_ai_remediation_prompt",
            "run_scan",
            "run_check",
            "run_watch",
            "run_tests",
            "main",
        ]
        for exp in expected_exports:
            self.assertTrue(hasattr(reposhield, exp), f"Missing public export: {exp}")

    def test_cli_help_and_version(self):
        self.assertEqual(main(["--version"]), 0)
        self.assertEqual(main(["--help"]), 0)

    def test_water_distribution_baseline(self):
        pipes = os.path.join(self.test_dir, "pipes.py")
        village = os.path.join(self.test_dir, "village.py")
        school = os.path.join(self.test_dir, "school.py")

        with open(pipes, "w") as f:
            f.write(
                "def supply_water(household_id, liters=50):\n"
                "    print(f'Pumping {liters}L to {household_id}')\n\n"
                "def deliver_water(target_facility, liters=500, pressure_psi=45.0):\n"
                "    supply_water(target_facility, liters=liters)\n"
            )
        with open(village, "w") as f:
            f.write("from pipes import supply_water\nsupply_water(1)")
        with open(school, "w") as f:
            f.write("from pipes import deliver_water\ndeliver_water('School')")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertEqual(crits, [])

    def test_water_distribution_deliberate_regression(self):
        pipes = os.path.join(self.test_dir, "pipes.py")
        school = os.path.join(self.test_dir, "school.py")

        # Deliberately remove deliver_water
        with open(pipes, "w") as f:
            f.write("def supply_water(household_id, liters=50): pass")
        with open(school, "w") as f:
            f.write("from pipes import deliver_water\ndeliver_water('School')")

        errors, warnings, stats = check_project_integrity(self.test_dir)
        crits = errors
        self.assertTrue(len(crits) >= 1)
        file_data, consumers = build_dependency_graph(self.test_dir)
        direct, trans = get_transitive_dependents(pipes, consumers, file_data)
        prompt = generate_ai_remediation_prompt(pipes, crits, direct, trans)
        self.assertIn("deliver_water", prompt)


if __name__ == "__main__":
    unittest.main()
