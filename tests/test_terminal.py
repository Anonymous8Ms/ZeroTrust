"""Exercise terminal home actions through the public command line."""

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]


def open_home(choices, env):
    return subprocess.run(
        [sys.executable, "-B", str(ROOT / "main.py"), "--interactive"],
        input=choices, env=env, capture_output=True, text=True, check=True,
    ).stdout


class TerminalTests(unittest.TestCase):
    def test_demo_runs_without_an_environment_key(self):
        with TemporaryDirectory() as tmp:
            env = {**os.environ, "TMPDIR": tmp}
            env.pop("RAKSHA_SECRET", None)
            display = open_home("1\n2\n0\n", env)
            demo, = Path(tmp).glob("zerotrust-demo-*")

            self.assertIn("Z E R O T R U S T", display)
            self.assertIn("Set RAKSHA_SECRET", display)
            self.assertIn("Completed with quarantined files", display)
            self.assertEqual({entry.name for entry in demo.iterdir()},
                             {"sanitized", "report.json", "records.jsonl"})
            self.assertNotIn("Asha Demo", display)

    def test_run_from_menu_and_reopen_summary(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            source = ROOT / "tests" / "fixtures" / "input"
            report_path = output / "report.json"
            env = {**os.environ, "RAKSHA_SECRET": "synthetic-terminal-key"}
            display = open_home(f"1\n{source}\n{output}\n3\n{report_path}\n0\n", env)
            report = json.loads(report_path.read_text(encoding="utf-8"))

            self.assertEqual(report["counts"]["files_sanitized"], 3)
            self.assertEqual(display.count("Files quarantined"), 2)
            self.assertNotIn("synthetic-terminal-key", display)
            self.assertNotIn("registration.csv", display)
