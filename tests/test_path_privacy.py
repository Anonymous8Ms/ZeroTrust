"""Verify privacy of exported filenames, folders, and references to them."""

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PathPrivacyTests(unittest.TestCase):
    def test_private_folders_and_identifier_patterns_are_rewritten(self):
        private = {
            "notes/00123456.csv": "00123456",
            "0012-3456/ward-note.csv": "0012-3456",
            "Meera.Devi/ward-note.csv": "Meera.Devi",
            "notes/ward-4527.csv": "4527",
            "notes/bundle-AB12CD.csv": "AB12CD",
            "notes/R.K./ward-note.csv": "R.K.",
            "notes/००१२३४५६/ward-note.csv": "००१२३४५६",
            "notes/ward-20-27/ward-note.csv": "20-27",
        }
        safe = "notes/batch-02/ward-note-2026.csv"
        with TemporaryDirectory() as temp:
            source, output = Path(temp) / "input", Path(temp) / "output"
            source.mkdir()
            names_by_digest = {}
            for index, name in enumerate([*private, safe]):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                data = f"Diagnosis,Encounter\nasthma,{index}\n".encode()
                path.write_bytes(data)
                names_by_digest[sha256(data).hexdigest()] = name

            run = subprocess.run(
                [sys.executable, "-B", str(ROOT / "main.py"), "--input", str(source),
                 "--output", str(output)],
                env={**os.environ, "RAKSHA_SECRET": "synthetic-path-check"},
                capture_output=True, text=True, check=True,
            )
            audit_text = (output / "report.json").read_text()
            audit = json.loads(audit_text)
            self.assertEqual(audit["counts"]["files_sanitized"], len(names_by_digest))
            published_paths = []
            for item in audit["files"]:
                published = item["output"]
                original = names_by_digest[item["input_sha256"]]
                self.assertIn("asthma", (output / published).read_text())
                if original == safe:
                    self.assertEqual(published, f"sanitized/{safe}")
                else:
                    self.assertIn("file-", published)
                published_paths.append(published)
            visible = "\n".join(published_paths) + audit_text + (output / "records.jsonl").read_text()
            visible += run.stdout + run.stderr
            for marker in private.values():
                self.assertNotIn(marker, visible)
