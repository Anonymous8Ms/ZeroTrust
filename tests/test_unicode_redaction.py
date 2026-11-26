"""Exercise Unicode name redaction through the command-line entry point."""

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]


class UnicodeRedactionTests(unittest.TestCase):
    def test_devanagari_names_with_join_controls_are_fully_replaced(self):
        doctor = "Dr. आर्\u200dया शाह"
        clinical = "BP 150/90; Dolo 650 BD"
        with TemporaryDirectory() as temp:
            source = Path(temp) / "input"
            output = Path(temp) / "output"
            source.mkdir()
            (source / "register.csv").write_text(
                "patient_name,phone,diagnosis\nAsha Demo,7000000301,asthma\n", encoding="utf-8",
            )
            controls = {
                "joiner.txt": "\u200d",
                "non-joiner.txt": "\u200c",
                "zero-width-space.txt": "\u200b",
                "direction-mark.txt": "\u200f",
                "soft-hyphen.txt": "\u00ad",
            }
            for filename, control in controls.items():
                note = (f"रोगी: {control}आ{control}शा डे{control}मो{control}\n"
                        f"फोन: 7000000301\n{doctor}\n{clinical}\n")
                (source / filename).write_text(note, encoding="utf-8")

            subprocess.run(
                [sys.executable, "-B", str(ROOT / "main.py"), "--input", str(source),
                 "--output", str(output)],
                env={**os.environ, "RAKSHA_SECRET": "synthetic-join-controls-key"},
                capture_output=True, text=True, check=True,
            )

            records = [json.loads(line) for line in
                       (output / "records.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(records), 1 + len(controls))
            mapping = {row["file"]: row["patient"] for row in records}
            audit = json.loads((output / "report.json").read_text(encoding="utf-8"))
            outputs_by_digest = {item["input_sha256"]: item["output"] for item in audit["files"]}
            register = sha256((source / "register.csv").read_bytes()).hexdigest()
            patient = mapping[outputs_by_digest[register]]
            self.assertTrue(patient.startswith("PSN-"))
            for filename in controls:
                with self.subTest(filename=filename):
                    digest = sha256((source / filename).read_bytes()).hexdigest()
                    relative = outputs_by_digest[digest]
                    lines = (output / relative).read_text(encoding="utf-8").splitlines()
                    self.assertEqual(lines, [f"रोगी: {patient}", "फोन: [REDACTED]", doctor, clinical])
                    self.assertEqual(mapping[relative], patient)
