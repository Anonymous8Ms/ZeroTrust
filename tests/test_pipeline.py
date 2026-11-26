"""Exercise the organiser's real CLI on team-generated synthetic records."""
import csv
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "tests" / "fixtures" / "input"


def run(output, key):
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--input", str(INPUT),
         "--output", str(output)],
        env={**os.environ, "RAKSHA_SECRET": key},
        check=True, capture_output=True, text=True,
    )


def rows(path):
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def report(path):
    return json.loads((path / "report.json").read_text())


def stable_output(path):
    files = {
        file.relative_to(path).as_posix(): file.read_bytes()
        for file in path.rglob("*") if file.is_file() and file.name != "report.json"
    }
    audit = report(path)
    del audit["timing"], audit["resources"]
    return files, audit


def unique_records(records):
    demographics = [(row["age"], row["location"]) for row in records]
    return sum(demographics.count(pair) == 1 for pair in demographics)


class PipelineTest(unittest.TestCase):
    def test_synthetic_handoff(self):
        with TemporaryDirectory() as directory:
            first, repeat, rotated = (Path(directory) / run_name
                                      for run_name in ("first", "repeat", "rotated"))
            execution = run(first, "synthetic-demo-secret-a")
            run(repeat, "synthetic-demo-secret-a")
            run(rotated, "synthetic-demo-secret-b")
            export = first / "sanitized"
            registration = rows(export / "registration.csv")
            rotated_rows = rows(rotated / "sanitized" / "registration.csv")
            note = (export / "hindi.txt").read_text()
            ambiguous = (export / "ambiguous.txt").read_text()
            audit = report(first)
            files, _ = stable_output(first)

            self.assertEqual(stable_output(first), stable_output(repeat))
            for row, changed in zip(registration, rotated_rows):
                self.assertNotEqual(row["patient_name"], changed["patient_name"])
                self.assertNotEqual(row["admitted"], changed["admitted"])
                self.assertEqual(
                    (date.fromisoformat(row["discharged"]) -
                     date.fromisoformat(row["admitted"])).days, 9,
                )
            self.assertIn(registration[0]["patient_name"], note)
            self.assertIn(registration[0]["admitted"], note)
            self.assertIn(registration[0]["discharged"], note)
            self.assertNotEqual(registration[0]["patient_name"], registration[1]["patient_name"])
            self.assertIn("BP 150/90; Dolo 650 BD", note)
            self.assertEqual([row["diagnosis"] for row in registration], ["dengue", "dengue"])
            self.assertEqual([row["age"] for row in registration], ["40-49", "40-49"])
            dates = [date.fromisoformat(line.rsplit(" ", 1)[1])
                     for line in ambiguous.splitlines() if line.startswith(("Admission:", "Discharge:"))]
            self.assertEqual((dates[1] - dates[0]).days, 9)

            mapping = [json.loads(line) for line in files["records.jsonl"].splitlines()]
            by_location = {(entry["file"], entry["loc"]): entry["patient"] for entry in mapping}
            self.assertEqual(by_location[("sanitized/hindi.txt", "doc")],
                             by_location[("sanitized/registration.csv", "row:0")])
            self.assertIsNone(by_location[("sanitized/ambiguous.txt", "doc")])
            self.assertEqual(len(mapping), 4)
            self.assertEqual(audit["counts"]["records_linked"], 3)
            self.assertEqual(audit["counts"]["identifiers_detected"], 9)
            self.assertEqual(audit["counts"]["files_quarantined"], 1)
            self.assertEqual(audit["counts"]["files_sanitized"], 3)
            self.assertEqual(
                {entry["input_sha256"] for entry in audit["files"]},
                {hashlib.sha256(file.read_bytes()).hexdigest() for file in INPUT.iterdir()},
            )
            self.assertFalse((export / "malformed.csv").exists())

            observable = b"\n".join((*files.values(), json.dumps(audit).encode(),
                                     execution.stdout.encode(), execution.stderr.encode()))
            for marker in ("Asha Demo", "आशा डेमो", "00000 00101", "00000 00102",
                           "FIX-A", "FIX-B", "Example Village East", "Example Village West",
                           "synthetic-demo-secret-a"):
                self.assertNotIn(marker.encode(), observable)
            self.assertEqual(unique_records(rows(INPUT / "registration.csv")), 2)
            self.assertEqual(unique_records(registration), 0)
            self.assertGreater(audit["timing"]["seconds"], 0)
            self.assertGreater(audit["resources"]["peak_rss_mb"], 0)


if __name__ == "__main__":
    unittest.main()
