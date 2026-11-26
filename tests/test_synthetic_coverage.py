"""Check the real CLI on a larger mixed-format synthetic corpus."""

from collections import Counter, defaultdict
import csv
from datetime import date
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from synthetic_coverage import generate


ROOT = Path(__file__).resolve().parents[1]


class SyntheticCoverageTests(unittest.TestCase):
    def test_150_file_corpus(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            manifest = generate(home / "corpus")
            source = home / "corpus" / "input"
            output = home / "output"
            expected = manifest["cases"]
            command = [sys.executable, "-B", str(ROOT / "main.py"), "--input", str(source),
                       "--output", str(output)]
            run = subprocess.run(command, env={**os.environ, "RAKSHA_SECRET": "synthetic-scale-key"},
                                 capture_output=True, text=True, check=True)
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            counts = report["counts"]
            self.assertEqual(counts["files_total"], 150)
            self.assertEqual(counts["files_sanitized"], 126)
            self.assertEqual(counts["records_linked"], 120)
            self.assertEqual(counts["files_quarantined"], 24)
            self.assertEqual(Counter(entry.get("reason") for entry in report["files"])["embedded_attachment"], 9)
            self.assertCountEqual(
                (entry["input_sha256"] for entry in report["files"]), expected.keys()
            )

            records = defaultdict(list)
            for line in (output / "records.jsonl").read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                records[row["file"]].append(row)
            groups = defaultdict(set)
            patient_occurrences = Counter()
            for entry in report["files"]:
                case = expected[entry["input_sha256"]]
                with self.subTest(file=case["file"]):
                    source_file = source / case["file"]
                    self.assertEqual(sha256(source_file.read_bytes()).hexdigest(), entry["input_sha256"])
                    if case["reason"]:
                        self.assertIsNone(entry["output"])
                        self.assertEqual(entry["status"], "quarantined")
                        self.assertEqual(entry["reason"], case["reason"])
                        self.assertFalse((output / "sanitized" / case["file"]).exists())
                        continue

                    self.assertEqual(entry["status"], "sanitized")
                    cleaned = output / entry["output"]
                    text = cleaned.read_text(encoding="utf-8")
                    self.assertIn(case["clinical"], text)
                    record, = records[entry["output"]]
                    patient = record["patient"]
                    if case["group"]:
                        self.assertTrue(patient.startswith("PSN-"))
                        groups[case["group"]].add(patient)
                        patient_occurrences[patient] += 1
                        self.assertIn(patient, text)
                    else:
                        self.assertIsNone(patient)

                    if case["file"].startswith("registrations/"):
                        with cleaned.open(encoding="utf-8", newline="") as stream:
                            row, = csv.DictReader(stream)
                        stay = date.fromisoformat(row["discharged"]) - date.fromisoformat(row["admitted"])
                        self.assertEqual(stay.days, 9)
                        self.assertEqual(row["location"], "Example District")
                    elif case["file"].startswith("visits/"):
                        self.assertEqual(record["loc"], "/data/visits/0")
                    elif case["file"].startswith("fhir/"):
                        bundle = json.loads(text)["entry"]
                        observation = bundle[1]["resource"]
                        self.assertEqual(observation["subject"]["reference"], bundle[0]["fullUrl"])
                        self.assertEqual(observation["valueQuantity"], {"value": 105, "unit": "mg/dL"})

            self.assertEqual(len(groups), 24)
            self.assertTrue(all(len(patients) == 1 for patients in groups.values()))
            self.assertEqual(sorted(patient_occurrences.values()), [5] * 24)
            self.assertEqual(len(records), 126)
            observed = "\n".join([run.stdout, run.stderr, *(
                path.relative_to(output).as_posix() + "\n" + path.read_text(encoding="utf-8")
                for path in output.rglob("*") if path.is_file()
            )])
            for marker in (*manifest["forbidden_markers"], "Asha_Demo", "synthetic-scale-key"):
                self.assertNotIn(marker, observed)
