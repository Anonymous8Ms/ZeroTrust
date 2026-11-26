"""Exercise the organiser's real CLI on team-generated synthetic records."""
import base64
import csv
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "tests" / "fixtures" / "input"


def run(output, key, input_root=INPUT, *, check=True):
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--input", str(input_root),
         "--output", str(output)],
        env={**os.environ, "RAKSHA_SECRET": key},
        check=check, capture_output=True, text=True,
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
    def test_missing_or_blank_secret_is_rejected_before_export(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            for secret in (None, "", "   "):
                with self.subTest(secret=secret):
                    env = os.environ.copy()
                    env.pop("RAKSHA_SECRET", None)
                    if secret is not None:
                        env["RAKSHA_SECRET"] = secret
                    result = subprocess.run(
                        [sys.executable, str(ROOT / "main.py"), "--input", str(INPUT),
                         "--output", str(output)],
                        env=env, capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("Set RAKSHA_SECRET", result.stderr)
                    self.assertFalse(output.exists())

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
            for marker in ("Asha Demo", "आशा डेमो", "70000 00101", "70000 00102",
                           "FIX-A", "FIX-B", "Example Village East", "Example Village West",
                           "synthetic-demo-secret-a"):
                self.assertNotIn(marker.encode(), observable)
            self.assertEqual(unique_records(rows(INPUT / "registration.csv")), 2)
            self.assertEqual(unique_records(registration), 0)
            self.assertGreater(audit["timing"]["seconds"], 0)
            self.assertGreater(audit["resources"]["peak_rss_mb"], 0)


    def test_renamed_inputs_and_mixed_formats(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "inputs"
            source.mkdir()
            nested = source / "batch"
            nested.mkdir()
            shutil.copyfile(INPUT / "registration.csv", nested / "intake.csv")
            shutil.copyfile(INPUT / "hindi.txt", source / "ward-note.txt")
            shutil.copyfile(INPUT / "malformed.csv", source / "broken-upload.csv")

            output = root / "renamed-output"
            run(output, "synthetic-mixed-key", source)
            self.assertEqual(report(output)["counts"]["files_sanitized"], 2)
            self.assertEqual(report(output)["counts"]["files_quarantined"], 1)
            intake = rows(output / "sanitized" / "batch" / "intake.csv")
            note = (output / "sanitized" / "ward-note.txt").read_text(encoding="utf-8")
            self.assertIn(intake[0]["patient_name"], note)
            self.assertNotEqual(intake[0]["patient_name"], intake[1]["patient_name"])
            self.assertIn("BP 150/90; Dolo 650 BD", note)
            self.assertFalse((output / "sanitized" / "broken-upload.csv").exists())

            (source / "encounters.tsv").write_text(
                "patient_name\tphone\tdiagnosis\nAsha Demo\t7000000101\tdengue\n",
                encoding="utf-8",
            )
            nested_json = {"data": {"visits": [
                {"patient_name": "Asha Demo", "phone": "7000000101", "diagnosis": "dengue"},
                {"patient_name": "Asha Demo", "phone": "7000000102", "diagnosis": "malaria"},
            ]}, "metadata": {"phone": "7000000101"}}
            (source / "visits.json").write_text(json.dumps(nested_json), encoding="utf-8")
            fhir = {"resourceType": "Bundle", "type": "collection", "entry": [
                {"fullUrl": "https://example.invalid/Patient/source-patient",
                 "resource": {"resourceType": "Patient", "id": "source-patient",
                              "name": [{"text": "Asha Demo"}],
                              "telecom": [{"system": "phone", "value": "7000000101"}]}},
                {"fullUrl": "https://example.invalid/Observation/observation",
                 "resource": {"resourceType": "Observation", "id": "observation",
                              "status": "final", "code": {"text": "Glucose"},
                              "subject": {"reference": "Patient/source-patient"},
                              "valueQuantity": {"value": 105, "unit": "mg/dL"}}},
            ]}
            (source / "resources.fhir").write_text(json.dumps(fhir), encoding="utf-8")

            output = root / "mixed-output"
            run(output, "synthetic-mixed-key", source)
            repeated = root / "mixed-repeat"
            run(repeated, "synthetic-mixed-key", source)
            self.assertEqual(stable_output(output), stable_output(repeated))
            audit = report(output)
            self.assertEqual(audit["counts"]["files_sanitized"], 5, audit)
            self.assertEqual(audit["counts"]["files_quarantined"], 1)
            self.assertEqual(audit["counts"]["records_processed"], 7)
            bad_sha = hashlib.sha256((source / "broken-upload.csv").read_bytes()).hexdigest()
            self.assertEqual(next(item["output"] for item in audit["files"]
                                  if item["input_sha256"] == bad_sha), None)

            records = [json.loads(line) for line in (output / "records.jsonl").read_text().splitlines()]
            by_location = {(r["file"], r["loc"]): r["patient"] for r in records}
            patient = by_location[("sanitized/batch/intake.csv", "row:0")]
            self.assertTrue(patient.startswith("PSN-"))
            for file, loc in (("ward-note.txt", "doc"), ("encounters.tsv", "row:0"),
                              ("visits.json", "/data/visits/0"), ("resources.fhir", "doc")):
                self.assertEqual(by_location[(f"sanitized/{file}", loc)], patient)
                self.assertIn(patient, (output / "sanitized" / file).read_text())

            other = by_location[("sanitized/batch/intake.csv", "row:1")]
            self.assertNotEqual(other, patient)
            self.assertEqual(by_location[("sanitized/visits.json", "/data/visits/1")], other)
            exported = json.loads((output / "sanitized" / "visits.json").read_text())
            self.assertEqual(exported["data"]["visits"][1]["diagnosis"], "malaria")
            self.assertEqual(exported["metadata"]["phone"], "[REDACTED]")
            exported_fhir = json.loads((output / "sanitized/resources.fhir").read_text())
            fhir_patient, observation = [item["resource"] for item in exported_fhir["entry"]]
            self.assertEqual(observation["subject"]["reference"], "Patient/" + fhir_patient["id"])
            self.assertEqual(observation["valueQuantity"], {"value": 105, "unit": "mg/dL"})
            public_files, _ = stable_output(output)
            payload = b"\n".join(public_files.values())
            for marker in (b"Asha Demo", b"7000000101", b"7000000102", b"source-patient"):
                self.assertNotIn(marker, payload)

    def test_age_labels_and_numeric_date_orders(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "inputs"
            source.mkdir()
            (source / "ward-note.txt").write_text(
                "उम्र: ४२ वर्ष / महिला\n"
                "Admission: 08/09/2026\nDischarge: 09/09/2026\n"
                "Clinical: BP 150/90; Dolo 650 BD\n",
                encoding="utf-8",
            )
            (source / "encounters.csv").write_text(
                "Age,Admitted,Discharged,DOB (MM/DD/YYYY),Visit Date (DD/MM/YYYY)\n"
                "47 years,09/08/2026,09/17/2026,05/10/1984,08/09/2026\n",
                encoding="utf-8",
            )
            (source / "invalid-age.txt").write_text("Age: 131 years\n", encoding="utf-8")
            (source / "invalid-date.txt").write_text("Admission: 31/02/2026\n", encoding="utf-8")

            output = root / "output"
            run(output, "synthetic-age-date-key", source)
            counts = report(output)["counts"]
            self.assertEqual(counts["files_sanitized"], 2)
            self.assertEqual(counts["files_quarantined"], 2)

            export = output / "sanitized"
            note = (export / "ward-note.txt").read_text(encoding="utf-8").splitlines()
            self.assertEqual(note[0], "उम्र: 40-49 वर्ष / महिला")
            admitted, discharged = (date.fromisoformat(line.split(": ")[1]) for line in note[1:3])
            self.assertEqual((discharged - admitted).days, 1)
            self.assertEqual(note[3], "Clinical: BP 150/90; Dolo 650 BD")

            encounter = rows(export / "encounters.csv")[0]
            self.assertEqual(encounter["Age"], "40-49 years")
            self.assertEqual(encounter["Visit Date (DD/MM/YYYY)"], encounter["Admitted"])
            admitted = date.fromisoformat(encounter["Admitted"])
            discharged = date.fromisoformat(encounter["Discharged"])
            born = date.fromisoformat(encounter["DOB (MM/DD/YYYY)"])
            self.assertEqual((discharged - admitted).days, 9)
            self.assertEqual((admitted - born).days, (date(2026, 9, 8) - date(1984, 5, 10)).days)

    def test_redacts_identifiers_on_hidden_surfaces_and_in_notes(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "inputs"
            source.mkdir()
            (source / "calls_ABX-2026-01125.csv").write_text(
                'remarks,diagnosis,ABX-0074162 Synthetic Column\n'
                'called by Casey Reporter,dengue,Source field\n',
                encoding="utf-8",
            )
            (source / "contacts.txt").write_text(
                "18:40 - Taylor Visitor (attendant), mob 7000012345\n"
                "08/09/2026 22:00 - Morgan Patient ka BP 150/90\n"
                "Treated conservatively. Morgan Patient ki condition ab stable hai.\n",
                encoding="utf-8",
            )
            payload = base64.b64encode(b"Name: Parker Sender; contact: 7000012468").decode("ascii")
            nested = {
                "attachment": {"contentType": "text/plain", "data": payload},
                "metadata": {"source_path": "/export/Synthetic Person/004321/intake.csv"},
                "by_name": {"Blair Subject": {"Reg No": "ABC-0014213", "diagnosis": "malaria"}},
            }
            (source / "intake.json").write_text(json.dumps(nested), encoding="utf-8")
            fhir = {"resourceType": "Bundle", "type": "collection", "entry": [
                {"fullUrl": "https://example.invalid/Patient/ABX-0050012", "resource": {
                    "resourceType": "Patient", "id": "ABX-0050012",
                    "name": [{"text": "Jamie Example"}],
                }},
                {"fullUrl": "urn:uuid:observation-fixture", "resource": {
                    "resourceType": "Observation", "id": "ABX-0050013",
                    "subject": {"reference": "https://example.invalid/Patient/ABX-0050012", "display": "Jamie Example"},
                    "text": {"status": "generated", "div":
                             '<div xmlns="http://www.w3.org/1999/xhtml">Jamie Example, 42 yrs</div>'},
                    "extension": [{"url": "https://example.invalid/StructureDefinition/mothers-name",
                                   "valueString": "Dana Parent"}],
                    "valueQuantity": {"value": 105, "unit": "mg/dL"},
                }},
            ]}
            (source / "resources.fhir").write_text(json.dumps(fhir), encoding="utf-8")

            output = root / "output"
            run(output, "synthetic-redaction-test", source)
            audit = report(output)
            self.assertEqual(audit["counts"]["files_sanitized"], 4, audit)
            files, _ = stable_output(output)
            surface = "\n".join((*files, *(value.decode("utf-8") for value in files.values())))
            for marker in ("ABX-2026-01125", "ABX-0074162", "Casey Reporter", "Taylor Visitor",
                           "Morgan Patient", "Synthetic Person", "Blair Subject", "ABC-0014213",
                           "Jamie Example", "Dana Parent", "ABX-0050012", "ABX-0050013", payload):
                self.assertNotIn(marker, surface)
            self.assertIn("BP 150/90", surface)
            self.assertIn("condition ab stable hai", surface)
            self.assertIn("dengue", surface)
            clean_json = json.loads(files["sanitized/intake.json"])
            self.assertEqual(base64.b64decode(clean_json["attachment"]["data"], validate=True), b"[REDACTED]")
            self.assertEqual(next(iter(clean_json["by_name"].values()))["diagnosis"], "malaria")
            clean_fhir = json.loads(files["sanitized/resources.fhir"])
            observation = clean_fhir["entry"][1]["resource"]
            self.assertEqual(observation["subject"]["reference"], clean_fhir["entry"][0]["fullUrl"])
            self.assertEqual(observation["valueQuantity"], {"value": 105, "unit": "mg/dL"})
            self.assertIn("40-49 yrs", observation["text"]["div"])

    def test_all_quarantined_is_a_failed_cli_run(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "inputs"
            source.mkdir()
            (source / "unsupported.bin").write_bytes(b"synthetic data")
            output = root / "output"
            result = run(output, "synthetic-test", source, check=False)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(report(output)["counts"]["files_quarantined"], 1)
            self.assertEqual(list((output / "sanitized").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
