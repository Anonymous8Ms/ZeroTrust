import codecs
import hashlib
import json
import tempfile
import unittest
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

from secret_wards.adapters import (
    FieldEdit,
    FilenameEdit,
    HeaderEdit,
    KeyEdit,
    SpanEdit,
)
from secret_wards.file_io import FileAdapters, discover


# Stand-ins live here until Person 3 supplies the shared contracts.
@dataclass(repr=False)
class ParsedRecord:
    record_key: str
    source_file: Path
    loc: str
    format: str
    content: object


@dataclass(repr=False)
class RewritePlan:
    record_key: str
    edits: tuple = field(default_factory=tuple)


@dataclass
class ExportResult:
    input_sha256: str | None
    safe_output_path: str | None
    status: str
    safe_reason: str | None
    final_record_locations: dict


FIXTURES = Path(__file__).parent / "fixtures" / "adapters"


class AdaptersTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.inputs = self.root / "inputs"
        self.outputs = self.root / "out"
        self.inputs.mkdir()
        self.adapters = FileAdapters(record_factory=ParsedRecord, result_factory=ExportResult)

    def ingest(self, name, bytes_, **options):
        path = self.inputs / name
        path.write_bytes(bytes_)
        return self.adapters.ingest(path, self.inputs, **options)

    def read_output(self, result):
        self.assertEqual(result.status, "exported", result.safe_reason)
        return (self.outputs / result.safe_output_path).read_bytes()

    def denied(self, result, code):
        self.assertEqual(result.status, "quarantined")
        self.assertEqual(result.safe_reason, code)
        self.assertIsNone(result.safe_output_path)
        self.assertEqual(result.final_record_locations, {})

    def test_csv_and_hindi_first_handoff(self):
        found = {path.name: path for path in discover(FIXTURES)}
        csv_path = found["synthetic-name.csv"]
        before = csv_path.read_bytes()
        csv = self.adapters.ingest(csv_path, FIXTURES)
        first, second = csv.records
        self.assertEqual((first.format, first.loc, second.loc), ("csv", "row:0", "row:1"))
        self.assertEqual(first.record_key, self.adapters.ingest(csv_path, FIXTURES).records[0].record_key)
        exported = self.adapters.export(csv, [
            RewritePlan(first.record_key, (FieldEdit(("synthetic-name",), "P-01"),)),
            RewritePlan(second.record_key, (FieldEdit(("synthetic-name",), "P-02"),)),
        ], self.outputs, file_edits=(FilenameEdit("safe.csv"), HeaderEdit("synthetic-name", "subject")))
        self.assertEqual(exported.safe_output_path, "sanitized/safe.csv")
        self.assertEqual(exported.input_sha256, hashlib.sha256(before).hexdigest())
        self.assertEqual(exported.final_record_locations[first.record_key], "row:0")
        self.assertEqual(self.read_output(exported), b'subject,condition,note\nP-01,asthma,"first line\nsecond line"\nP-02,migraine,stable\n')
        self.assertEqual(csv_path.read_bytes(), before)
        note = self.adapters.ingest(found["hindi-note.txt"], FIXTURES)
        record, = note.records
        self.assertEqual((record.loc, record.format), ("doc", "text"))
        name = record.content.index("उदाहरण व्यक्ति")
        phone = record.content.index("0000000000")
        exported_note = self.adapters.export(note, [RewritePlan(record.record_key, (
            SpanEdit((), phone, phone + 10, "[हटाया]"),
            SpanEdit((), name, name + len("उदाहरण व्यक्ति"), "P-01"),
        ))], self.outputs)
        self.assertEqual(self.read_output(exported_note).decode(), "नाम: P-01\nनिदान: अस्थमा\nफ़ोन: [हटाया]\n")
        self.assertNotIn("hindi-note", exported_note.safe_output_path)
        self.assertEqual(exported_note.final_record_locations[record.record_key], "doc")
        malformed = self.adapters.ingest(found["malformed.csv"], FIXTURES)
        failure = self.adapters.export(malformed, [], self.outputs)
        self.denied(failure, "malformed_table")
        self.assertEqual(failure.input_sha256, hashlib.sha256(found["malformed.csv"].read_bytes()).hexdigest())
        self.assertEqual(len(list((self.outputs / "sanitized").iterdir())), 2)

    def test_tsv_bom_blank_lines_and_no_final_newline(self):
        tsv = self.ingest("source.tsv", "id\tcondition\r\n\r\nसैंपल\tअस्थमा".encode("utf-16"))
        record, = tsv.records
        self.assertEqual(record.loc, "row:0")
        result = self.adapters.export(tsv, [RewritePlan(record.record_key, (
            FieldEdit(("id",), "P-01"),
        ))], self.outputs)
        self.assertEqual(self.read_output(result), "id\tcondition\r\n\r\nP-01\tअस्थमा".encode())
        cp = self.ingest("source.txt", "Échantillon\n".encode("cp1252"), encoding="cp1252")
        result = self.adapters.export(cp, [RewritePlan(cp.records[0].record_key)], self.outputs)
        self.assertEqual(self.read_output(result), "Échantillon\n".encode())
        utf8 = self.ingest("bom.txt", codecs.BOM_UTF8 + "अस्थमा".encode())
        self.assertEqual(utf8.records[0].content, "अस्थमा")

    def test_nested_json_reports_escaped_final_pointers_and_retains_precision(self):
        doc = self.ingest(
            "source.json", b'{"unsafe/key":{"patient":{"name":"Example","amount":1.234567890123456789}}}',
            json_record_paths=[("unsafe/key", "patient")],
        )
        record, = doc.records
        self.assertEqual(record.loc, "/unsafe~1key/patient")
        result = self.adapters.export(doc, [RewritePlan(record.record_key, (
            FieldEdit(("name",), "P-01"), KeyEdit(("name",), "subject"),
        ))], self.outputs, file_edits=(KeyEdit(("unsafe/key",), "safe~key"),))
        self.assertEqual(result.final_record_locations, {record.record_key: "/safe~0key/patient"})
        tree = json.loads(self.read_output(result), parse_float=Decimal)
        self.assertEqual(tree["safe~key"]["patient"], {"subject": "P-01", "amount": Decimal("1.234567890123456789")})

    def test_invalid_inputs_and_plans_are_safe(self):
        for name, raw, reason in [
            ("input.bin", b"raw", "unsupported_format"),
            ("input.json", b'{"x":1,"x":2}', "duplicate_json_key"),
            ("input.json", b'{"x":', "malformed_json"),
            ("input.txt", b"\xf0\x9f", "invalid_encoding"),
            ("input.csv", b'a,b\nname"bad,condition\n', "malformed_table"),
        ]:
            with self.subTest(reason=reason):
                doc = self.ingest(name, raw)
                result = self.adapters.export(doc, [], self.outputs)
                self.denied(result, reason)
                self.assertEqual(result.input_sha256, hashlib.sha256(raw).hexdigest())
        document = self.ingest("input.txt", b"synthetic")
        record, = document.records
        self.denied(self.adapters.export(document, [], self.outputs), "missing_record_plan")
        for edits, reason in [
            ((SpanEdit((), 0, 5, "x"), SpanEdit((), 4, 6, "y")), "overlapping_edits"),
            ((FilenameEdit("../unsafe.txt"),), "unsafe_output_path"),
            ((FieldEdit((), "\x00"),), "invalid_text"),
        ]:
            result = self.adapters.export(document, [RewritePlan(record.record_key, edits)], self.outputs)
            self.denied(result, reason)
        self.assertEqual([path.relative_to(self.outputs).as_posix() for path in self.outputs.rglob("*")],
                         ["sanitized"])

    def test_rejects_collisions_without_touching_prior_output_or_inputs(self):
        document = self.ingest("input.txt", b"input")
        plan = RewritePlan(document.records[0].record_key, (FieldEdit((), "safe"),))
        result = self.adapters.export(document, [plan], self.outputs, file_edits=(FilenameEdit("fixed.txt"),))
        self.assertEqual(self.read_output(result), b"safe")
        self.denied(self.adapters.export(document, [plan], self.outputs, file_edits=(
            FilenameEdit("fixed.txt"),
        )), "output_exists")
        self.assertEqual(self.read_output(result), b"safe")
        self.assertEqual((self.inputs / "input.txt").read_bytes(), b"input")

    def test_fhir_rewrites_local_references_and_rejects_multi_patient(self):
        urn = "urn:uuid:00000000-0000-4000-8000-000000000001"
        patient_url = "https://example.invalid/Patient/example"
        bundle = {"resourceType": "Bundle", "type": "collection", "entry": [
            {"fullUrl": patient_url, "resource": {
                "resourceType": "Patient", "id": "example", "meta": {"versionId": "v1"},
                "identifier": [{"system": "urn:synthetic:registry", "value": "example"}],
                "contained": [{"resourceType": "Organization", "id": "org"}],
                "managingOrganization": {"reference": "#org"},
            }},
            {"fullUrl": urn, "resource": {
                "resourceType": "Observation", "id": "obs", "status": "final",
                "code": {"text": "Synthetic measurement"},
                "subject": {"reference": patient_url + "/_history/v1"},
                "focus": [{"reference": "Patient/example"}, {"identifier": {"value": "example"}}],
                "derivedFrom": [{"reference": urn}],
            }},
        ]}
        doc = self.ingest("fhir.json", json.dumps(bundle).encode())
        self.assertIsNone(doc.reason)
        record, = doc.records
        self.assertEqual((record.format, record.loc), ("fhir", "doc"))
        plan = RewritePlan(record.record_key, (
            FieldEdit(("entry", 0, "resource", "id"), "p-01"),
            FieldEdit(("entry", 0, "resource", "meta", "versionId"), "v2"),
            FieldEdit(("entry", 0, "resource", "identifier", 0, "value"), "p-01"),
            FieldEdit(("entry", 0, "resource", "contained", 0, "id"), "org-01"),
            FieldEdit(("entry", 1, "fullUrl"), urn[:-1] + "2"),
        ))
        exported = self.adapters.export(doc, [plan], self.outputs)
        actual = json.loads(self.read_output(exported))
        first, second = actual["entry"]
        self.assertEqual(first["fullUrl"], "https://example.invalid/Patient/p-01")
        self.assertEqual(first["resource"]["managingOrganization"]["reference"], "#org-01")
        self.assertEqual(second["resource"]["subject"]["reference"], first["fullUrl"] + "/_history/v2")
        self.assertEqual(second["resource"]["focus"], [
            {"reference": "Patient/p-01"}, {"identifier": {"value": "p-01"}},
        ])
        self.assertEqual(second["resource"]["derivedFrom"][0]["reference"], urn[:-1] + "2")
        bad = RewritePlan(record.record_key, plan.edits + (
            FieldEdit(("entry", 1, "resource", "subject", "reference"), "Patient/wrong"),
        ))
        self.denied(self.adapters.export(doc, [bad], self.outputs), "inconsistent_fhir_rewrite")
        bundle["entry"].append({"fullUrl": "urn:uuid:00000000-0000-4000-8000-000000000003",
                                "resource": {"resourceType": "Patient", "id": "another"}})
        multi = self.ingest("multi.fhir", json.dumps(bundle).encode())
        self.denied(self.adapters.export(multi, [], self.outputs), "multi_patient_fhir_bundle")

    def test_fhir_validator_is_run_before_publish_and_errors_are_safe(self):
        def validator(tree):
            if tree["id"] == "P-01":
                raise ValueError("private adapter input")
            return True

        self.adapters.fhir_validator = validator
        document = self.ingest("fhir.json", b'{"resourceType":"Patient","id":"example"}')
        record, = document.records
        result = self.adapters.export(document, [RewritePlan(record.record_key, (
            FieldEdit(("id",), "P-01"),
        ))], self.outputs)
        self.denied(result, "invalid_fhir")
        self.assertEqual(list((self.outputs / "sanitized").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
