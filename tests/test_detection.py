import unittest

from fixture_records import ParsedRecord, note_fixture, registration_fixture
from secret_wards.detection import TextSurface, detect_record
from secret_wards.normalization import birth_date, name_form, name_similarity, phone_number


class DetectionTests(unittest.TestCase):
    def test_structured_registration_paths_and_clinical_field(self):
        record = registration_fixture()[0]
        before = dict(record.content)
        result = detect_record(record, day_first=True)
        self.assertEqual(record.content, before)
        self.assertEqual(
            {(target.path, target.kind) for target in result.sensitive_targets},
            {
                (("Patient Name",), "PATIENT_NAME"), (("DOB",), "DOB"),
                (("Mobile No",), "PHONE"), (("Father Name",), "RELATIVE_NAME"), (("MRN",), "MRN"),
            },
        )
        self.assertEqual([target.path for target in result.protected_clinical_targets], [("Diagnosis",)])
        self.assertTrue(all(target.start is None for target in result.sensitive_targets))
        self.assertEqual(result.hospital, "Demo Hospital A")

    def test_structured_guardian_name_stays_separate_from_patient(self):
        record = ParsedRecord("r", "synthetic", "doc", "json", {
            "patient_name": "Meera Kapoor", "guardian": {"name": "Rajan Kapoor"},
        })
        observed = detect_record(record)
        self.assertEqual({(item.kind, item.value) for item in observed.identity_evidence}, {
            ("PATIENT_NAME", "Meera Kapoor"), ("RELATIVE_NAME", "Rajan Kapoor"),
        })
        self.assertIn(("guardian", "name"), {target.path for target in observed.sensitive_targets})

    def test_hindi_note_offsets_and_context(self):
        record = note_fixture("hindi")
        result = detect_record(record, day_first=True)
        sensitive = {(target.kind, record.content[target.start:target.end]) for target in result.sensitive_targets}
        protected = {record.content[target.start:target.end] for target in result.protected_clinical_targets}
        self.assertEqual(sensitive, {
            ("PATIENT_NAME", "मीरा कपूर"), ("DOB", "१६/०९/१९७९"),
            ("RELATIVE_NAME", "राजन कपूर"), ("PHONE", "७००००१२३४५"),
            ("RELATIVE_NAME", "Ramesh"),
        })
        self.assertTrue({
            "fever", "Dr. Ramesh", "BP 150/90", "Dolo 650 BD", "1-0-1", "105 mg/dL",
        } <= protected)
        for target in result.sensitive_targets:
            self.assertFalse(any(
                target.start < clinical.end and clinical.start < target.end
                for clinical in result.protected_clinical_targets
            ))

    def test_hidden_surfaces_detect_names_and_identifiers_without_linkage_evidence(self):
        record = ParsedRecord("record", "synthetic-json", "/visits/0", "json", {
            "patient_name": "Meera Kapoor", "meta": {"source_path": r"C:\export\Meera_Kapoor\file"},
            "contact": "7000012345", "aadhaar": 234512340909, "abha": "91-3456-7890-1234",
            "pan": "ABCDE1234F", "insurance_id": "DEMO-5791", "address": "House 18, Demo Colony",
        })
        result = detect_record(record, surfaces=[
            TextSurface("Meera_Kapoor_8999912345.txt", "filename"),
            TextSurface("INS-4455", "header", (0,), "insurance_id"),
            TextSurface("Meera-Kapoor", "key", ("test",)),
        ])
        channel_kinds = {(target.channel, target.kind) for target in result.sensitive_targets}
        self.assertTrue({
            ("filename", "PATIENT_NAME"), ("filename", "PHONE"), ("header", "INSURANCE_ID"),
            ("key", "PATIENT_NAME"), ("metadata", "SOURCE_PATH"), ("content", "AADHAAR"),
            ("content", "ABHA_NUMBER"), ("content", "PAN"), ("content", "ADDRESS"),
            ("content", "INSURANCE_ID"),
        } <= channel_kinds)
        self.assertFalse(any(item.value == "8999912345" for item in result.identity_evidence))
        self.assertNotIn("Meera", repr(result))
        self.assertNotIn("Meera", repr(result.identity_evidence))

    def test_hinglish_and_english_rules(self):
        text = (
            "Md. Arif sahab ka BP 150/90\n"
            "S/o Nasir Ali; C/O bukhar; C/O Parkinson's disease\n"
            "MRN: ABC/26/012345\n"
            "UHID = UID-00868\n"
            "Insurance ID: COVER-4455\n"
            "Aadhaar: 2345 1234 0909\n"
            "ABHA: 91-3456-7890-1234\n"
            "PAN: ABCDE1234F\n"
            "Address: House 17, Demo Colony\n"
        )
        result = detect_record(ParsedRecord("r", "note", "doc", "text", text))
        hits = {target.kind: text[target.start:target.end] for target in result.sensitive_targets}
        self.assertEqual(hits, {
            "PATIENT_NAME": "Md. Arif", "RELATIVE_NAME": "Nasir Ali", "MRN": "ABC/26/012345",
            "UHID": "UID-00868", "INSURANCE_ID": "COVER-4455", "AADHAAR": "2345 1234 0909",
            "ABHA_NUMBER": "91-3456-7890-1234", "PAN": "ABCDE1234F",
            "ADDRESS": "House 17, Demo Colony",
        })

    def test_hinglish_names_exclude_the_report_heading_and_preceding_sentence(self):
        text = (
            "Patient Name: Geeta Chauhan\n"
            "Treated conservatively. Geeta ji ki condition ab stable hai.\n"
            "Report of Geeta ji  48 Y / F\n"
            "Pt allergic to sulfa drugs.\n"
        )
        result = detect_record(ParsedRecord("r", "note", "doc", "text", text))
        names = [text[hit.start:hit.end] for hit in result.sensitive_targets if hit.kind == "PATIENT_NAME"]
        self.assertEqual(names, ["Geeta Chauhan", "Geeta", "Geeta"])

    def test_normalizes_matching_copies(self):
        self.assertEqual(name_form("श्री मोहम्मद आरिफ़"), name_form("Arif, Md. sahab"))
        self.assertEqual(name_similarity(name_form("M. Kapoor"), name_form("Kapoor, मीरा")), 2)
        self.assertEqual(name_form("Fatima amma"), name_form("Fatima"))
        self.assertNotEqual(name_form("Amma Devi"), name_form("Devi"))
        self.assertEqual(name_form("Kavita Pandey"), name_form("कविता पांडे"))
        self.assertNotEqual(name_form("Priya Sharma"), name_form("Pari Sharma"))
        self.assertEqual(phone_number("0091 (70000) 12345"), "7000012345")
        self.assertEqual(phone_number("०७००००१२०४५"), "7000012045")
        self.assertEqual(birth_date("०१/०६/१९९१", True), "1991-06-01")
        self.assertEqual(birth_date("01/06/1991", False), "1991-01-06")
        self.assertEqual(birth_date("01/06/1991"), "")

    def test_phone_offsets_and_extended_clinical_context(self):
        text = "Hospital: Demo Hospital A\nPt. Meera Kapoor\nCall +९१-७००-००१-२३४५\nC/O lower back pain; C/O Ramesh cough\n"
        result = detect_record(ParsedRecord("r", "note", "doc", "text", text))
        self.assertEqual(result.hospital, "Demo Hospital A")
        self.assertEqual(
            {(target.kind, text[target.start:target.end]) for target in result.sensitive_targets},
            {("PATIENT_NAME", "Meera Kapoor"), ("PHONE", "+९१-७००-००१-२३४५"), ("RELATIVE_NAME", "Ramesh")},
        )

    def test_fhir_patient_names_and_clinician_names_keep_distinct_roles(self):
        content = {"resourceType": "Bundle", "entry": [
            {"resource": {"resourceType": "Patient", "id": "resource-001",
                          "name": [{"given": ["Meera"], "family": "Kapoor"}],
                          "identifier": [{"system": "https://example.invalid/mrn", "value": "7001"},
                                         {"system": "https://healthid.abdm.gov.in/",
                                          "value": "91-3456-7890-1234"}]}},
            {"resource": {"resourceType": "Practitioner", "name": [{"given": ["Ramesh"], "family": "Demo"}]}},
            {"resource": {"resourceType": "Medication", "name": "Dolo"}},
        ]}
        result = detect_record(ParsedRecord("r", "synthetic-fhir", "doc", "fhir", content))
        self.assertEqual([(item.kind, item.value) for item in result.identity_evidence], [
            ("MRN", "7001"), ("ABHA_NUMBER", "91-3456-7890-1234"), ("PATIENT_NAME", "Meera Kapoor"),
        ])
        self.assertIn(("entry", 0, "resource", "id"), {target.path for target in result.sensitive_targets})
        self.assertEqual(
            {target.path for target in result.protected_clinical_targets},
            {("entry", 1, "resource", "name", 0, "given", 0), ("entry", 1, "resource", "name", 0, "family")},
        )
