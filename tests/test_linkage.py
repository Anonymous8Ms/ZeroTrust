import unittest

from fixture_records import ParsedRecord, note_fixture, registration_fixture
from secret_wards.detection import detect_record
from secret_wards.linkage import LinkageDiagnostics, LinkageMetrics, evaluate_links, link_records


def detect(key, fields, *, hospital=None):
    record = ParsedRecord(key, "synthetic", "doc", "json", fields)
    return detect_record(record, hospital=hospital)


class LinkageTests(unittest.TestCase):
    def test_csv_to_hindi_and_homonym_and_unresolved(self):
        records = [*registration_fixture(), note_fixture("hindi"), note_fixture("ambiguous")]
        detections = [detect_record(record, day_first=True) for record in records]
        stats = LinkageDiagnostics()
        linked = link_records(detections, diagnostics=stats)
        self.assertIsNotNone(linked["registration-0"])
        self.assertEqual(linked["registration-0"], linked["hindi"])
        self.assertIsNotNone(linked["registration-1"])
        self.assertNotEqual(linked["registration-1"], linked["hindi"])
        self.assertIsNone(linked["ambiguous"])
        self.assertEqual(linked, link_records(reversed(detections)))
        self.assertEqual(stats.shared_phones, 1)
        self.assertEqual(evaluate_links(linked, {
            "registration-0": "a", "hindi": "a", "registration-1": "b", "ambiguous": None,
        }), LinkageMetrics(1, 0, 0, 0))

    def test_equal_incompatible_candidates_leave_fragment_unresolved(self):
        detections = [
            detect("a", {"name": "Meera Kapoor", "spouse": "Rajan Mehta", "dob": "1979-09-16"}),
            detect("b", {"name": "Meera Khanna", "spouse": "Rajan Mehta", "dob": "1983-01-29"}),
            detect_record(ParsedRecord("note", "synthetic", "doc", "text", "Meera, W/o Rajan Mehta")),
        ]
        stats = LinkageDiagnostics()
        linked = link_records(detections, diagnostics=stats)
        self.assertNotEqual(linked["a"], linked["b"])
        self.assertIsNone(linked["note"])
        self.assertEqual(stats.ambiguous_records, 1)

    def test_unique_relative_corroborates_fragment(self):
        detections = [
            detect("registration", {"name": "Meera Kapoor", "spouse": "Rajan Mehta"}),
            detect_record(ParsedRecord("note", "synthetic", "doc", "text", "Meera, W/o Rajan Mehta")),
        ]
        linked = link_records(detections)
        self.assertIsNotNone(linked["note"])
        self.assertEqual(linked["note"], linked["registration"])

    def test_hospital_ids_do_not_cross_facilities_without_other_evidence(self):
        detections = [
            detect("one", {"mrn": "SYN-1234"}, hospital="Facility A"),
            detect("two", {"mrn": "SYN-1234"}, hospital="Facility A"),
            detect("three", {"mrn": "SYN-1234"}, hospital="Facility B"),
            detect("different-scheme", {"uhid": "SYN-1234"}, hospital="Facility A"),
            detect("missing", {"mrn": "SYN-1234"}),
        ]
        linked = link_records(detections)
        self.assertIsNotNone(linked["one"])
        self.assertEqual(linked["one"], linked["two"])
        self.assertNotEqual(linked["one"], linked["three"])
        self.assertNotEqual(linked["one"], linked["different-scheme"])
        self.assertIsNone(linked["missing"])

    def test_unscoped_id_needs_a_name_and_the_same_encounter(self):
        evidence = {
            "name": "Tara Pariksha", "mrn": "SSD-CHECK-1234",
            "admitted": "2026-10-14", "discharged": "2026-10-18",
        }
        detections = [
            detect("intake", evidence),
            detect("matching-note", {**evidence, "name": "तारा परीक्षा"}),
            detect("reused-id", {**evidence, "admitted": "2026-12-14", "discharged": "2026-12-18"}),
            detect("without-discharge", {**evidence, "discharged": ""}),
        ]
        linked = link_records(detections)
        self.assertIsNotNone(linked["intake"])
        self.assertEqual(linked["intake"], linked["matching-note"])
        self.assertIsNone(linked["reused-id"])
        self.assertIsNone(linked["without-discharge"])

        # The unscoped repeat cannot silently bridge two incompatible facilities.
        distinct = link_records([
            detect("a", evidence, hospital="Facility A"),
            detect("b", evidence, hospital="Facility B"),
            detect("unknown", evidence),
        ])
        self.assertNotEqual(distinct["a"], distinct["b"])
        self.assertIsNone(distinct["unknown"])

    def test_cluster_requires_support_between_all_members(self):
        detections = [
            detect("a", {"name": "Meera Kapoor", "dob": "1979-09-16"}),
            detect("bridge", {"name": "Meera Kapoor", "dob": "1979-09-16", "father name": "Rajan Mehta"}),
            detect("c", {"name": "Meera Kapoor", "father name": "Rajan Mehta"}),
        ]
        linked = link_records(detections)
        self.assertEqual(linked["a"], linked["bridge"])
        self.assertNotEqual(linked["a"], linked["c"])

    def test_conflicting_national_ids_veto_shared_phone(self):
        detections = [
            detect("a", {"name": "Meera Kapoor", "phone": "7000012345", "aadhaar": "234512340909"}),
            detect("b", {"name": "Meera Kapoor", "phone": "7000012345", "aadhaar": "234512340908"}),
        ]
        linked = link_records(detections)
        self.assertIsNotNone(linked["a"])
        self.assertIsNotNone(linked["b"])
        self.assertNotEqual(linked["a"], linked["b"])
        self.assertEqual(evaluate_links(linked, {"a": "known", "b": "known"}).missed_matches, 1)
        self.assertEqual(evaluate_links({"a": "merged", "b": "merged"}, {"a": "x", "b": "y"}).false_merges, 1)

    def test_same_name_and_birth_with_conflicting_relative_stay_separate(self):
        first = detect("a", {"name": "Meera Kapoor", "dob": "1979-09-16", "father": "Rajan"})
        second = detect("b", {"name": "Meera Kapoor", "dob": "1979-09-16", "father": "Harish"})
        linked = link_records([first, second])
        self.assertIsNotNone(linked["a"])
        self.assertIsNotNone(linked["b"])
        self.assertNotEqual(linked["a"], linked["b"])
