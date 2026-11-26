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

    def test_unscoped_uhid_links_only_with_an_unambiguous_full_name(self):
        first = {"uhid": "HX-000482", "name": "Tara Pariksha"}
        second = {"uhid": "HX-000482", "name": "तारा परीक्षा"}
        visits = [detect("first", first), detect("second", second)]
        links = link_records(visits + [detect("bare-id", {"uhid": "HX-000482"})])
        self.assertIsNotNone(links["first"])
        self.assertEqual(links["first"], links["second"])
        self.assertIsNone(links["bare-id"])

        for a, b in (
            (detect("a", first, hospital="Facility A"), detect("b", first, hospital="Facility B")),
            (detect("a", {**first, "dob": "1974-09-18"}),
             detect("b", {**first, "dob": "1983-01-29"})),
        ):
            with self.subTest(a=a.record_key, locations=(a.hospital, b.hospital)):
                linked = link_records([a, b, *visits])
                self.assertIsNotNone(linked["a"])
                self.assertIsNotNone(linked["b"])
                self.assertNotEqual(linked["a"], linked["b"])
                self.assertIsNone(linked["first"])
                self.assertIsNone(linked["second"])

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

    def test_national_id_anchor_connects_strong_matches_without_conflicts(self):
        national = {"aadhaar": "234512340909"}
        local = {"name": "Meera Kapoor", "uhid": "DEMO-10492"}
        anchor = detect("anchor", {**national, **local})
        national_record = detect("national", national)
        local_record = detect("local", local)
        matched = link_records([anchor, national_record, local_record])
        self.assertIsNotNone(matched["anchor"])
        self.assertEqual(matched["anchor"], matched["national"])
        self.assertEqual(matched["anchor"], matched["local"])
        self.assertEqual(matched, link_records([local_record, national_record, anchor]))

        conflicted = link_records([
            anchor,
            detect("national", {**national, "dob": "1981-03-15"}),
            detect("local", {**local, "dob": "1983-05-12"}),
        ])
        self.assertEqual(conflicted["anchor"], conflicted["national"])
        self.assertNotEqual(conflicted["national"], conflicted["local"])

        abha = {"abha": "91-3456-7890-1234"}
        linked_identifiers = link_records([
            detect("anchor", {**national, **abha}), national_record, detect("abha", abha),
        ])
        self.assertIsNotNone(linked_identifiers["anchor"])
        self.assertEqual(linked_identifiers["anchor"], linked_identifiers["national"])
        self.assertEqual(linked_identifiers["anchor"], linked_identifiers["abha"])

    def test_facility_uhid_anchor_links_short_names_in_the_same_scope(self):
        fields = {"name": "Meera Kapoor", "uhid": "DEMO-10492"}
        anchor = detect("anchor", fields, hospital="Facility A")
        full_name = detect("full-name", fields)
        short_name = {**fields, "name": "Meera"}

        linked = link_records([anchor, full_name, detect("short", short_name, hospital="Facility A")])
        self.assertIsNotNone(linked["anchor"])
        self.assertEqual(linked["anchor"], linked["full-name"])
        self.assertEqual(linked["anchor"], linked["short"])

        distinct = link_records([anchor, full_name, detect("short", short_name, hospital="Facility B")])
        self.assertEqual(distinct["anchor"], distinct["full-name"])
        self.assertNotEqual(distinct["anchor"], distinct["short"])

    def test_reconnects_facility_groups_through_matching_full_name_and_birth_date(self):
        identity = {"name": "Meera Pariksha", "dob": "1981-03-15"}
        intake = {"uhid": "QA-41927"}
        followup = {"uhid": "QA-62184"}
        detections = [
            detect("a-intake", {**identity, **intake}, hospital="Facility A"),
            detect("a-lab", intake, hospital="Facility A"),
            detect("b-intake", {**identity, **followup}, hospital="Facility B"),
            detect("b-lab", followup, hospital="Facility B"),
        ]
        linked = link_records(detections)
        self.assertIsNotNone(linked["a-intake"])
        self.assertEqual(len(set(linked.values())), 1)
        self.assertEqual(linked, link_records(reversed(detections)))

        conflict = detect("b-intake", {**identity, **followup, "dob": "1981-04-15"}, hospital="Facility B")
        split = link_records([*detections[:2], conflict, detections[3]])
        self.assertEqual(split["a-intake"], split["a-lab"])
        self.assertEqual(split["b-intake"], split["b-lab"])
        self.assertNotEqual(split["a-intake"], split["b-intake"])

    def test_same_facility_and_full_name_corroborate_a_local_number_alias(self):
        intake = detect("intake", {"name": "Meera Pariksha", "mrn": "QA-18459"}, hospital="Facility A")
        lab_fields = {"name": "मीरा परीक्षा", "uhid": "QA-18459"}
        lab = detect("lab", lab_fields, hospital="Facility A")
        elsewhere = detect("elsewhere", lab_fields, hospital="Facility B")
        linked = link_records([intake, lab, elsewhere])
        self.assertIsNotNone(linked["intake"])
        self.assertEqual(linked["intake"], linked["lab"])
        self.assertNotEqual(linked["intake"], linked["elsewhere"])

    def test_hindi_prescription_uses_age_at_visit_and_village_to_resolve_homonyms(self):
        name = {"name": "Meera Kapoor"}
        patient = detect("registration", {**name, "village": "Rampur", "dob": "1980-05-10", "age": 41})
        rival = detect("rival", {**name, "village": "Rampur", "dob": "1970-05-10", "age": 45})
        elsewhere = detect("elsewhere", {**name, "village": "Sitapur", "dob": "1979-10-10", "age": 45})
        prescription = detect_record(ParsedRecord(
            "prescription", "synthetic", "doc", "text",
            "नाम: मीरा कपूर, आयु: 45 वर्ष\nग्राम: रामपुर\nतारीख: 2025-09-03\nRx: Dolo 650 BD",
        ))
        # The matching registration's saved age is stale. Its DOB supports the
        # age at the visit, while the other Rampur registration's DOB does not.
        linked = link_records([patient, rival, elsewhere, prescription])
        self.assertIsNotNone(linked["prescription"])
        self.assertEqual(linked["prescription"], linked["registration"])
        self.assertNotEqual(linked["prescription"], linked["rival"])
        self.assertNotEqual(linked["prescription"], linked["elsewhere"])

        uncertain = detect("uncertain", {**name, "village": "Rampur", "dob": "1981-05-10"})
        linked = link_records([patient, uncertain, prescription])
        self.assertIsNone(linked["prescription"])

    def test_short_name_and_uhid_need_an_unambiguous_observed_issuer(self):
        number = {"uhid": "QA-88821"}
        intake = detect("intake", {**number, "name": "Meera"}, hospital="Facility A")
        lab = detect("lab", {**number, "name": "मीरा कपूर"})
        linked = link_records([intake, lab])
        self.assertIsNotNone(linked["lab"])
        self.assertEqual(linked["intake"], linked["lab"])

        reused = detect("reused", {**number, "name": "Meera"}, hospital="Facility B")
        linked = link_records([intake, reused, lab])
        self.assertNotEqual(linked["intake"], linked["reused"])
        self.assertIsNone(linked["lab"])
        self.assertEqual(linked, link_records([lab, reused, intake]))

    def test_phone_fragment_needs_one_corroborated_full_name_owner(self):
        phone = {"mobile": "7000012345"}
        patient = detect("patient", {**phone, "name": "Meera Kapoor", "dob": "1980-05-10"})
        note = detect("note", {**phone, "name": "मीरा"})
        linked = link_records([patient, note])
        self.assertIsNotNone(linked["note"])
        self.assertEqual(linked["patient"], linked["note"])

        homonym = detect("homonym", {**phone, "name": "Meera Kapoor", "dob": "1970-05-10"})
        linked = link_records([patient, homonym, note])
        self.assertNotEqual(linked["patient"], linked["homonym"])
        self.assertIsNone(linked["note"])

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
