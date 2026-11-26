"""Check conservative recovery of missing identity evidence."""

from decimal import Decimal
import unittest

from secret_wards.contracts import ParsedRecord
from secret_wards.detection import detect_record
from secret_wards.linkage import LinkageMetrics, evaluate_links, link_records


def detect(key, data):
    return detect_record(ParsedRecord(key, "synthetic", "doc", "json", data))


class LinkageRecoveryTests(unittest.TestCase):
    def test_nameless_record_needs_an_unshared_phone_and_exact_birth_date(self):
        details = {"phone": "7000000901", "dob": "1980-03-01"}
        anchor = detect("anchor", {"name": "Meera Kapoor", **details})
        nameless = detect("nameless", details)
        phone_only = detect("phone-only", {"phone": details["phone"]})
        self.assertEqual(
            evaluate_links(link_records([anchor, nameless, phone_only]),
                           {"anchor": "group", "nameless": "group", "phone-only": "other"}),
            LinkageMetrics(1, 0, 0, 1),
        )
        shared_phone = detect("other", {**details, "name": "Tara Pariksha"})
        ambiguous = link_records([anchor, nameless, shared_phone])
        self.assertIsNone(ambiguous["nameless"])

    def test_masked_id_requires_matching_birth_date_and_name_evidence(self):
        details = {"dob": "1980-03-01"}
        anchor = detect("a", {**details, "name": "Meera Kapoor",
                              "Aadhaar Card Number": "234512340909"})
        fragment = detect("b", {**details, "name": "Meera", "aadhaar": "XXXX XXXX 0909"})
        suffix = detect("c", {**details, "name": "Meera", "Aadhaar last 4": "0908"})
        no_birth = detect("d", {"name": "Meera", "Aadhaar last 4": "0909"})
        wrong_birth = detect("e", {"name": "Meera", "Aadhaar last 4": "0909", "dob": "1981-03-01"})
        result = link_records([anchor, fragment, suffix, no_birth, wrong_birth])
        self.assertIsNotNone(result["a"])
        self.assertEqual(result["a"], result["b"])
        for record in ("c", "d", "e"):
            self.assertIsNone(result[record])

        rival = detect("rival", {**details, "name": "Meera Khanna", "aadhaar": "234512990909"})
        self.assertIsNone(link_records([anchor, fragment, rival])["b"])

    def test_exact_national_id_spellings_and_rounded_rejection(self):
        detections = [
            detect("full-aadhaar", {"aadhaar": "234512340909"}),
            detect("exact-aadhaar", {"UIDAI Number": "2.34512340909E11"}),
            detect("full-abha", {"abha": "91234567890123"}),
            detect("exact-abha", {"abha": Decimal("9.1234567890123e13")}),
            detect("rounded", {"aadhaar": "2.345e11"}),
            detect("full-with-zeros", {"aadhaar": "234500000000"}),
        ]
        links = link_records(detections)
        self.assertEqual(links["full-aadhaar"], links["exact-aadhaar"])
        self.assertEqual(links["full-abha"], links["exact-abha"])
        self.assertNotEqual(links["full-aadhaar"], links["full-abha"])
        self.assertIsNone(links["rounded"])
        self.assertIsNone(link_records([
            detect("rounded-number", {"aadhaar": Decimal("2.345e11")}),
            detections[-1],
        ])["rounded-number"])

    def test_14400_pairs_with_two_scientific_notation_records(self):
        detections = []
        expected = {}
        for index in range(1440):
            group = f"group-{index}"
            number = str(234512000000 + index)
            for position in range(5):
                key = f"{index:04d}-{position}"
                if index < 2 and position == 4:
                    value = f"{number[0]}.{number[1:]}e11"
                else:
                    value = number if position % 2 else f"{number[:4]} {number[4:8]} {number[8:]}"
                detections.append(detect(key, {"aadhaar": value}))
                expected[key] = group
        metrics = evaluate_links(link_records(detections), expected)
        self.assertEqual(metrics, LinkageMetrics(14400, 0, 0, 0))
