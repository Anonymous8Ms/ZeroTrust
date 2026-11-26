"""Small synthetic harness until the team adapters and detector land."""
import csv
import io
import re

from .contracts import (
    DetectionResult, ExportResult, ParsedFile, ParsedRecord, Quarantine, Target,
)

COLUMNS = ("patient_name", "patient_id", "phone", "age", "location",
           "admitted", "discharged", "diagnosis")
KINDS = ("patient_name", "identifier", "identifier", "age", "location",
         "date", "date", "protected")
LABELS = {
    "रोगी": "patient_name", "Patient": "patient_name",
    "फोन": "identifier", "Phone": "identifier",
    "प्रवेश": "date", "Admission": "date", "छुट्टी": "date", "Discharge": "date",
    "Clinical": "protected",
}


class FixtureBackend:
    def parse(self, source, raw):
        if source not in {"registration.csv", "malformed.csv", "hindi.txt", "ambiguous.txt"}:
            raise Quarantine("format outside synthetic fixture support")
        try:
            text = raw.decode("utf-8", errors="strict")
            if source.endswith(".csv"):
                rows = list(csv.reader(io.StringIO(text), strict=True))
                if not rows or tuple(rows[0]) != COLUMNS or not rows[1:]:
                    raise Quarantine("unexpected CSV schema")
                if any(len(row) != len(COLUMNS) for row in rows[1:]):
                    raise Quarantine("invalid CSV row")
                records = tuple(
                    ParsedRecord(f"{source}:{i}", source, f"row:{i}", "csv",
                                 dict(zip(COLUMNS, row)))
                    for i, row in enumerate(rows[1:])
                )
            else:
                records = (ParsedRecord(f"{source}:doc", source, "doc", "text", text),)
        except (UnicodeError, csv.Error):
            raise Quarantine("malformed fixture") from None
        return ParsedFile(records, source)

    def detect(self, record):
        evidence = {}
        targets = []
        if record.format == "csv":
            for key, kind in zip(COLUMNS, KINDS):
                value = record.content[key]
                if key == "diagnosis" and value != "dengue":
                    raise Quarantine("unrecognised fixture diagnosis")
                targets.append(Target((key,), kind, value))
            evidence["phone"] = re.sub(r"\D", "", record.content["phone"])
            evidence["patient_id"] = record.content["patient_id"]
        else:
            position = 0
            labels = set()
            for line in record.content.splitlines(keepends=True):
                match = re.fullmatch(r"([^:\r\n]+): ([^\r\n]+)(?:\r?\n)?", line)
                if not match or match[1] not in LABELS or match[1] in labels:
                    raise Quarantine("unexpected fixture note layout")
                label, value = match.groups()
                labels.add(label)
                kind = LABELS[label]
                if kind == "protected" and not re.fullmatch(
                    r"BP [0-9]{2,3}/[0-9]{2,3}(?:; Dolo 650 BD)?", value
                ):
                    raise Quarantine("unrecognised fixture clinical text")
                if kind == "identifier":
                    evidence["phone"] = re.sub(r"\D", "", value)
                span = tuple(position + offset for offset in match.span(2))
                targets.append(Target((), kind, value, span))
                position += len(line)
        slot = next((target for target in targets if target.kind == "patient_name"), None)
        return DetectionResult(record.record_key, evidence, tuple(targets), slot)

    def resolve(self, detections):
        anchors = {}
        for result in detections:
            phone = result.evidence.get("phone")
            patient = result.evidence.get("patient_id")
            if phone and patient:
                anchors.setdefault(phone, set()).add(patient)
        groups = {}
        for result in detections:
            candidates = anchors.get(result.evidence.get("phone"), set())
            groups[result.record_key] = result.evidence.get("patient_id") or (
                next(iter(candidates)) if len(candidates) == 1 else None
            )
        return groups

    def render(self, parsed, plans):
        source = parsed.structure
        if source.endswith(".csv"):
            buffer = io.StringIO(newline="")
            writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
            writer.writeheader()
            for record in parsed.records:
                row = dict(record.content)
                for edit in plans[record.record_key].edits:
                    row[edit.target.path[0]] = edit.replacement
                writer.writerow(row)
            output = buffer.getvalue()
        else:
            record = parsed.records[0]
            output = record.content
            for edit in sorted(plans[record.record_key].edits,
                               key=lambda edit: edit.target.span, reverse=True):
                start, stop = edit.target.span
                output = output[:start] + edit.replacement + output[stop:]
        locations = {record.record_key: record.loc for record in parsed.records}
        return ExportResult(source, output.encode("utf-8"), locations)
