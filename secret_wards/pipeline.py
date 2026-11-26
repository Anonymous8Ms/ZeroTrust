"""Connect validated file I/O, patient detection and the privacy policy."""
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
import re
from time import perf_counter

from .adapters import FieldEdit, FilenameEdit, HeaderEdit, KeyEdit, SpanEdit
from .adapters.fhir import resource_id_spans
from .adapters.json_records import get
from .contracts import (
    DetectionResult as PolicyDetection, ParsedRecord, Quarantine, Target,
)
from .detection import DetectionResult, TextSurface, detect_record
from .file_io import FileAdapters, IngestedFile, discover
from .linkage import link_records
from .normalization import birth_date, date_order_hint
from .privacy import Policy, build_plan, derive
from .reporting import write_reports

_LOCATIONS = {"VILLAGE", "TEHSIL", "DISTRICT", "PIN"}
_INDEX_FIELDS = {
    "by name": "name", "by patient name": "name", "by uhid": "uhid",
    "by mrn": "mrn", "by patient id": "patient id",
}
_SAFE_PART = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10)
}


@dataclass(frozen=True)
class ExportStatus:
    input_sha256: str | None
    safe_output_path: str | None
    status: str
    safe_reason: str | None
    final_record_locations: Mapping[str, str]


@dataclass(frozen=True)
class AdapterPlan:
    record_key: str
    edits: tuple[FieldEdit | SpanEdit | KeyEdit, ...]
    patient: str | None


@dataclass(frozen=True)
class WorkItem:
    source: Path
    document: IngestedFile
    detections: tuple[DetectionResult, ...]
    envelope: ParsedRecord | None = None
    fallback_day_first: bool = True


def json_keys(value, path=()):
    if isinstance(value, dict):
        parent = path[-1] if path and isinstance(path[-1], str) else ""
        label = _INDEX_FIELDS.get(re.sub(r"[_-]+", " ", parent).casefold())
        for key, child in value.items():
            target = (*path, key)
            yield TextSurface(key, "key", target, label)
            yield from json_keys(child, target)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from json_keys(child, (*path, index))


def inspect_record(record: ParsedRecord, path_surfaces=()) -> DetectionResult:
    if record.format in {"csv", "tsv"}:
        surfaces = (TextSurface(key, "header", (key,)) for key in record.content)
    elif record.format in {"json", "fhir"}:
        surfaces = json_keys(record.content)
    else:
        surfaces = ()
    return detect_record(record, surfaces=(*surfaces, *path_surfaces))


def extract(record: ParsedRecord, hit):
    value = record.content
    for part in hit.path:
        value = value[part]
    text = str(value)
    if hit.start is not None:
        return text[hit.start:hit.end]
    return text.strip()


def fallback_date_order(records, detections):
    """Use unambiguous dates or format labels in the file to resolve unlabeled dates."""
    observed, declared = set(), set()
    for record, detection in zip(records, detections, strict=True):
        for hit in detection.sensitive_targets:
            if hit.channel != "content" or hit.kind not in {"DATE", "DOB"}:
                continue
            if hit.path and isinstance(hit.path[-1], str):
                hint = date_order_hint(hit.path[-1])
                if hint is not None:
                    declared.add(hint)
                    continue
            value = extract(record, hit)
            day_first, month_first = birth_date(value, True), birth_date(value, False)
            if bool(day_first) != bool(month_first):
                observed.add(bool(day_first))
    if len(observed) == 1:
        return observed.pop()
    if not observed and len(declared) == 1:
        return declared.pop()
    # Use the local convention for ambiguous dates without a consistent source hint.
    return True


def opaque(secret, purpose, value):
    return derive(secret, purpose, value).hex()[:24]


def policy_plan(record, detection, group, secret, policy):
    targets = []
    slot = None
    fhir_id = None
    resource_ids = {}
    if record.format == "fhir":
        for hit in detection.sensitive_targets:
            if hit.channel in {"header", "key", "filename"} or hit.path[-1:] != ("id",):
                continue
            resource = get(record.content, hit.path[:-1])
            if isinstance(resource, Mapping) and "resourceType" in resource:
                resource_ids[hit.path] = resource["resourceType"]
    managed_spans = resource_id_spans(record.content, resource_ids) if resource_ids else {}
    edited_ids = set()
    for hit in detection.sensitive_targets:
        if hit.channel in {"header", "key", "filename"}:
            continue
        value = extract(record, hit)
        kind = {
            "PATIENT_NAME": "patient_name", "DATE": "date", "DOB": "date",
            "AGE": "age", "ATTACHMENT_DATA": "attachment",
        }.get(hit.kind, "location" if hit.kind in _LOCATIONS else "identifier")
        span = (hit.start, hit.end) if hit.start is not None else None
        managed = managed_spans.get(hit.path)
        if span and managed and managed[0] <= span[0] and span[1] <= managed[1]:
            continue
        if hit.path in resource_ids:
            if hit.path in edited_ids:
                continue
            edited_ids.add(hit.path)
            value, span = get(record.content, hit.path), None
        target = Target(hit.path, kind, value, span)
        targets.append(target)
        if hit.channel == "content" and kind == "patient_name" and slot is None:
            slot = target
        if resource_ids.get(hit.path) == "Patient":
            fhir_id = target
        if hit.channel == "content" and slot is None and record.format == "fhir":
            if hit.path and hit.path[-1] == "value" and hit.kind in {"UHID", "MRN"}:
                slot = target
    if slot is None:
        slot = fhir_id
    if group is not None and slot is None:
        slot = next((t for t in targets if t.kind == "identifier" and t.path not in resource_ids), None)
    for hit in detection.protected_clinical_targets:
        span = (hit.start, hit.end) if hit.start is not None else None
        targets.append(Target(hit.path, "protected", "", span))

    plan = build_plan(PolicyDetection(record.record_key, {}, tuple(targets), slot),
                      group, secret, policy, day_first=detection.day_first,
                      fallback_day_first=detection.fallback_day_first)
    edits = []
    for edit in plan.edits:
        target, replacement = edit.target, edit.replacement
        if target.span is None:
            if target.path in resource_ids:
                if not (target == slot and plan.patient):
                    replacement = "id-" + opaque(secret, "fhir-id", target.value)
            if record.format == "fhir" and target.path[-2:] == ("meta", "source"):
                replacement = "urn:secret-wards:" + opaque(secret, "fhir-source", target.value)
            edits.append(FieldEdit(target.path, replacement))
        else:
            edits.append(SpanEdit(target.path, *target.span, replacement))

    for hit in detection.sensitive_targets:
        if hit.channel == "key":
            if record.format == "fhir":
                raise Quarantine("unsafe FHIR key")
            replacement = "field-" + opaque(secret, "json-key", str(hit.path[-1]))
            key_edit = KeyEdit(hit.path, replacement)
            if key_edit not in edits:
                edits.append(key_edit)
    return AdapterPlan(plan.record_key, tuple(edits), plan.patient), any(
        edit.target.kind in {"age", "location", "date"} for edit in plan.edits
    )


def filename_surfaces(relative: Path):
    for index, part in enumerate(relative.parts):
        probe = Path(part).stem if index == len(relative.parts) - 1 else part
        yield TextSurface(probe, "filename", (index,))


def safe_path(item, relative, secret):
    parts = relative.parts
    sensitive = {
        hit.path[0] for detection in item.detections for hit in detection.sensitive_targets
        if hit.channel == "filename"
    }
    safe_parts = []
    for index, part in enumerate(parts):
        if (index in sensitive or not _SAFE_PART.fullmatch(part)
                or part.split(".")[0].upper() in _RESERVED):
            part = "file-" + opaque(secret, "export-path", "/".join(parts[:index + 1]))
            if index == len(parts) - 1:
                part += relative.suffix.lower()
        safe_parts.append(part)
    return tuple(safe_parts[:-1]), safe_parts[-1]


def run_pipeline(source: Path, output: Path, secret: bytes, policy: Policy) -> dict:
    start = perf_counter()
    source, output = source.resolve(), output.resolve()
    if not source.is_dir() or output == source or output.is_relative_to(source):
        raise ValueError("invalid input or output directory")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output must be an empty directory")

    adapter = FileAdapters(record_factory=ParsedRecord, result_factory=ExportStatus)
    items = []
    for path in discover(source):
        document = adapter.ingest(path, source)
        path_surfaces = tuple(filename_surfaces(path.relative_to(source)))
        detections = tuple(inspect_record(record, path_surfaces) for record in document.records)
        day_first = fallback_date_order(document.records, detections)
        detections = tuple(replace(result, fallback_day_first=day_first) for result in detections)
        envelope = None
        if document.outer_content is not None:
            envelope = ParsedRecord("envelope:" + path.relative_to(source).as_posix(),
                                    path, "", "json", document.outer_content)
        items.append(WorkItem(path, document, detections, envelope, day_first))
    groups = link_records(result for item in items for result in item.detections)

    (output / "sanitized").mkdir(parents=True)
    counts = dict.fromkeys((
        "files_total", "files_sanitized", "files_quarantined", "records_processed",
        "identifiers_detected", "records_linked", "records_generalized",
        "records_suppressed", "records_quarantined",
    ), 0)
    counts["files_total"] = len(items)
    files, records = [], []
    for item in items:
        document = item.document
        counts["identifiers_detected"] += sum(
            hit.kind not in {"AGE", "DATE", "DISTRICT", "TEHSIL", "VILLAGE", "PIN"}
            for detection in item.detections for hit in detection.sensitive_targets
        )
        try:
            plans = [
                policy_plan(record, result, groups[result.record_key], secret, policy)
                for record, result in zip(document.records, item.detections)
            ]
            if document.reason:
                status = adapter.export(document, (), output)
            else:
                folders, filename = safe_path(item, item.source.relative_to(source), secret)
                headers = dict.fromkeys(
                    hit.path[-1] for result in item.detections for hit in result.sensitive_targets
                    if hit.channel == "header"
                )
                file_edits = [FilenameEdit(filename), *(
                    HeaderEdit(header, "field-" + opaque(secret, "header", header))
                    for header in headers
                )]
                if item.envelope is not None:
                    envelope_detection = replace(
                        inspect_record(item.envelope), fallback_day_first=item.fallback_day_first,
                    )
                    outer, _ = policy_plan(item.envelope, envelope_detection, None, secret, policy)
                    file_edits.extend(outer.edits)
                status = adapter.export(document, (plan for plan, _ in plans), output,
                                        file_edits=file_edits, folders=folders)
        except Quarantine:
            status = ExportStatus(document.input_sha256, None, "quarantined",
                                  "privacy_rewrite_failed", {})

        if status.status != "exported":
            files.append({"input_sha256": status.input_sha256, "output": None,
                          "status": "quarantined", "reason": status.safe_reason})
            counts["records_quarantined"] += len(document.records)
            continue
        files.append({"input_sha256": status.input_sha256, "output": status.safe_output_path,
                      "status": "sanitized"})
        counts["files_sanitized"] += 1
        for plan, generalized in plans:
            records.append({"file": status.safe_output_path,
                            "loc": status.final_record_locations[plan.record_key],
                            "patient": plan.patient})
            counts["records_processed"] += 1
            counts["records_linked"] += plan.patient is not None
            counts["records_generalized"] += generalized

    counts["files_quarantined"] = len(items) - counts["files_sanitized"]
    write_reports(output, files, counts, records, perf_counter() - start)
    return counts
