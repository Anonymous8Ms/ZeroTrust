"""Run the two privacy passes with injected team components."""
from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
from time import perf_counter

from .contracts import Adapter, DetectionResult, Detector, Linker, ParsedFile, Quarantine
from .privacy import Policy, build_plan
from .reporting import write_reports


@dataclass
class WorkItem:
    digest: str
    parsed: ParsedFile | None = None
    detections: tuple[DetectionResult, ...] = ()


def quarantine(item: WorkItem, reason: str) -> dict:
    return {
        "input_sha256": item.digest, "output": None, "status": "quarantined",
        "reason": reason,
    }


def run_pipeline(source: Path, output: Path, secret: bytes, policy: Policy,
                 adapter: Adapter, detector: Detector, linker: Linker) -> None:
    start = perf_counter()
    source, output = source.resolve(), output.resolve()
    if not source.is_dir() or output == source or output.is_relative_to(source):
        raise ValueError("invalid input or output directory")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("output must be an empty directory")
    entries = sorted(source.rglob("*"))
    if any(path.is_symlink() or not (path.is_file() or path.is_dir()) for path in entries):
        raise ValueError("unsupported filesystem entry")
    items = []
    for path in entries:
        if not path.is_file():
            continue
        raw = path.read_bytes()
        item = WorkItem(hashlib.sha256(raw).hexdigest())
        items.append(item)
        try:
            parsed = adapter.parse(path.relative_to(source).as_posix(), raw)
            item.detections = tuple(detector.detect(record) for record in parsed.records)
            if tuple(result.record_key for result in item.detections) != tuple(
                record.record_key for record in parsed.records
            ):
                raise Quarantine
            item.parsed = parsed
        except Quarantine:
            continue

    del entries
    detections = [result for item in items if item.parsed for result in item.detections]
    keys = {result.record_key for result in detections}
    if len(keys) != len(detections):
        raise ValueError("duplicate internal record key")
    groups = linker.resolve(detections)
    if set(groups) != keys:
        raise ValueError("invalid linkage results")

    sanitized = output / "sanitized"
    sanitized.mkdir(parents=True)
    counts = dict.fromkeys((
        "files_total", "files_sanitized", "files_quarantined", "records_processed",
        "identifiers_detected", "records_linked", "records_generalized",
        "records_suppressed", "records_quarantined",
    ), 0)
    counts["files_total"] = len(items)
    files, records = [], []
    for item in items:
        if item.parsed is None:
            files.append(quarantine(item, "parse or detection failed"))
            continue
        counts["identifiers_detected"] += sum(
            target.kind in {"identifier", "patient_name"}
            for detection in item.detections for target in detection.targets
        )
        try:
            plans = {
                result.record_key: build_plan(result, groups[result.record_key], secret, policy)
                for result in item.detections
            }
            result = adapter.render(item.parsed, plans)
            relative = PurePosixPath(result.path)
            if (relative.is_absolute() or not relative.parts or ".." in relative.parts
                    or set(result.locations) != set(plans)):
                raise Quarantine
            target = sanitized.joinpath(*relative.parts)
            if target.exists() or any(parent.is_file() for parent in target.parents):
                raise Quarantine
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(result.content)
        except Quarantine:
            files.append(quarantine(item, "rewrite or export validation failed"))
            counts["records_quarantined"] += len(item.detections)
            continue

        safe_path = f"sanitized/{relative.as_posix()}"
        files.append({"input_sha256": item.digest, "output": safe_path, "status": "sanitized"})
        counts["files_sanitized"] += 1
        for key, plan in plans.items():
            records.append({"file": safe_path, "loc": result.locations[key], "patient": plan.patient})
            counts["records_processed"] += 1
            counts["records_linked"] += plan.patient is not None
            counts["records_generalized"] += any(
                edit.target.kind in {"age", "location", "date"} for edit in plan.edits
            )

    counts["files_quarantined"] = len(items) - counts["files_sanitized"]
    write_reports(output, files, counts, records, perf_counter() - start)
