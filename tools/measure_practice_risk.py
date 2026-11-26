"""Measure age and district uniqueness on the organiser's synthetic practice data.

Use the practice answer key for comparison only. Print aggregate counts and keep
the truth file outside both the input folder and the published output.
"""

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import re

from secret_wards.contracts import ParsedRecord
from secret_wards.detection import _kind, _label
from secret_wards.file_io import FileAdapters
from secret_wards.normalization import matching_text


def signature(record, *, exported):
    values = {_kind(_label(key)): matching_text(str(value)).strip()
              for key, value in record.items()}
    age, district = values.get("AGE", ""), values.get("DISTRICT", "")
    pattern = r"\d{1,3}\s*[-–]\s*\d{1,3}" if exported else r"\d{1,3}(?=\s|/|$)"
    match = re.match(pattern, age)
    if not match or not district:
        return None
    return re.sub(r"\s+", "", match[0]), " ".join(district.split())


def unique_count(signatures):
    return sum(count == 1 for count in Counter(signatures).values())


def measure(input_root, output_root, truth):
    report = json.loads((output_root / "report.json").read_text(encoding="utf-8"))
    exports = defaultdict(list)
    for item in report["files"]:
        if item["status"] == "sanitized":
            exports[item["input_sha256"]].append(item["output"])
    locations = {}
    with (output_root / "records.jsonl").open(encoding="utf-8") as lines:
        for line in lines:
            row = json.loads(line)
            locations[row["file"], row["loc"]] = row.get("out", row["loc"])

    picked = {}
    adapter = FileAdapters(record_factory=ParsedRecord, result_factory=dict)
    safe_folder = output_root / "sanitized"
    for name, entry in sorted(truth["files"].items()):
        source = Path(name)
        if len(source.parts) < 2 or source.parts[0] != "registration":
            continue
        choices = exports[entry["sha256"]]
        if len(choices) != 1:
            continue
        output_name, = choices
        output = (output_root / output_name).resolve()
        if not output.is_relative_to(safe_folder) or output.suffix.lower() not in {".csv", ".tsv"}:
            continue
        document = adapter.ingest(input_root / source, input_root)
        if document.reason or document.input_sha256 != entry["sha256"]:
            continue
        delimiter = "\t" if output.suffix.lower() == ".tsv" else ","
        with output.open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream, delimiter=delimiter))
        for record in document.records:
            patient = entry["units"].get(record.loc, {}).get("patient")
            location = locations.get((output_name, record.loc), "")
            position = re.fullmatch(r"row:(\d+)", location)
            if not patient or patient in picked or not position or int(position[1]) >= len(rows):
                continue
            raw = signature(record.content, exported=False)
            clean = signature(rows[int(position[1])], exported=True)
            if raw and clean:
                picked[patient] = raw, clean
    before = unique_count(raw for raw, _ in picked.values())
    after = unique_count(clean for _, clean in picked.values())
    return {"matched_patients": len(picked), "unique_before": before, "unique_after": after}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    args = parser.parse_args()
    try:
        truth = json.loads(args.truth.read_text(encoding="utf-8"))
        result = measure(args.input.resolve(), args.output.resolve(), truth)
    except (OSError, KeyError, ValueError, TypeError):
        parser.exit(2, "Could not read the practice inputs, answer key or output.\n")
    if not result["matched_patients"]:
        parser.exit(1, "No comparable registration records were found.\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
