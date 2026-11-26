"""Synthetic parsed records for detection and linkage tests."""

from dataclasses import dataclass, field
from pathlib import Path
import csv


_ROOT = Path(__file__).parent / "fixtures"


@dataclass(frozen=True)
class ParsedRecord:
    record_key: str
    source_file: str = field(repr=False)
    loc: str
    format: str
    content: object = field(repr=False)


def registration_fixture() -> list[ParsedRecord]:
    with (_ROOT / "registration.csv").open(encoding="utf-8", newline="") as file:
        return [
            ParsedRecord(f"registration-{index}", "synthetic-csv", f"row:{index}", "csv", row)
            for index, row in enumerate(csv.DictReader(file))
        ]


def note_fixture(name: str) -> ParsedRecord:
    return ParsedRecord(name, "synthetic-note", "doc", "text", (_ROOT / f"{name}.txt").read_text(encoding="utf-8"))
