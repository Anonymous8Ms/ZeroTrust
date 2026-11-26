"""Interfaces shared by format adapters, detection, linkage and policy."""
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path as FilePath
from typing import Literal

Path = tuple[str | int, ...]
Kind = Literal["identifier", "patient_name", "date", "age", "location", "protected"]


class Quarantine(Exception):
    """An input could not be processed safely."""


@dataclass(frozen=True)
class ParsedRecord:
    record_key: str
    source_file: str | FilePath
    loc: str
    format: str
    content: object


@dataclass(frozen=True)
class Target:
    path: Path
    kind: Kind
    value: str
    span: tuple[int, int] | None = None
    surface: Literal["value", "key", "filename", "metadata"] = "value"


@dataclass(frozen=True)
class DetectionResult:
    record_key: str
    evidence: Mapping[str, str]
    targets: tuple[Target, ...]
    # Reuse a patient field or a suitable insertion point supplied by the adapter/detector.
    patient_slot: Target | None = None


@dataclass(frozen=True)
class Edit:
    target: Target
    replacement: str


@dataclass(frozen=True)
class RewritePlan:
    record_key: str
    edits: tuple[Edit, ...]
    patient: str | None
