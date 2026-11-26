"""Interfaces shared by format adapters, detection, linkage and policy."""
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

Path = tuple[str | int, ...]
Kind = Literal["identifier", "patient_name", "date", "age", "location", "protected"]


class Quarantine(Exception):
    """An input could not be processed safely."""


@dataclass(frozen=True)
class ParsedRecord:
    record_key: str
    source_file: str
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


@dataclass(frozen=True)
class ParsedFile:
    records: tuple[ParsedRecord, ...]
    structure: object


@dataclass(frozen=True)
class ExportResult:
    # Paths are relative to sanitized/. The pipeline controls publication.
    path: str
    content: bytes
    locations: Mapping[str, str]


class Adapter(Protocol):
    def parse(self, source: str, raw: bytes) -> ParsedFile: ...

    def render(self, parsed: ParsedFile, plans: Mapping[str, RewritePlan]) -> ExportResult: ...


class Detector(Protocol):
    def detect(self, record: ParsedRecord) -> DetectionResult: ...


class Linker(Protocol):
    def resolve(self, detections: Sequence[DetectionResult]) -> Mapping[str, str | None]: ...
