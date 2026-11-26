"""Adapter edit vocabulary. Paths always address the original document."""

from dataclasses import dataclass
from decimal import Decimal

from ._errors import Reject

PathParts = tuple[str | int, ...]


@dataclass(frozen=True, repr=False)
class FieldEdit:
    path: PathParts
    replacement: object


@dataclass(frozen=True, repr=False)
class SpanEdit:
    path: PathParts
    start: int
    end: int
    replacement: str


@dataclass(frozen=True, repr=False)
class KeyEdit:
    path: PathParts
    replacement: str


@dataclass(frozen=True, repr=False)
class HeaderEdit:
    column: str
    replacement: str


@dataclass(frozen=True, repr=False)
class FilenameEdit:
    replacement: str


def apply_value(original, edits):
    if len(edits) == 1 and isinstance(edits[0], FieldEdit):
        value = edits[0].replacement
        if isinstance(original, (dict, list)) or type(value) not in (
            str, bool, int, float, Decimal, type(None)
        ):
            raise Reject("invalid_rewrite")
        if isinstance(value, float):
            return Decimal(str(value))
        return value
    if not isinstance(original, str) or any(not isinstance(e, SpanEdit) for e in edits):
        raise Reject("invalid_rewrite")
    for edit in edits:
        if (
            type(edit.start) is not int or type(edit.end) is not int
            or not 0 <= edit.start < edit.end <= len(original)
            or not isinstance(edit.replacement, str)
        ):
            raise Reject("invalid_rewrite")
    parts = []
    cursor = 0
    for edit in sorted(edits, key=lambda e: e.start):
        if edit.start < cursor:
            raise Reject("overlapping_edits")
        parts.extend((original[cursor:edit.start], edit.replacement))
        cursor = edit.end
    parts.append(original[cursor:])
    return "".join(parts)


def group_values(edits):
    groups = {}
    for edit in edits:
        if not isinstance(edit, (FieldEdit, SpanEdit)) or not isinstance(edit.path, tuple):
            raise Reject("invalid_rewrite")
        if any(type(part) not in (str, int) for part in edit.path):
            raise Reject("invalid_field_path")
        groups.setdefault(edit.path, []).append(edit)
    return groups
