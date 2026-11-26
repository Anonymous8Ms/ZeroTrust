"""Discover, hash, ingest and safely publish files using the format adapters."""

import copy
import hashlib
import os
import re
import stat
import tempfile
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .adapters import FieldEdit, FilenameEdit, HeaderEdit, KeyEdit, SpanEdit
from .adapters._edits import PathParts
from .adapters._errors import Reject
from .adapters.fhir import rewrite_references, validate_fhir
from .adapters.json_records import (
    final_pointer, get, parse_json, pointer, record_roots, rewrite_json, write_json,
)
from .adapters.tabular import Table, parse_table, rewrite_table, write_table
from .adapters.text_notes import check_text, decode_text, rewrite_note

_FORMATS = {".csv": "csv", ".tsv": "tsv", ".txt": "text", ".json": "json", ".fhir": "fhir"}
_SAFE_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10)
}

Edit = FieldEdit | FilenameEdit | HeaderEdit | KeyEdit | SpanEdit


class Plan(Protocol):
    @property
    def record_key(self) -> str: ...

    @property
    def edits(self) -> Iterable[Edit]: ...


@dataclass(frozen=True, repr=False)
class IngestedFile:
    input_sha256: str | None
    reason: str | None = None
    records: tuple = ()
    _format: str | None = None
    _suffix: str = ""
    _content: object = None
    _record_paths: dict[str, PathParts] = field(default_factory=dict)


def discover(input_root):
    """Yield file candidates in stable order without following symbolic links."""
    root = Path(input_root)

    def visit(folder):
        with os.scandir(folder) as entries:
            entries = sorted(entries, key=lambda entry: entry.name)
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                yield from visit(entry.path)
            else:
                yield Path(entry.path)

    try:
        yield from visit(root)
    except (OSError, ValueError, RecursionError):
        raise Reject("discovery_failed") from None


def _read_input(path, max_bytes):
    digest = hashlib.sha256()
    data = bytearray()
    size = 0
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Reject("not_regular_file")
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            if size <= max_bytes:
                data.extend(chunk)
    return digest.hexdigest(), data if size <= max_bytes else None


class FileAdapters:
    def __init__(self, *, record_factory, result_factory, fhir_validator=None,
                 max_input_bytes=32 * 1024 * 1024, max_records=100_000):
        self.record_factory = record_factory
        self.result_factory = result_factory
        self.fhir_validator = fhir_validator
        self.max_input_bytes = max_input_bytes
        self.max_records = max_records

    def _validate_fhir(self, content):
        validate_fhir(content)
        if self.fhir_validator is not None:
            try:
                valid = self.fhir_validator(content)
            except Exception:
                raise Reject("invalid_fhir") from None
            if valid is not True:
                raise Reject("invalid_fhir")

    def ingest(self, path, input_root, *, encoding=None, json_record_paths=None):
        """Read an input once, retaining original structure for later rewrites."""
        digest = None
        try:
            path = Path(path)
            input_root = Path(input_root).resolve(strict=True)
            path = path.parent.resolve(strict=True) / path.name
            if not path.is_relative_to(input_root):
                raise Reject("outside_input_root")
            if path.is_symlink():
                raise Reject("not_regular_file")
            digest, raw = _read_input(path, self.max_input_bytes)
            suffix = path.suffix.lower()
            file_format = _FORMATS.get(suffix)
            if file_format is None:
                raise Reject("unsupported_format")
            if raw is None:
                raise Reject("input_too_large")
            text = decode_text(raw, encoding)
            root_relative = path.relative_to(input_root).as_posix()
            file_key = hashlib.sha256(os.fsencode(root_relative) + b"\0" + digest.encode()).hexdigest()
            records = []
            record_paths = {}

            def add(location, record_content, record_path):
                key = hashlib.sha256(f"{file_key}\0{location}".encode()).hexdigest()
                record_paths[key] = record_path
                records.append(self.record_factory(
                    record_key=key, source_file=path, loc=location,
                    format=file_format, content=record_content,
                ))

            if file_format in {"csv", "tsv"}:
                content = parse_table(text, "," if file_format == "csv" else "\t", self.max_records)
                for index, row in enumerate(content.rows):
                    add(f"row:{index}", dict(zip(content.header, row)), (index,))
            elif file_format == "text":
                content = text
                add("doc", text, ())
            else:
                content = parse_json(text)
                if file_format == "json" and isinstance(content, dict) and "resourceType" in content:
                    file_format = "fhir"
                if file_format == "fhir":
                    self._validate_fhir(content)
                    add("doc", copy.deepcopy(content), ())
                else:
                    for location in record_roots(content, json_record_paths, self.max_records):
                        add(pointer(location), copy.deepcopy(get(content, location)), location)
            return IngestedFile(
                digest, None, tuple(records), file_format, suffix, content, record_paths
            )
        except Reject as exc:
            return IngestedFile(digest, str(exc))
        except OSError:
            return IngestedFile(digest, "input_unreadable")
        except (UnicodeError, ValueError, RecursionError):
            return IngestedFile(digest, "malformed_input")

    def export(self, document, plans, output_root, *, file_edits=()):
        """Apply complete plans and publish one validated file, or quarantine it."""
        def result(reason=None, path=None, locations=None):
            return self.result_factory(
                input_sha256=document.input_sha256, safe_output_path=path,
                status="quarantined" if reason else "exported", safe_reason=reason,
                final_record_locations=locations if locations is not None else {},
            )

        if document.reason:
            return result(document.reason)
        try:
            content, filename, locations = _rewrite(document, plans, file_edits)
            self._publish(document._format, content, filename, Path(output_root))
        except Reject as exc:
            return result(str(exc))
        except FileExistsError:
            return result("output_exists")
        except OSError:
            return result("output_write_failed")
        except (TypeError, AttributeError, ValueError, ArithmeticError, RecursionError):
            return result("invalid_rewrite")
        return result(path=f"sanitized/{filename}", locations=locations)

    def _publish(self, file_format, content, filename, output_root):
        # Stage outside sanitized/ and link only after validation. link() is atomic
        # and fails if another export already owns this filename.
        output_root.mkdir(parents=True, exist_ok=True)
        safe_dir = output_root / "sanitized"
        safe_dir.mkdir(exist_ok=True)
        directory_fd = os.open(safe_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stage = None
        published = False
        try:
            fd, stage = tempfile.mkstemp(prefix=".secret-wards-", dir=output_root)
            with os.fdopen(fd, "w+", encoding="utf-8", newline="") as stream:
                if file_format in {"csv", "tsv"}:
                    write_table(content, stream)
                elif file_format == "text":
                    stream.write(content)
                else:
                    write_json(content, stream)
                stream.flush()
                stream.seek(0)
                staged = check_text(stream.read())
                if file_format in {"csv", "tsv"}:
                    observed = parse_table(staged, content.delimiter, self.max_records)
                elif file_format == "text":
                    observed = staged
                else:
                    observed = parse_json(staged)
                    if file_format == "fhir":
                        self._validate_fhir(observed)
                if observed != content:
                    raise Reject("output_validation_failed")
                os.fsync(stream.fileno())
            os.link(stage, filename, dst_dir_fd=directory_fd)
            published = True
        finally:
            os.close(directory_fd)
            if stage is not None:
                try:
                    os.unlink(stage)
                except FileNotFoundError:
                    pass
                except OSError:
                    if not published:
                        raise


def _rewrite(document, plans, file_edits):
    locations = {}
    contents = document._content
    file_format = document._format
    filename = None
    headers = {}
    key_edits = []
    values = []
    table_rows = {}

    def collect(edit, path=None):
        nonlocal filename
        if isinstance(edit, FilenameEdit):
            if filename is not None or not isinstance(edit.replacement, str):
                raise Reject("invalid_rewrite")
            filename = edit.replacement
        elif isinstance(edit, HeaderEdit):
            if (
                not isinstance(contents, Table) or edit.column not in contents.header
                or edit.column in headers or not isinstance(edit.replacement, str)
                or not edit.replacement
            ):
                raise Reject("invalid_rewrite")
            headers[edit.column] = edit.replacement
        elif isinstance(edit, KeyEdit):
            if file_format != "json" or not isinstance(edit.path, tuple):
                raise Reject("invalid_rewrite")
            key_edits.append(KeyEdit((path or ()) + edit.path, edit.replacement))
        elif isinstance(edit, (FieldEdit, SpanEdit)):
            if not isinstance(edit.path, tuple):
                raise Reject("invalid_field_path")
            if isinstance(contents, Table):
                if path is None or len(edit.path) != 1 or edit.path[0] not in contents.header:
                    raise Reject("invalid_field_path")
                table_rows.setdefault(path[0], []).append(edit)
                return
            absolute = (path or ()) + edit.path
            values.append(
                FieldEdit(absolute, edit.replacement) if isinstance(edit, FieldEdit)
                else SpanEdit(absolute, edit.start, edit.end, edit.replacement)
            )
        else:
            raise Reject("invalid_rewrite")

    seen = set()
    for plan in plans:
        key = plan.record_key
        if key not in document._record_paths or key in seen:
            raise Reject("invalid_record_plan")
        seen.add(key)
        path = document._record_paths[key]
        for edit in plan.edits:
            collect(edit, path)
    if seen != document._record_paths.keys():
        raise Reject("missing_record_plan")
    for edit in file_edits:
        collect(edit)

    if filename is None:
        filename = f"file-{uuid.uuid4().hex}{document._suffix}"
    if (
        not _SAFE_NAME.fullmatch(filename) or Path(filename).suffix.lower() != document._suffix
        or filename.split(".")[0].upper() in _RESERVED_NAMES
    ):
        raise Reject("unsafe_output_path")

    if isinstance(contents, Table):
        rewritten = rewrite_table(contents, headers, table_rows)
        locations = {key: f"row:{path[0]}" for key, path in document._record_paths.items()}
    elif file_format == "text":
        rewritten = rewrite_note(contents, values)
        locations = dict.fromkeys(document._record_paths, "doc")
    else:
        rewritten, renames = rewrite_json(contents, values, key_edits)
        if file_format == "fhir":
            rewrite_references(contents, rewritten, {edit.path for edit in values})
            locations = dict.fromkeys(document._record_paths, "doc")
        else:
            if isinstance(rewritten, dict) and "resourceType" in rewritten:
                raise Reject("format_changed")
            locations = {
                key: final_pointer(path, renames)
                for key, path in document._record_paths.items()
            }
    return rewritten, filename, locations
