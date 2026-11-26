"""Read, edit and write CSV and TSV tables."""

import csv
import io
import re
from dataclasses import dataclass

from ._edits import apply_value, group_values
from ._errors import Reject


# Check quoting rules absent from csv.reader(strict=True), including a quote
# appearing in the middle of an unquoted field.
def _table_pattern(delimiter):
    separator = re.escape(delimiter)
    field = rf'(?:[^"{separator}\r\n]*|"(?:""|[^"])*")'
    return re.compile(rf"{field}(?:{separator}{field})*")


_TABLE_PATTERNS = {delimiter: _table_pattern(delimiter) for delimiter in ",\t"}


@dataclass(repr=False)
class Table:
    header: tuple[str, ...]
    rows: list[tuple[str, ...]]
    layout: list[tuple[str, bool]]
    delimiter: str


def parse_table(text, delimiter, max_records):
    stream = io.StringIO(text, newline="")
    reader = csv.reader(stream, delimiter=delimiter, strict=True)
    header = None
    rows = []
    layout = []
    previous = 0
    try:
        for row in reader:
            end = stream.tell()
            terminator = next(
                (suffix for suffix in ("\r\n", "\r", "\n")
                 if text.endswith(suffix, previous, end)),
                "",
            )
            if '"' in text[previous:end] and not _TABLE_PATTERNS[delimiter].fullmatch(
                text, previous, end - len(terminator)
            ):
                raise Reject("malformed_table")
            previous = end
            if len(layout) >= max_records + 10_001 or len(row) > 4096:
                raise Reject("table_structure_limit")
            layout.append((terminator, bool(row)))
            if not row:
                continue
            if header is None:
                if any(not name for name in row) or len(set(row)) != len(row):
                    raise Reject("malformed_table")
                header = tuple(row)
            else:
                if len(row) != len(header):
                    raise Reject("malformed_table")
                if len(rows) >= max_records:
                    raise Reject("record_limit")
                rows.append(tuple(row))
    except csv.Error:
        raise Reject("malformed_table") from None
    if header is None:
        raise Reject("malformed_table")
    return Table(header, rows, layout, delimiter)


def write_table(table, stream):
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, delimiter=table.delimiter, lineterminator="\r\n")
    rows = iter(table.rows)
    row = table.header
    for terminator, populated in table.layout:
        if populated:
            writer.writerow(row)
            stream.write(buffer.getvalue()[:-2])
            buffer.seek(0)
            buffer.truncate()
            row = next(rows, None)
        stream.write(terminator)


def rewrite_table(contents, headers, table_rows):
    header = tuple(headers.get(column, column) for column in contents.header)
    if len(set(header)) != len(header):
        raise Reject("duplicate_header")
    rows = contents.rows.copy()
    positions = {column: index for index, column in enumerate(contents.header)}
    for index, edits in table_rows.items():
        row = list(rows[index])
        for (column,), group in group_values(edits).items():
            position = positions[column]
            value = apply_value(row[position], group)
            if not isinstance(value, str):
                raise Reject("invalid_rewrite")
            row[position] = value
        rows[index] = tuple(row)
    return Table(header, rows, contents.layout, contents.delimiter)
