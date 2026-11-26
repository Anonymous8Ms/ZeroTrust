"""Parse and rewrite nested JSON while retaining exact decimal values."""

import json
import re
from decimal import Decimal

from ._edits import apply_value, group_values
from ._errors import Reject
from ..contracts import REDACTED_ATTACHMENT_DATA


def _object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise Reject("duplicate_json_key")
    return result


def _constant(_):
    raise Reject("malformed_json")


_END = object()
_SURROGATE = re.compile(r"[\ud800-\udfff]")


def parse_json(text):
    try:
        value = json.loads(
            text, object_pairs_hook=_object, parse_float=Decimal, parse_constant=_constant
        )
        pending = [iter((value,))]
        while pending:
            node = next(pending[-1], _END)
            if node is _END:
                pending.pop()
            elif isinstance(node, dict):
                pending.extend((iter(node.values()), iter(node)))
            elif isinstance(node, list):
                pending.append(iter(node))
            elif isinstance(node, str) and _SURROGATE.search(node):
                raise Reject("malformed_json")
        return value
    except (ValueError, ArithmeticError, RecursionError):
        raise Reject("malformed_json") from None


# Payloads in these fields are opaque to the text detector.
_ATTACHMENT_KEYS = {"attachment", "attachments", "valueattachment", "photo", "presentedform"}
_PAYLOAD_KEYS = {"data", "content", "body", "payload"}
_ENCODED_KEYS = {"base64", "database64", "contentbase64", "encodeddata", "attachmentdata"}
_DATA_URI = re.compile(r"^\s*data:[^,\s]*,", re.IGNORECASE)


def reject_opaque_attachments(value):
    """Reject residual opaque payloads before any export is staged on disk."""
    pending = [(value, False)]
    while pending:
        node, attachment = pending.pop()
        if isinstance(node, dict):
            fields = {_field_name(key): child for key, child in node.items()}
            attachment = attachment or fields.get("resourcetype") == "Binary"
            has_media_type = "contenttype" in fields
            for key, child in node.items():
                field = _field_name(key)
                payload = field in _ENCODED_KEYS or (
                    field in _PAYLOAD_KEYS and (attachment or (has_media_type and isinstance(child, str)))
                )
                if payload and child not in (None, "", REDACTED_ATTACHMENT_DATA):
                    raise Reject("embedded_attachment")
                nested_attachment = attachment and isinstance(child, (dict, list))
                pending.append((child, nested_attachment or field in _ATTACHMENT_KEYS))
        elif isinstance(node, list):
            pending.extend((child, attachment) for child in node)
        elif isinstance(node, str):
            if (attachment and node.strip()) or _DATA_URI.match(node):
                raise Reject("embedded_attachment")


def _field_name(key):
    return "".join(char for char in key.casefold() if char.isalnum())


def write_json(value, stream):
    """Emit Decimal values as JSON numbers without rounding clinical values."""
    def emit(node):
        if isinstance(node, dict):
            stream.write("{")
            for index, (key, child) in enumerate(node.items()):
                if index:
                    stream.write(",")
                stream.write(json.dumps(key, ensure_ascii=False))
                stream.write(":")
                emit(child)
            stream.write("}")
        elif isinstance(node, list):
            stream.write("[")
            for index, child in enumerate(node):
                if index:
                    stream.write(",")
                emit(child)
            stream.write("]")
        elif isinstance(node, Decimal):
            if not node.is_finite():
                raise Reject("invalid_rewrite")
            stream.write(str(node))
        else:
            stream.write(json.dumps(node, ensure_ascii=False, allow_nan=False))

    emit(value)
    stream.write("\n")


def pointer(path):
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in path)


def get(tree, path):
    for part in path:
        if isinstance(tree, list) and type(part) is int and 0 <= part < len(tree):
            tree = tree[part]
        elif isinstance(tree, dict) and type(part) is str and part in tree:
            tree = tree[part]
        else:
            raise Reject("invalid_field_path")
    return tree


def record_roots(content, paths, limit):
    if paths is None:
        if isinstance(content, list):
            if len(content) > limit:
                raise Reject("record_limit")
            return [(index,) for index in range(len(content))]
        if isinstance(content, dict):
            arrays = []
            pending = [((), content)]
            while pending:
                prefix, node = pending.pop()
                for key, value in node.items():
                    path = (*prefix, key)
                    if isinstance(value, dict):
                        pending.append((path, value))
                    elif (key.casefold() in {"records", "visits", "patients", "encounters"}
                          and isinstance(value, list) and value
                          and all(isinstance(record, dict) for record in value)):
                        arrays.append((path, len(value)))
            if len(arrays) > 1:
                raise Reject("ambiguous_record_collections")
            if arrays:
                path, length = arrays[0]
                if length > limit:
                    raise Reject("record_limit")
                return [(*path, index) for index in range(length)]
        return [()]
    selected = set()
    result = []
    for path in paths:
        if len(result) >= limit:
            raise Reject("record_limit")
        if not isinstance(path, tuple) or any(type(part) not in (str, int) for part in path):
            raise Reject("invalid_record_path")
        if path in selected:
            raise Reject("invalid_record_path")
        get(content, path)
        selected.add(path)
        result.append(path)
    if any(path[:i] in selected for path in result for i in range(len(path))):
        raise Reject("overlapping_records")
    return result


def rewrite_json(original, values, key_edits):
    replacements = {path: apply_value(get(original, path), edits)
                    for path, edits in group_values(values).items()}
    renames = {}
    for edit in key_edits:
        path = edit.path
        if (
            not isinstance(path, tuple) or not path or type(path[-1]) is not str
            or any(type(part) not in (str, int) for part in path)
            or not isinstance(edit.replacement, str) or path in renames
        ):
            raise Reject("invalid_rewrite")
        get(original, path)
        renames[path] = edit.replacement

    def visit(node, path):
        if path in replacements:
            return replacements[path]
        if isinstance(node, list):
            return [visit(child, path + (i,)) for i, child in enumerate(node)]
        if isinstance(node, dict):
            result = {}
            for key, child in node.items():
                child_path = path + (key,)
                name = renames.get(child_path, key)
                if name in result:
                    raise Reject("duplicate_json_key")
                result[name] = visit(child, child_path)
            return result
        return node

    return visit(original, ()), renames


def final_pointer(path, renames):
    return pointer(tuple(renames.get(path[:i + 1], part) for i, part in enumerate(path)))
