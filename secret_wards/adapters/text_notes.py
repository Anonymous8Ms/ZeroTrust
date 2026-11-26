"""Decode text inputs and apply edits to plain text notes."""

import codecs
import re

from ._edits import apply_value, group_values
from ._errors import Reject

_BOMS = (
    (codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"),
)
_ENCODINGS = {"utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be",
              "utf-32", "utf-32-le", "utf-32-be", "cp1252", "iso8859-1"}
_BAD_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")


def check_text(text):
    if _BAD_TEXT.search(text):
        raise Reject("invalid_text")
    return text


def decode_text(raw, encoding, *, allow_cp1252=False):
    try:
        if encoding is None:
            encoding = next((name for bom, name in _BOMS if raw.startswith(bom)), None)
            if encoding is None:
                try:
                    return check_text(raw.decode("utf-8"))
                except UnicodeDecodeError:
                    if not allow_cp1252:
                        raise
                    encoding = "cp1252"
        encoding = codecs.lookup(encoding).name
        if encoding not in _ENCODINGS:
            raise Reject("unsupported_encoding")
        return check_text(raw.decode(encoding))
    except UnicodeError:
        raise Reject("invalid_encoding") from None
    except LookupError:
        raise Reject("unsupported_encoding") from None


def rewrite_note(contents, values):
    groups = group_values(values)
    if groups.keys() - {()}:
        raise Reject("invalid_field_path")
    rewritten = apply_value(contents, groups[()]) if groups else contents
    if not isinstance(rewritten, str):
        raise Reject("invalid_rewrite")
    return rewritten
