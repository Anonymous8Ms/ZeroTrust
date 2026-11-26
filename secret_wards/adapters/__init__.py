"""Format adapters and the edit vocabulary used by rewrite plans."""

from ._edits import (
    FieldEdit as FieldEdit,
    FilenameEdit as FilenameEdit,
    HeaderEdit as HeaderEdit,
    KeyEdit as KeyEdit,
    SpanEdit as SpanEdit,
)


def __getattr__(name):
    # Preserve imports from the first adapter handoff.
    if name in {"FileAdapters", "discover"}:
        from .. import file_io

        return getattr(file_io, name)
    raise AttributeError(name)
