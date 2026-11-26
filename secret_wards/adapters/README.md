# Secret Wards ingestion and export

The adapter uses the Python standard library and runs offline on Python 3.10+
on macOS and Linux. From the repository root, run the synthetic handoff checks.

```sh
python3 -B -m unittest discover -s tests -p test_adapters.py -v
```

The adapter tests use their own synthetic CSV and Hindi note fixtures under
`tests/fixtures/adapters/`. The CLI fixture tests use `tests/fixtures/input/`.
The adapter tests exercise the ingest/export API directly. The CLI uses
the same file adapters and translates detector targets into adapter edits
in `secret_wards/pipeline.py`.

## Adapter interface

Import `FileAdapters` and `discover` from `secret_wards.file_io`. Import edit
classes from `secret_wards.adapters`.

- Construct `FileAdapters` with factories for parsed records and export status.
  The adapter passes shared fields as keyword arguments. This implementation
  calls the parsed payload `content` and passes an internal `Path` as
  `source_file`. A factory can translate these fields to the shared definitions.
- Iterate `discover(input_root)` and call `ingest(path, input_root)` for each
  candidate. Submit `document.records` for detection. Keep source paths, original
  locations, content and record keys internal. A record key is stable for the
  same input root relative path, bytes and record location. To limit memory when
  working across many files, retain the evidence and plans and reread individual
  files before exporting them. Changed inputs produce different record keys.
- Call `export(document, plans, output_root, file_edits=...)` for every ingested
  file, including parse failures. Supply one plan per record, including records
  with unresolved identity. An empty plan explicitly approves an unchanged
  record. The result uses `exported` or `quarantined`, a fixed reason code for
  quarantine, and `final_record_locations` keyed by the internal record handle.
  The CLI can publish the location values in its report. A missing SHA-256
  indicates the bytes could not be safely read, for example a symbolic link.
- Use separate input and output roots and a fresh output root for each run.
  A safe output path is relative to the output root and begins with
  `sanitized/`. The writer creates a random opaque basename by default. A
  supplied name must be an approved flat ASCII basename with the original
  extension. The writer stages and validates files outside `sanitized/` and
  publishes them atomically without replacing an existing file.

A plan supplies `record_key` and `edits`. The privacy policy provides the
replacement values. The adapter applies them and validates the output structure.

| Edit | Target |
| --- | --- |
| `FieldEdit(path, replacement)` | Replace an existing scalar value |
| `SpanEdit(path, start, end, replacement)` | Replace a nonempty half-open span in an original string. Offsets count Python Unicode code points |
| `KeyEdit(path, replacement)` | Rename a JSON object key. The path ends in the original key |
| `HeaderEdit(column, replacement)` | Rename a CSV or TSV header using the original header |
| `FilenameEdit(replacement)` | Set the complete safe basename, including extension |

Paths are tuples of object keys and zero-based indices, relative to the
record. Use `()` for the complete text note and `("column",)` for a table cell.
File edits address the original file root. Use them for names, headers and
JSON envelope fields, including keys above a record. Plans must cover every
sensitive key before the CLI publishes final JSON record locations. Edits
against the same value must be nonoverlapping. A rename and value edit can
address the same JSON member in one export.

## Format conventions

- CSV and TSV use a header row, unique nonempty headers and zero-based data
  locations such as `row:0`. Quoted multiline fields, embedded separators,
  blank lines and record line endings survive export. Quoting is canonicalized.
- Plain text and FHIR use `doc`. Generic JSON uses RFC 6901 pointers, with the
  empty string for the root. An array at the root yields one record per item.
  The reader also recognises one nested `records`, `visits`, `patients` or
  `encounters` array. An API caller can pass `json_record_paths` for other
  nonoverlapping record paths. Export reports pointers after key renames.
- The default decoder accepts strict UTF-8 and BOM-marked UTF-8, UTF-16 or
  UTF-32. Callers may specify an encoding for known legacy sources, including
  Windows-1252 and Latin-1. Output uses UTF-8. Default limits are 32 MiB per
  input and 100,000 records. Tables also limit extra blank lines and column
  count. Readable failures still receive the SHA-256 of their original bytes.
- FHIR accepts R4 JSON resources and bundles in `.fhir` or `.json`. The
  built-in validator checks resource types, IDs, supported Bundle structure
  and local reference consistency. The adapter propagates planned rewrites
  through unambiguous contained, literal and identifier references, so the
  writer can reject conflicting edits. References outside a file are never
  fetched. Install the kit validator through the optional
  `fhir_validator(tree) -> bool` callback for full schema or profile
  validation. It must run offline. Bundles with multiple Patient resources
  and nested bundles are quarantined as `multi_patient_fhir_bundle` and
  `nested_fhir_bundle`, respectively. The team needs a multi-patient linkage
  convention before enabling those exports.

FHIR behavior follows the identity and reference rules in the
[HL7 R4 Bundle specification](https://hl7.org/fhir/R4/bundle.html) and the
[HL7 R4 Reference specification](https://hl7.org/fhir/R4/references.html).
