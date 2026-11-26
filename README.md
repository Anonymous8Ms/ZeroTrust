# ZeroTrust

ZeroTrust is an offline Python command-line tool for preparing synthetic
healthcare records for research. It replaces direct identifiers, links records
that belong to the same patient, and reduces the detail in dates, ages and
locations while preserving clinical values such as diagnoses, doses and vital
signs.

The CLI accepts CSV, TSV, plain text, JSON and supported FHIR R4 JSON layouts.
It detects identifiers in structured fields and in English, Hindi and Hinglish
text. Use synthetic data only.

## Quick start

Use Python 3.11 or later on Linux or macOS. The current build uses the Python
standard library. From the repository root, run:

```sh
RAKSHA_SECRET=local-demo-key python3 main.py \
  --input tests/fixtures/input \
  --output my_output
```

Use an empty or nonexistent output directory for each run. The key above is an
example for the bundled fixtures. Supply your own secret through the
`RAKSHA_SECRET` environment variable for other runs and keep it out of source
control.

## Output

| Path | Contents |
| --- | --- |
| `sanitized/` | Records that were successfully processed. |
| `report.json` | Input SHA-256 digests, processing outcomes, quarantine counts, elapsed time and peak memory. |
| `records.jsonl` | One entry per exported record with its output path, location and patient pseudonym. Unresolved identities have `patient: null`. |

Source files remain unchanged. Files that cannot be safely processed are
accounted for in the report and excluded from the export. For a nonempty input
directory, the CLI returns a failure status if every file is quarantined.

JSON and FHIR files with recognised embedded attachment payloads are
quarantined with the reason `embedded_attachment`. The CLI does not decode or
export those payloads.

## Processing model

1. **Inspect and link.** Inventory inputs, parse records, identify sensitive
   fields and group records with sufficient evidence of a shared identity.
2. **Apply policy and export.** Generate keyed pseudonyms and date offsets,
   apply age and location rules, and write the export and audit reports.

[The privacy policy](config/policy.yaml) defines the age-band width, date-shift
range and location mappings. Linked records receive a consistent date offset
per patient. Unlinked records receive an offset scoped to the encounter so
admission and discharge intervals remain intact. Unmapped locations are withheld.

The pipeline runs locally without network calls. It keeps raw working data in
memory and omits direct identifiers and the key from its reports. Protect the
input directory and host storage separately. Pseudonymised records can still
carry re-identification risk. The built-in FHIR validator checks resource and
reference structure. Full profile validation requires an additional validator.
See [the privacy design notes](docs/privacy-design.md)
for policy references and limitations.

## Development

- `main.py` is the command-line entry point.
- `secret_wards/contracts.py` defines parsed records and privacy policy targets.
- `secret_wards/file_io.py` and `secret_wards/adapters/` own parsing, validation
  and file publication.
- `secret_wards/detection.py` and `secret_wards/linkage.py` detect sensitive
  fields and group patient records.
- `secret_wards/pipeline.py` coordinates processing.
- `secret_wards/privacy.py` and `secret_wards/reporting.py` implement privacy
  transformations and output reports.
- `tests/` contains the synthetic fixtures and CLI checks.

Run the tests with:

```sh
python3 -m unittest discover -s tests -v
```

The checks run renamed and mixed-format datasets through the CLI and cover
consistent pseudonyms, unresolved identities, preserved clinical values and
encounter durations, FHIR references, and quarantine of malformed input. Sanitised
records and mappings are reproducible for the same input and key. Measured
runtime and peak memory can vary between runs.
