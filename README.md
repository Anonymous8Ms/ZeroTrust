# ZeroTrust

ZeroTrust is an offline privacy pipeline for Secret Wards, Track 3 of the
Yugaantar DevForge hackathon. This branch contains the Person 3
foundation and a fixture-only backend. The backend recognises the checked-in
fixture layouts and quarantines other files. The team adapters, multilingual
detector and linker are integration dependencies.

## Run the first handoff

Use Python 3.11 or newer on Linux or macOS. The foundation has no third-party
runtime dependencies. Start with an empty or nonexistent output directory.

```sh
python3 -m pip install -r requirements.txt
RAKSHA_SECRET=synthetic-demo-secret-a python3 main.py \
  --input tests/fixtures/input --output my_output
python3 -m unittest discover -s tests -v
```

The example key is for the synthetic fixture. The judge provides the runtime
key through the environment. Outputs are written to `sanitized/`,
`report.json` and `records.jsonl`. Use fresh output directories for repeats.

## Architecture

1. Inventory, hash and parse inputs. Detect sensitive targets and preserve
   clinical targets. Resolve patient groups across accepted records.
2. Build rewrite plans from group assignments and the privacy policy. Render
   and validate files through the adapter. Record safe paths and locations
   in the reports and account for each quarantined input by hash.

`secret_wards/contracts.py` defines the handoffs. Person 1 supplies an
`Adapter`, Person 2 supplies a `Detector` and `Linker`, and Person 3 wires
them into `run_pipeline` in `main.py`. Adapters return rendered UTF-8 bytes
and final safe paths and locations. They own format validation and must use
the final record location after any key rename. The `Target` type supports
structured paths, spans into original text, and key, filename and metadata
surfaces. A detector must mark where a resolved patient pseudonym can appear.

## Privacy defaults

- Resolved patients share an HMAC pseudonym and a consistent, separately
  derived offset for related dates. For an unresolved identity, use the
  internal record key as the date scope, keep all dates in that encounter
  aligned, and use `patient: null` in the index. Do not infer a timeline
  across unresolved records. The current date policy accepts ISO dates.
- Use ten-year age bands. Generalise locations through explicit mappings
  and withhold unknown regions. Preserve diagnoses and exact encounter
  durations. If sensitive and protected targets conflict, quarantine the
  file. `config/policy.yaml` uses JSON-compatible YAML.
- Raw inputs stay in the input directory. The pipeline holds raw working
  data in memory and writes sanitised content only. At-rest encryption for
  the organiser's input and host swap is a deployment responsibility.
- Sanitised content, record mappings and report counts are deterministic.
  Observed runtime and process peak RSS vary. A changed key changes HMAC
  pseudonyms. Date offsets are bounded, so individual offset collisions
  across keys are possible.

## Verification and teammate handoffs

The synthetic check covers removal of nine labelled identifier targets,
preserved diagnoses and clinical values, three nine-day stays, no false
merge in the fixture, one unresolved record and one quarantined file.
The age-and-location uniqueness baseline drops from two of two registration
rows to zero of two. That is a fixture metric, separate from the judge's
re-identification evaluation. See [privacy design](docs/privacy-design.md)
for the policy references and limits.

- Person 1: provide adapter entry points, supported encoding/format cases,
  safe export and quarantine evidence, FHIR reference handling and limits.
- Person 2: provide detector/linker entry points, evidence from the
  practice data, matching thresholds or abstention rules and limits.

When the organiser's kit arrives, run:

```sh
python3 validate_output.py --input dev/input --output my_output/
```

Use an output generated from `dev/input` for that check. The organiser
validator and practice dataset are currently unavailable in this checkout.
