# Privacy design references

This prototype processes synthetic records. Its controls are informed by
privacy frameworks and are evaluated using the hackathon's test contract.

| Reference | Design application | Evidence and limits |
| --- | --- | --- |
| [India's DPDP Act](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf) | Remove direct identifiers, keep processing local, and confine the runtime key to the process environment. | The tests check the export, reports and process messages for known identifiers. Storage encryption is verified separately. |
| [HIPAA de-identification guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html) | Use its identifier categories as a detector design reference. | Shifted month and day values remain in the export to retain encounter intervals. The prototype makes no Safe Harbor claim. |
| [EU GDPR, Recital 26 and Article 4](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/) | Pseudonymisation supports longitudinal analysis. Age and location generalisation reduce specificity. | Remaining attributes may still identify a patient. The practice uniqueness check covers age and district only. |

## Field preservation and risk

The policy retains diagnoses and stay lengths, bands ages, shifts dates
consistently for linked patients, and maps geography to configured areas.
It withholds unmapped locations because geography combined with rare
conditions and dates can help identify patients. The organiser's practice
checker retained 4,762 of 4,855 values. All 93 missed probes were
district values withheld by the policy.

The practice check matched one comparable registration row per synthetic
patient using the answer key, input digest and final record location. Among
the 28 matched patients, 28 had a unique exact age-and-district combination
before processing and 2 had a unique age-band-and-released-district
combination after processing. The denominator is the 28 comparable
patients with both fields available for the comparison.

This is a two-field singling-out measure within the selected registration
sample. It excludes other formats and patients without a comparable row.
It does not measure re-identification from diagnoses, encounter dates,
linked histories, external registries or multiple releases. A patient
with a common age-and-district combination can still be singled out
using additional information.

Rerun the comparison from the repository root using the organiser's
practice answer key.

```sh
python3 -m tools.measure_practice_risk \
  --input "$KIT/dev/input" --truth "$KIT/dev/truth/truth.json" --output "$OUT"
```

## Storage and key handling

The operator verifies the following on the deployment host before launch.

1. Ensure that the resolved input, output and temporary paths are backed
   by encrypted storage. Mount the input read-only and place the release
   directory and `TMPDIR` on an encrypted workspace. The pipeline stages
   rewritten candidate files beside the release.
2. Keep storage credentials in the host key store. Inject a separate
   per-release pseudonym key through `RAKSHA_SECRET`. Limit access to the
   run account and retain approved releases only.
3. Disable crash dumps. Use encrypted swap or disable swap. Compare input
   hashes before and after the run and validate the release before sharing it.

The CLI reads inputs without changing them and processes original values
and linkage evidence in memory. It publishes a rewritten candidate after
format validation. It accounts for rejected files by digest and reason
without copying their contents into the release.

A synthetic deployment test verified two AES-256 disk images. The input
mount was read-only and all 200 input hashes stayed unchanged. The release
and temporary directories were on a separate encrypted image. The
organiser's validator returned `CONTRACT OK` for 192 exports and 8
quarantines. Both test images were detached after the run. The Desktop
volume reported FileVault off, so the encryption check applies to those
test images. The organiser's evaluation host requires its own verification.
