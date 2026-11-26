# Privacy design references

This prototype processes synthetic records. Its controls are informed by
privacy frameworks and are evaluated using the hackathon's test contract.

| Reference | Design application | Evidence and limits |
| --- | --- | --- |
| [India's DPDP Act](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf) | Remove direct identifiers, keep processing local, and confine the runtime key to the process environment. | The fixture checks the export, reports and process messages for known identifiers. Input volume encryption depends on deployment. |
| [HIPAA de-identification guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html) | Use its identifier categories as a detector design reference. | Shifted month and day values remain in the export to retain encounter intervals. The prototype makes no Safe Harbor claim. |
| [EU GDPR, Recital 26 and Article 4](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/) | Pseudonymisation supports longitudinal analysis. Age and location generalisation reduce specificity. | Remaining attributes may still identify a patient. The practice uniqueness check covers age and district only. |

## Field preservation and risk

Diagnoses and stay lengths are retained. Explicit geographic mappings are
configured in the privacy policy. Unmapped locations are withheld because
districts and rare combinations of conditions and dates can still identify
people. The practice checker counts withheld district values as missing
preservation probes. In the practice run, the 93 withheld district values
accounted for all preservation misses.

On 28 comparable synthetic patients in the organiser's registration tables,
28 had a unique exact age and district before processing. Two had a unique
age band and published district after processing. The check uses the first
comparable record per truth patient and matches it to the same exported row.
This is a limited singling-out measure. It does not estimate prediction
accuracy using all available attributes or represent a score on hidden data.
Rerun it from the repository root with the organiser's practice answer key:

```sh
python3 -m tools.measure_practice_risk \
  --input "$KIT/dev/input" --truth "$KIT/dev/truth/truth.json" --output "$OUT"
```

## Storage and key handling

For a deployed run, mount the input read-only from encrypted storage and place
the output and temporary workspace on encrypted storage. Verify the mounts
before launch, restrict access to the run account, and retain only approved
releases. Keep the encryption key in the host key store and inject the
separate pseudonym secret as `RAKSHA_SECRET` at launch. Disable crash dumps
and use encrypted swap or disable swap for the run host.

The CLI reads user inputs without changing them, keeps original values and
linkage evidence in memory, and writes only rewritten candidates to a temporary
file beside the release. A candidate is published after format validation.
Rejected files are accounted for by digest and reason code without copying
their contents to the output. Host encryption is a deployment requirement
and must be verified by the operator.
