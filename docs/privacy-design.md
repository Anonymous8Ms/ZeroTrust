# Privacy design references

This prototype processes synthetic records. Its controls are informed by
privacy frameworks and are evaluated using the hackathon's test contract.

| Reference | Design application | Evidence and limits |
| --- | --- | --- |
| [India's DPDP Act](https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf) | Remove direct identifiers, keep processing local, and confine the runtime key to the process environment. | The fixture checks the export, reports and process messages for known identifiers. Input volume encryption depends on deployment. |
| [HIPAA de-identification guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html) | Use its identifier categories as a detector design reference. | Shifted month and day values remain in the export to retain encounter intervals. The prototype makes no Safe Harbor claim. |
| [EU GDPR, Recital 26 and Article 4](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/) | Pseudonymisation supports longitudinal analysis. Age and location generalisation reduce specificity. | Remaining attributes may still identify a patient. The fixture's uniqueness check covers age and location only. |

Preserve diagnoses and stay lengths under the current hackathon policy.
Revisit any rare-diagnosis suppression after the organisers clarify their
clinical preservation requirements. Position the design as a research
prototype rather than legal compliance or guaranteed anonymisation.
