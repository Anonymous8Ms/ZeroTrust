"""Generate a deterministic, synthetic-only corpus and its expected outcomes."""

import argparse
import base64
from datetime import date, timedelta
from hashlib import sha256
import json
from pathlib import Path


def generate(root: Path):
    inputs = root / "input"
    inputs.mkdir(parents=True)
    cases = {}
    markers = {"Asha Demo", "आशा डेमो"}

    def add(name, data, *, group=None, reason=None, clinical=None):
        path = inputs / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, dict):
            data = json.dumps(data, ensure_ascii=False)
        if isinstance(data, str):
            data = data.encode()
        path.write_bytes(data)
        digest = sha256(data).hexdigest()
        if digest in cases:
            raise ValueError("synthetic cases must have distinct contents")
        cases[digest] = {"file": name, "group": group, "reason": reason, "clinical": clinical}

    def bundle(patient_id, patient, suffix):
        patient_url = f"https://example.invalid/Patient/{patient_id}"
        return {"resourceType": "Bundle", "type": "collection", "entry": [
            {"fullUrl": patient_url, "resource": {
                "resourceType": "Patient", "id": patient_id, **patient,
            }},
            {"fullUrl": f"https://example.invalid/Observation/observation-{suffix}",
             "resource": {"resourceType": "Observation", "id": f"observation-{suffix}",
                          "status": "final", "code": {"text": "Glucose"},
                          "subject": {"reference": patient_url},
                          "valueQuantity": {"value": 105, "unit": "mg/dL"}}},
        ]}

    for i in range(1, 25):
        group = f"group-{i:02d}"
        phone = f"700000{i:04d}"
        patient_id = f"synthetic-patient-{i:03d}"
        birth = (date(1980, 1, 1) + timedelta(days=i)).isoformat()
        admitted = date(2026, 1, 1) + timedelta(days=i)
        discharged = admitted + timedelta(days=9)
        diagnosis = "asthma" if i % 2 else "malaria"
        markers.update((phone, patient_id))
        add(f"registrations/visit-{i:02d}.csv",
            "patient_name,phone,DOB,age,location,admitted,discharged,diagnosis\n"
            f"Asha Demo,{phone},{birth},{30 + i},Example Village East,{admitted},{discharged},{diagnosis}\n",
            group=group, clinical=diagnosis)

        tab = f"Patient Name\tPhone\tDOB\tDiagnosis\nAsha Demo\t{phone}\t{birth}\t{diagnosis}\n"
        add(f"wards/visit-{i:02d}.tsv", tab.encode("utf-16") if i % 2 else tab,
            group=group, clinical=diagnosis)

        if i % 2:
            note = f"रोगी: आशा डेमो\nफोन: {phone}\nप्रवेश: {admitted}\nछुट्टी: {discharged}\n"
        else:
            note = f"Patient: Asha Demo\nMobile: {phone}\nAdmission: {admitted}\nDischarge: {discharged}\n"
        add(f"notes/ward-{i:02d}.txt", note + "BP 150/90; Dolo 650 BD\n",
            group=group, clinical="BP 150/90; Dolo 650 BD")

        add(f"visits/data-{i:02d}.json", {
            "data": {"visits": [{"patient_name": "Asha Demo", "phone": phone,
                                "dob": birth, "diagnosis": diagnosis}]},
            "metadata": {"source_path": f"/fixtures/private-export-{i:02d}/input.csv"},
        }, group=group, clinical=diagnosis)
        markers.add(f"private-export-{i:02d}")

        add(f"fhir/resources-{i:02d}.fhir", bundle(patient_id, {
            "name": [{"text": "Asha Demo"}],
            "telecom": [{"system": "phone", "value": phone}],
            "birthDate": birth,
        }, i), group=group, clinical="mg/dL")

    for i in range(1, 4):
        add(f"notes/ambiguous-{i}.txt",
            f"Patient: Asha Demo\nDiagnosis: asthma\nEncounter: {i}\n", clinical="asthma")

    sample = base64.b64encode(b"Patient: Synthetic Attachment Sample").decode()
    markers.add(sample)
    inline = {"contentType": "text/plain", "data": sample}
    add("extra/recognised.json", {"visits": [{"diagnosis": "asthma",
        "attachment": inline}]}, clinical="asthma")
    add("extra/recognised.fhir", {"resourceType": "DocumentReference", "status": "current",
        "description": "Synthetic radiology summary", "content": [{"attachment": inline}]},
        clinical="Synthetic radiology summary")
    add("extra/Asha_Demo.json", {"patient_name": "Asha Demo", "diagnosis": "dengue"},
        clinical="dengue")

    for i in range(1, 4):
        payload = base64.b64encode(f"Patient: Synthetic Metadata Case {i}".encode()).decode()
        markers.add(payload)
        add(f"quarantine/table-{i}.csv", f'name,diagnosis\n"Unfinished case {i}\n',
            reason="malformed_table")
        add(f"quarantine/encoding-{i}.txt", b"\xff" + bytes([i]), reason="invalid_encoding")
        add(f"quarantine/keys-{i}.json", f'{{"diagnosis":"case {i}","diagnosis":"asthma"}}',
            reason="duplicate_json_key")
        add(f"quarantine/document-{i}.pdf", f"Unsupported synthetic document {i}",
            reason="unsupported_format")
        add(f"quarantine/metadata-{i}.json", {"metadata": {"content_base64": payload}},
            reason="embedded_attachment")
        add(f"quarantine/wrapper-{i}.json", {"attachments": {"lab": {"blob": {"data": payload}}}},
            reason="embedded_attachment")
        add(f"quarantine/uri-{i}.json", {"metadata": {"source": f"data:text/plain;base64,{payload}"}},
            reason="embedded_attachment")
        groups = bundle(f"first-{i}", {}, f"q-{i}")
        groups["entry"].append({"fullUrl": f"https://example.invalid/Patient/extra-{i}",
                                "resource": {"resourceType": "Patient", "id": f"extra-{i}"}})
        add(f"quarantine/bundle-{i}.fhir", groups, reason="multi_patient_fhir_bundle")

    manifest = {"cases": cases, "forbidden_markers": sorted(markers)}
    (root / "expected.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="New directory for the generated corpus")
    args = parser.parse_args()
    print(f"Generated {len(generate(args.directory)['cases'])} synthetic input files.")
