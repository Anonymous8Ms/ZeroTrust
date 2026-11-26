"""Verify that embedded data URLs cannot reach the exported files."""

import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest


ROOT = Path(__file__).resolve().parents[1]


class InlineDataURLTests(unittest.TestCase):
    def test_quarantines_data_urls_but_exports_ordinary_urls_and_text(self):
        token = base64.b64encode(b"Patient: Synthetic Inline Patient Canary").decode()
        uri = f"data:text/plain;charset=utf-8;base64,{token}"
        document = {"resourceType": "DocumentReference", "status": "current"}
        blocked = {
            "metadata.json": {"metadata": {"source": uri}},
            "case.json": {"attachment": {"url": "DATA:;BASE64," + token}},
            "metadata-key.json": {"attributes": {uri: "opaque"}},
            "reference.fhir": {
                **document, "content": [{"attachment": {"contentType": "text/plain", "url": uri}}],
            },
            "narrative.fhir": {
                **document, "description": "Diagnostic note",
                "text": {"status": "generated", "div":
                         '<div xmlns="http://www.w3.org/1999/xhtml">'
                         f'<img src="{uri}" alt="Synthetic example"/></div>'},
            },
        }
        note = "Data: 150/90, patient stable"
        ordinary_url = "https://example.invalid/reference"
        safe = {"note": note, "reference": ordinary_url, "diagnosis": "asthma"}

        with TemporaryDirectory() as temp:
            source, output = Path(temp) / "input", Path(temp) / "output"
            source.mkdir()
            expected = {}
            for name, value in {**blocked, "record.json": safe}.items():
                payload = json.dumps(value).encode()
                (source / name).write_bytes(payload)
                expected[sha256(payload).hexdigest()] = name

            run = subprocess.run(
                [sys.executable, "-B", str(ROOT / "main.py"), "--input", str(source),
                 "--output", str(output)],
                env={**os.environ, "RAKSHA_SECRET": "synthetic-inline-check"},
                capture_output=True, text=True, check=True,
            )
            audit = json.loads((output / "report.json").read_text())
            self.assertEqual(audit["counts"]["files_quarantined"], len(blocked))
            self.assertEqual(audit["counts"]["files_sanitized"], 1)
            for item in audit["files"]:
                name = expected[item["input_sha256"]]
                with self.subTest(name=name):
                    if name in blocked:
                        self.assertEqual(item["status"], "quarantined")
                        self.assertEqual(item["reason"], "embedded_attachment")
                        self.assertIsNone(item["output"])
                    else:
                        self.assertEqual(json.loads((output / item["output"]).read_text()), safe)
            public_data = run.stdout + run.stderr + "\n".join(
                path.read_text(encoding="utf-8") for path in output.rglob("*") if path.is_file()
            )
            self.assertNotIn(token, public_data)
