"""Write machine-readable output contracts."""
import json
from pathlib import Path
import resource
import sys


def peak_memory_mb() -> float:
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    divisor = 1024 * 1024 if sys.platform == "darwin" else 1024
    return round(rss / divisor, 3)


def write_reports(output: Path, files: list, counts: dict, records: list, seconds: float, *, entities=None):
    with (output / "records.jsonl").open("w", encoding="utf-8") as stream:
        for record in records:
            print(json.dumps(record, ensure_ascii=False, sort_keys=True), file=stream)
    report = {
        "schema": "raksha-report/1", "entities": entities if entities is not None else {},
        "files": files, "counts": counts, "timing": {"seconds": round(seconds, 6)},
        "resources": {"peak_rss_mb": peak_memory_mb()},
    }
    (output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
