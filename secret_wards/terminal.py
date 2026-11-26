"""Offline home screen for running and reviewing synthetic sanitisation jobs."""

import json
import os
from pathlib import Path
from secrets import token_bytes
import tempfile

from .pipeline import run_pipeline
from .privacy import load_policy


_MENU = """\
+--------------------------------------------------+
|  Z E R O T R U S T                               |
|  Offline healthcare data sanitisation           |
+--------------------------------------------------+
   1  Run on a synthetic input folder
   2  Try the bundled demo
   3  Open a run summary
   0  Exit
"""

_COUNTS = (
    "files_total", "files_sanitized", "files_quarantined",
    "records_processed", "records_linked",
)


def _show_summary(counts):
    values = [counts[key] for key in _COUNTS]
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("invalid report counts")
    total, sanitized, quarantined, records, linked = values
    if total != sanitized + quarantined or linked > records:
        raise ValueError("inconsistent report counts")

    if not total:
        status = "No input files found"
    elif not sanitized:
        status = "No files exported"
    elif quarantined:
        status = "Completed with quarantined files"
    else:
        status = "Completed"

    print(f"\n  {status}\n  {'-' * 38}")
    for name, value in (
        ("Input files", total),
        ("Files sanitised", sanitized),
        ("Files quarantined", quarantined),
        ("Records exported", records),
        ("Patient pseudonyms assigned", linked),
        ("Unresolved identities", records - linked),
    ):
        print(f"  {name:<30} {value:>7}")
    print()


def _prompt_path(label):
    value = input(label).strip()
    if not value:
        raise ValueError("missing path")
    return Path(value).expanduser()


def _run(source, dest, secret, root):
    print("Processing synthetic records...")
    policy = load_policy(root / "config" / "policy.yaml")
    counts = run_pipeline(source, dest, secret, policy)
    _show_summary(counts)
    print("  See report.json, records.jsonl and sanitized/ in the output folder.\n")


def _open_report():
    path = _prompt_path("Path to report.json > ")
    if not path.is_file():
        raise ValueError("report is not a file")
    with path.open(encoding="utf-8") as stream:
        report = json.load(stream)
    _show_summary(report["counts"])


def run_home(root: Path) -> int:
    """Read menu choices until exit, EOF or an interrupt."""
    print(_MENU)
    try:
        while True:
            choice = input("Select [1/2/3/0] > ").strip()
            if choice == "0":
                return 0
            if choice == "1":
                secret = os.environ.get("RAKSHA_SECRET")
                if not secret or not secret.strip():
                    print("  Set RAKSHA_SECRET in your environment, then reopen the home screen.\n")
                    continue
                try:
                    source = _prompt_path("Synthetic input folder > ")
                    dest = _prompt_path("Empty output folder > ")
                    _run(source, dest, secret.encode(), root)
                except Exception:
                    # Errors from raw inputs may contain private values.
                    print("  Run failed. Check the input folder and choose an empty output folder.\n")
            elif choice == "2":
                try:
                    dest = Path(tempfile.mkdtemp(prefix="zerotrust-demo-"))
                    _run(root / "tests" / "fixtures" / "input", dest, token_bytes(32), root)
                    print(f"  Demo output folder: {ascii(str(dest))}\n")
                except Exception:
                    print("  Demo failed. Check that the bundled fixtures are available.\n")
            elif choice == "3":
                try:
                    _open_report()
                except (OSError, ValueError, KeyError, TypeError, RecursionError):
                    print("  Could not read a valid ZeroTrust report.\n")
            else:
                print("  Choose 1 to run, 2 for the demo, 3 for a report, or 0 to exit.\n")
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
