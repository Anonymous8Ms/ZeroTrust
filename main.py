"""Offline CLI invoked by the organiser's harness."""
import argparse
import os
from pathlib import Path
import sys

from secret_wards.pipeline import run_pipeline
from secret_wards.privacy import load_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="Sanitise synthetic hospital records.")
    parser.add_argument("--input", type=Path, help="Synthetic input folder")
    parser.add_argument("--output", type=Path, help="Empty or new output folder")
    parser.add_argument("--interactive", action="store_true", help="Open the terminal home screen")
    args = parser.parse_args()
    if args.interactive:
        if args.input is not None or args.output is not None:
            parser.error("--interactive cannot be combined with --input or --output")
        from secret_wards.terminal import run_home

        return run_home(Path(__file__).resolve().parent)
    if args.input is None or args.output is None:
        parser.error("--input and --output are required unless using --interactive")
    secret = os.environ.get("RAKSHA_SECRET")
    if not secret:
        print("RAKSHA_SECRET is required.", file=sys.stderr)
        return 2
    try:
        policy = load_policy(Path(__file__).resolve().parent / "config" / "policy.yaml")
        report = run_pipeline(args.input, args.output, secret.encode(), policy)
        if report["files_total"] and not report["files_sanitized"]:
            print("No inputs were exported. See report.json.", file=sys.stderr)
            return 1
    except Exception:
        # Raw paths and exception text can contain identifiers.
        print("Sanitisation failed. Check the inputs, policy and output directory.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
