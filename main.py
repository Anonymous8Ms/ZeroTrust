"""Offline CLI invoked by the organiser's harness."""
import argparse
import os
from pathlib import Path
import sys

from secret_wards.fixture_backend import FixtureBackend
from secret_wards.pipeline import run_pipeline
from secret_wards.privacy import load_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="Sanitise synthetic hospital records.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    secret = os.environ.get("RAKSHA_SECRET")
    if not secret:
        print("RAKSHA_SECRET is required.", file=sys.stderr)
        return 2
    try:
        policy = load_policy(Path(__file__).resolve().parent / "config" / "policy.yaml")
        backend = FixtureBackend()
        run_pipeline(args.input, args.output, secret.encode(), policy, backend, backend, backend)
    except Exception:
        # Raw paths and exception text can contain identifiers.
        print("Sanitisation failed. Check the inputs, policy and output directory.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
