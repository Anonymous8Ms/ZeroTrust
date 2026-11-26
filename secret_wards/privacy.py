"""Deterministic research-export policy."""
import base64
from dataclasses import dataclass
from datetime import date, timedelta
import hmac
import json
from pathlib import Path

from .contracts import DetectionResult, Edit, Quarantine, RewritePlan, Target


@dataclass(frozen=True)
class Policy:
    age_band_width: int
    max_date_shift_days: int
    locations: dict[str, str]


def load_policy(path: Path) -> Policy:
    # JSON is a subset of YAML, so the foundation needs no YAML dependency.
    policy = Policy(**json.loads(path.read_text(encoding="utf-8")))
    if policy.age_band_width < 1 or not 1 <= policy.max_date_shift_days <= 3650:
        raise ValueError("invalid policy bounds")
    return policy


def derive(secret: bytes, purpose: str, key: str) -> bytes:
    return hmac.digest(secret, f"secret-wards/v1/{purpose}\0{key}".encode(), "sha256")


def pseudonym(secret: bytes, group: str) -> str:
    token = base64.b32encode(derive(secret, "patient", group)[:16]).decode().rstrip("=")
    return f"PSN-{token}"


def date_offset(secret: bytes, scope: str, limit: int) -> int:
    bucket = int.from_bytes(derive(secret, "date", scope)[:8], "big") % (2 * limit)
    return bucket - limit if bucket < limit else bucket - limit + 1


def overlaps(left: Target, right: Target) -> bool:
    if (left.surface, left.path) != (right.surface, right.path):
        return False
    if left.span is None or right.span is None:
        return True
    return left.span[0] < right.span[1] and right.span[0] < left.span[1]


def build_plan(
    detection: DetectionResult, group: str | None, secret: bytes, policy: Policy
) -> RewritePlan:
    patient = pseudonym(secret, group) if group is not None else None
    scope = f"group:{group}" if group is not None else f"record:{detection.record_key}"
    shift = timedelta(days=date_offset(secret, scope, policy.max_date_shift_days))
    protected = [target for target in detection.targets if target.kind == "protected"]
    targets = [target for target in detection.targets if target.kind != "protected"]
    if patient and detection.patient_slot is None:
        raise Quarantine("missing patient slot")
    if patient and detection.patient_slot not in targets:
        targets.append(detection.patient_slot)
    edits: list[Edit] = []
    for target in targets:
        if any(overlaps(target, clinical) for clinical in protected):
            raise Quarantine("conflicting privacy and clinical targets")
        if any(overlaps(target, edit.target) for edit in edits):
            raise Quarantine("overlapping rewrite targets")
        if patient and target == detection.patient_slot:
            value = patient
        elif target.kind == "date":
            try:
                value = (date.fromisoformat(target.value) + shift).isoformat()
            except (ValueError, OverflowError):
                raise Quarantine("unsupported encounter date") from None
        elif target.kind == "age":
            try:
                age = int(target.value)
                if not 0 <= age <= 130:
                    raise ValueError
            except ValueError:
                raise Quarantine("invalid age") from None
            lower = age // policy.age_band_width * policy.age_band_width
            value = f"{lower}-{lower + policy.age_band_width - 1}"
        elif target.kind == "location":
            value = policy.locations.get(target.value, "[REGION WITHHELD]")
        else:
            value = "[REDACTED]"
        edits.append(Edit(target, value))
    return RewritePlan(detection.record_key, tuple(edits), patient)
