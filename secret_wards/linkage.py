"""Conservative, in-memory patient grouping over corroborated identity evidence."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import combinations
from typing import Optional

from .detection import DetectionResult
from .normalization import birth_date, identifier, name_form, name_similarity, phone_number

LinkageResult = dict[str, Optional[str]]
_MAX_WEAK_BLOCK = 32
_MAX_ID_BLOCK = 96
_NATIONAL_MATCH_SCORE = 100
_ANCHOR_MIN_SCORE = 80


@dataclass(frozen=True, repr=False)
class _Profile:
    names: frozenset[tuple[str, ...]]
    relatives: frozenset[tuple[str, tuple[str, ...]]]
    phones: frozenset[str]
    births: frozenset[str]
    national_ids: frozenset[tuple[str, str]]
    local_ids: frozenset[tuple[tuple[str, str], str]]
    hospital: str
    record_ids: frozenset[tuple[str, str]]
    encounter: tuple[str, str] | None
    named_uhid: tuple[str, ...] | None


def _profile(detection: DetectionResult) -> _Profile:
    names, relatives, phones, births, national_ids, local_ids = (set() for _ in range(6))
    record_ids = set()
    encounter_dates = {"ADMISSION_DATE": set(), "DISCHARGE_DATE": set()}
    hospital = identifier(detection.hospital) if detection.hospital else ""
    for item in detection.identity_evidence:
        if item.kind == "PATIENT_NAME" and item.role == "patient":
            normalized = name_form(item.value)
            if normalized:
                names.add(normalized)
        elif item.kind == "RELATIVE_NAME":
            normalized = name_form(item.value)
            if normalized:
                relatives.add((item.role, normalized))
        elif item.kind == "PHONE" and item.role == "patient":
            normalized = phone_number(item.value)
            if normalized:
                phones.add(normalized)
        elif item.kind == "DOB":
            normalized = birth_date(
                item.value, detection.day_first, fallback_day_first=detection.fallback_day_first,
            )
            if normalized:
                births.add(normalized)
        elif item.kind in encounter_dates:
            normalized = birth_date(
                item.value, detection.day_first, fallback_day_first=detection.fallback_day_first,
            )
            if normalized:
                encounter_dates[item.kind].add(normalized)
        elif item.kind in {"AADHAAR", "ABHA_NUMBER", "PAN", "MRN", "UHID"}:
            normalized = identifier(item.value)
            if item.kind in {"AADHAAR", "ABHA_NUMBER"}:
                size = 12 if item.kind == "AADHAAR" else 14
                if len(normalized) == size and normalized.isdecimal() and len(set(normalized)) > 1:
                    national_ids.add((item.kind, normalized))
            elif item.kind == "PAN":
                if len(normalized) == 10 and normalized[:5].isalpha() and normalized[5:9].isdecimal() and normalized[9].isalpha():
                    national_ids.add((item.kind, normalized))
            elif len(normalized) >= 3 and any(char.isdecimal() for char in normalized):
                record_ids.add((item.kind, normalized))
                if hospital:
                    local_ids.add(((hospital, item.kind), normalized))
    admissions, discharges = encounter_dates.values()
    encounter = None
    if len(admissions) == len(discharges) == 1:
        start, end = next(iter(admissions)), next(iter(discharges))
        if start <= end:
            encounter = (start, end)
    uhids = {value for kind, value in record_ids if kind == "UHID"}
    named_uhid = None
    full_names = {name for name in names if name_similarity(name, name) == 3}
    if len(uhids) == len(full_names) == 1:
        named_uhid = (next(iter(uhids)), *next(iter(full_names)))
    return _Profile(
        frozenset(names), frozenset(relatives), frozenset(phones), frozenset(births),
        frozenset(national_ids), frozenset(local_ids), hospital, frozenset(record_ids), encounter, named_uhid,
    )


def _same_scope_conflict(
    left: frozenset[tuple], right: frozenset[tuple],
) -> bool:
    agreed_scopes = {scope for scope, _ in left & right}
    return bool(
        ({scope for scope, _ in left} & {scope for scope, _ in right}) - agreed_scopes
    )


def _conflict(left: _Profile, right: _Profile) -> bool:
    if left.births and right.births and left.births.isdisjoint(right.births):
        return True
    if _same_scope_conflict(left.national_ids, right.national_ids):
        return True
    if left.names and right.names and not any(
        name_similarity(a, b) for a in left.names for b in right.names
    ):
        # A one-word mention can be another spelling or a nickname. It is too weak
        # to contradict a strong ID, but it is also too weak to support a merge alone.
        if all(len(name) > 1 for name in left.names | right.names):
            return True
    return any(
        left_role == right_role != "relative"
        and not name_similarity(a, b)
        for left_role, a in left.relatives for right_role, b in right.relatives
    )


def _inconsistent(profile: _Profile) -> bool:
    return (
        len(profile.births) > 1
        or len({scope for scope, _ in profile.national_ids}) < len(profile.national_ids)
        or any(
            len(a) > 1 and len(b) > 1 and not name_similarity(a, b)
            for a, b in combinations(profile.names, 2)
        )
    )


def _shared_phones(profiles: list[_Profile]) -> set[str]:
    examples: dict[str, set[_Profile]] = defaultdict(set)
    for profile in profiles:
        for phone in profile.phones:
            if len(examples[phone]) <= _MAX_WEAK_BLOCK:
                examples[phone].add(profile)
    return {
        phone for phone, owners in examples.items()
        if len(owners) > _MAX_WEAK_BLOCK or any(
            _conflict(left, right)
            or _same_scope_conflict(left.local_ids, right.local_ids)
            or (
                left.relatives and right.relatives and not any(
                    name_similarity(a, b) for _, a in left.relatives for _, b in right.relatives
                )
            )
            for left, right in combinations(owners, 2)
        )
    }


def _tokens(names: Iterable[tuple[str, ...]]) -> set[str]:
    return {token for name in names for token in name if len(token) > 1}


def _blocks(profile: _Profile, shared_phones: set[str]) -> Iterable[tuple[str, ...]]:
    for scheme, value in profile.national_ids:
        yield "national", scheme, value
    for (hospital, scheme), value in profile.local_ids:
        yield "local", hospital, scheme, value
    if profile.named_uhid:
        yield "named-uhid", *profile.named_uhid
    if profile.encounter and profile.names:
        for scheme, value in profile.record_ids:
            yield "encounter", scheme, value, *profile.encounter
    for phone in profile.phones - shared_phones:
        yield "phone", phone
    relatives = _tokens(name for _, name in profile.relatives)
    for token in _tokens(profile.names):
        for dob in profile.births:
            yield "birth", token, dob
        for relative in relatives:
            yield "relative", token, relative


def _score(
    left: _Profile, right: _Profile, shared_phones: set[str], *,
    allow_encounter: bool = True, allow_named_uhid: bool = False,
) -> int:
    if _conflict(left, right):
        return 0
    if left.national_ids & right.national_ids:
        return _NATIONAL_MATCH_SCORE
    if left.local_ids & right.local_ids:
        return 90

    name = max((name_similarity(a, b) for a in left.names for b in right.names), default=0)
    if not name:
        return 0
    relative = max((
        name_similarity(a, b)
        for left_role, a in left.relatives for right_role, b in right.relatives
        if left_role == right_role or "relative" in (left_role, right_role)
    ), default=0)
    dob = bool(left.births & right.births)
    phone = bool((left.phones & right.phones) - shared_phones)
    if _same_scope_conflict(left.local_ids, right.local_ids) and not (dob and relative >= 2):
        return 0
    if (
        allow_encounter and name == 3 and (not left.hospital or not right.hospital)
        and left.encounter is not None and left.encounter == right.encounter
        and len(left.record_ids) == len(right.record_ids) == 1
        and left.record_ids == right.record_ids
    ):
        return 61
    if allow_named_uhid and left.named_uhid and left.named_uhid == right.named_uhid:
        return _ANCHOR_MIN_SCORE
    if dob and (name >= 2 or relative or phone):
        return 70 + 4 * bool(relative) + 4 * phone + name
    if name >= 2 and phone and relative:
        return 65 + name
    if (name >= 2 and (phone or relative >= 2)) or (relative == 3 and name == 1):
        return 50 + name + (2 if relative == 3 else 0)
    return 0


@dataclass
class LinkageDiagnostics:
    """Only counts, suitable for aggregate practice evaluation."""

    candidate_pairs: int = 0
    supported_pairs: int = 0
    overfull_blocks: int = 0
    shared_phones: int = 0
    ambiguous_records: int = 0
    inconsistent_records: int = 0
    resolved_records: int = 0
    patient_groups: int = 0
    unresolved_records: int = 0


def link_records(
    detections: Iterable[DetectionResult],
    *,
    diagnostics: LinkageDiagnostics | None = None,
) -> LinkageResult:
    """Resolve groups deterministically and map every record key, including unresolved ones."""
    detections = sorted(detections, key=lambda detection: detection.record_key)
    keys = [detection.record_key for detection in detections]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate record key in linkage")
    stats = LinkageDiagnostics()
    profiles = [_profile(detection) for detection in detections]
    inconsistent = {index for index, profile in enumerate(profiles) if _inconsistent(profile)}
    stats.inconsistent_records = len(inconsistent)
    shared_phones = _shared_phones(profiles)
    stats.shared_phones = len(shared_phones)

    # Collapse exact duplicate evidence only when it already supports a link. This
    # keeps repeated exports of the same identity out of high-frequency buckets.
    unique: dict[_Profile, int] = {}
    aliases: dict[int, int] = {}
    buckets: dict[tuple[str, ...], list[int]] = defaultdict(list)
    for index, profile in enumerate(profiles):
        if index in inconsistent:
            continue
        if _score(profile, profile, shared_phones, allow_encounter=False):
            representative = unique.setdefault(profile, index)
            if representative != index:
                aliases[index] = representative
                continue
        for block in _blocks(profile, shared_phones):
            bucket = buckets[block]
            limit = _MAX_ID_BLOCK if block[0] in {"local", "national"} else _MAX_WEAK_BLOCK
            if len(bucket) <= limit:
                bucket.append(index)

    neighbors: dict[int, list[tuple[list[int], int]]] = defaultdict(list)
    eligible_uhids: set[tuple[str, ...]] = set()
    for block, members in buckets.items():
        limit = _MAX_ID_BLOCK if block[0] in {"local", "national"} else _MAX_WEAK_BLOCK
        if block[0] == "encounter" and all(profiles[index].hospital for index in members):
            continue
        if len(members) > limit:
            stats.overfull_blocks += 1
            continue
        if block[0] == "named-uhid":
            # The same UHID and full name can occur at different sites. Any
            # known facility or identity conflict disables this fallback.
            owners = {profiles[index] for index in members}
            if (len({profile.hospital for profile in owners if profile.hospital}) > 1
                    or any(_conflict(a, b) for a, b in combinations(owners, 2))):
                continue
            eligible_uhids.add(block[1:])
        for offset, index in enumerate(members[:-1]):
            neighbors[index].append((members, offset + 1))

    edges: list[tuple[int, int, int]] = []
    support: dict[int, dict[int, int]] = defaultdict(dict)
    for left, sources in neighbors.items():
        candidates = {right for members, offset in sources for right in members[offset:]}
        stats.candidate_pairs += len(candidates)
        for right in candidates:
            score = _score(
                profiles[left], profiles[right], shared_phones,
                allow_named_uhid=profiles[left].named_uhid in eligible_uhids,
            )
            if score:
                edges.append((-score, left, right))
                support[left][right] = score
                support[right][left] = score
    stats.supported_pairs = len(edges)

    def compatible_via_anchor(left: int, right: int, anchor: int) -> bool:
        links = support[anchor]
        scores = links.get(left, 0), links.get(right, 0)
        a, b, source = profiles[left], profiles[right], profiles[anchor]
        if min(scores) < _ANCHOR_MIN_SCORE or _conflict(a, b):
            return False
        if _same_scope_conflict(a.local_ids, b.local_ids):
            return False
        if max(scores) == _NATIONAL_MATCH_SCORE:
            return True
        if not source.hospital or not source.named_uhid or source.named_uhid not in eligible_uhids:
            return False
        scope = (source.hospital, "UHID")
        uhid = source.named_uhid[0]
        left_uhids = {value for key, value in a.local_ids if key == scope}
        right_uhids = {value for key, value in b.local_ids if key == scope}
        return (
            (left_uhids == {uhid} and b.named_uhid == source.named_uhid)
            or (right_uhids == {uhid} and a.named_uhid == source.named_uhid)
        )

    ambiguous = set()
    for index, ranked in support.items():
        best = max(ranked.values())
        rivals = [other for other, score in ranked.items() if score >= best - 3]
        if any(b not in support[a] and not compatible_via_anchor(a, b, index)
               for a, b in combinations(rivals, 2)):
            ambiguous.add(index)
    stats.ambiguous_records = len(ambiguous) + sum(
        representative in ambiguous for representative in aliases.values()
    )

    roots = list(range(len(keys)))
    groups: dict[int, set[int]] = {}
    for _, left, right in sorted(edges):
        if left in ambiguous or right in ambiguous:
            continue
        a_root, b_root = sorted((roots[left], roots[right]))
        if a_root == b_root:
            continue
        a = groups.get(a_root, {a_root})
        b = groups.get(b_root, {b_root})
        # Ordinarily every pair needs direct support. A single anchor can cover
        # missing pairs when it strongly matches every member and corroborates
        # each missing pair through a national ID or a facility-scoped UHID.
        members = a | b
        if not all(j in support[i] for i in a for j in b) and not any(
            all(
                member == anchor or support[anchor].get(member, 0) >= _ANCHOR_MIN_SCORE
                for member in members
            ) and all(j in support[i] or compatible_via_anchor(i, j, anchor) for i in a for j in b)
            for anchor in members if profiles[anchor].national_ids or profiles[anchor].hospital
        ):
            continue
        for member in b:
            roots[member] = a_root
        groups[a_root] = members
        groups.pop(b_root, None)

    repeated = Counter(aliases.values())
    result = {}
    group_keys: dict[int, str] = {}
    for index, key in enumerate(keys):
        representative = aliases.get(index, index)
        profile = profiles[representative]
        root = roots[representative]
        corroborated = bool(_score(profile, profile, shared_phones, allow_encounter=False))
        if representative in ambiguous or representative in inconsistent or not (
            root in groups or repeated[representative] or corroborated
        ):
            result[key] = None
        else:
            if root not in group_keys:
                # Only an internal record handle seeds this key. The privacy layer
                # can use the resulting opaque key as an input to its keyed HMAC.
                group_keys[root] = "group-" + sha256(keys[root].encode("utf-8")).hexdigest()
            result[key] = group_keys[root]
    stats.patient_groups = len(group_keys)
    stats.resolved_records = sum(value is not None for value in result.values())
    stats.unresolved_records = len(result) - stats.resolved_records
    if diagnostics is not None:
        for name, value in vars(stats).items():
            setattr(diagnostics, name, value)
    return result


@dataclass(frozen=True)
class LinkageMetrics:
    true_matches: int
    missed_matches: int
    false_merges: int
    unresolved_records: int


def evaluate_links(
    linkage: Mapping[str, str | None], expected_groups: Mapping[str, str | None],
) -> LinkageMetrics:
    """Count pairs against in-memory practice truth joined on the stable record key."""
    actual_counts: Counter[str] = Counter()
    expected_counts: Counter[str] = Counter()
    joint_counts: Counter[tuple[str, str]] = Counter()
    unresolved = 0
    for record_key, expected in expected_groups.items():
        if expected is None:
            continue
        expected_counts[expected] += 1
        actual = linkage.get(record_key)
        if actual is None:
            unresolved += 1
        else:
            actual_counts[actual] += 1
            joint_counts[expected, actual] += 1
    true_matches = sum(count * (count - 1) // 2 for count in joint_counts.values())
    expected_pairs = sum(count * (count - 1) // 2 for count in expected_counts.values())
    actual_pairs = sum(count * (count - 1) // 2 for count in actual_counts.values())
    return LinkageMetrics(true_matches, expected_pairs - true_matches, actual_pairs - true_matches, unresolved)
