"""FHIR R4 JSON structure and in-document reference integrity checks."""

import re
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlsplit

from ._errors import Reject
from .json_records import get

_ID = re.compile(r"[A-Za-z0-9.-]{1,64}")
# Concrete resource types from the HL7 FHIR R4 4.0.1 ResourceType expansion.
# https://hl7.org/fhir/R4/valueset-resource-types.html
_RESOURCE_TYPES = frozenset("""
Account ActivityDefinition AdverseEvent AllergyIntolerance Appointment
AppointmentResponse AuditEvent Basic Binary BiologicallyDerivedProduct BodyStructure
Bundle CapabilityStatement CarePlan CareTeam CatalogEntry ChargeItem ChargeItemDefinition
Claim ClaimResponse ClinicalImpression CodeSystem Communication CommunicationRequest
CompartmentDefinition Composition ConceptMap Condition Consent Contract Coverage
CoverageEligibilityRequest CoverageEligibilityResponse DetectedIssue Device
DeviceDefinition DeviceMetric DeviceRequest DeviceUseStatement DiagnosticReport
DocumentManifest DocumentReference EffectEvidenceSynthesis Encounter Endpoint
EnrollmentRequest EnrollmentResponse EpisodeOfCare EventDefinition Evidence
EvidenceVariable ExampleScenario ExplanationOfBenefit FamilyMemberHistory Flag Goal
GraphDefinition Group GuidanceResponse HealthcareService ImagingStudy Immunization
ImmunizationEvaluation ImmunizationRecommendation ImplementationGuide InsurancePlan
Invoice Library Linkage List Location Measure MeasureReport Media Medication
MedicationAdministration MedicationDispense MedicationKnowledge MedicationRequest
MedicationStatement MedicinalProduct MedicinalProductAuthorization
MedicinalProductContraindication MedicinalProductIndication MedicinalProductIngredient
MedicinalProductInteraction MedicinalProductManufactured MedicinalProductPackaged
MedicinalProductPharmaceutical MedicinalProductUndesirableEffect MessageDefinition
MessageHeader MolecularSequence NamingSystem NutritionOrder Observation
ObservationDefinition OperationDefinition OperationOutcome Organization
OrganizationAffiliation Parameters Patient PaymentNotice PaymentReconciliation Person
PlanDefinition Practitioner PractitionerRole Procedure Provenance Questionnaire
QuestionnaireResponse RelatedPerson RequestGroup ResearchDefinition
ResearchElementDefinition ResearchStudy ResearchSubject RiskAssessment
RiskEvidenceSynthesis Schedule SearchParameter ServiceRequest Slot Specimen
SpecimenDefinition StructureDefinition StructureMap Subscription Substance
SubstanceNucleicAcid SubstancePolymer SubstanceProtein SubstanceReferenceInformation
SubstanceSourceMaterial SubstanceSpecification SupplyDelivery SupplyRequest Task
TerminologyCapabilities TestReport TestScript ValueSet VerificationResult
VisionPrescription
""".split())
_REST = re.compile(
    r"(?:(https?://[^/?#]+(?:/[^/?#]+)*)/)?"
    r"([A-Z][A-Za-z0-9]+/[A-Za-z0-9.-]{1,64})(?:/_history/([A-Za-z0-9.-]{1,64}))?"
)
_BUNDLES = {
    "document", "message", "transaction", "transaction-response", "batch",
    "batch-response", "history", "searchset", "collection",
}
_REFERENCE_KEYS = {"id", "extension", "reference", "type", "identifier", "display"}
_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"}


def _require(condition):
    if not condition:
        raise Reject("invalid_fhir")


def _match(pattern, value):
    return pattern.fullmatch(value) if isinstance(value, str) else None


def _identifier(node):
    _require(isinstance(node, dict))
    for key in ("system", "value"):
        if key in node:
            _require(isinstance(node[key], str) and bool(node[key]))
    return node.get("system"), node.get("value")


@dataclass(repr=False)
class Resource:
    path: tuple
    node: dict
    owner: tuple
    full_url: str | None = None

    @property
    def relative(self):
        if "id" in self.node:
            return self.node["resourceType"] + "/" + self.node["id"]
        return None

    @property
    def version(self):
        return self.node.get("meta", {}).get("versionId")

    @property
    def base(self):
        match = _match(_REST, self.full_url)
        return match[1] if match else None


def _resources(root, *, check_urls=True):
    resources = {}

    def add(node, path, owner, full_url=None):
        _require(isinstance(node, dict))
        kind = node.get("resourceType")
        _require(isinstance(kind, str) and kind in _RESOURCE_TYPES)
        if "id" in node:
            _require(_match(_ID, node["id"]))
        if "meta" in node:
            _require(isinstance(node["meta"], dict))
            if "versionId" in node["meta"]:
                _require(_match(_ID, node["meta"]["versionId"]))
        if path and kind == "Bundle":
            raise Reject("nested_fhir_bundle")
        info = Resource(path, node, owner, full_url)
        resources[path] = info
        if full_url is not None:
            match = _match(_REST, full_url)
            if check_urls and match and match[1] and info.relative:
                _require(match[2] == info.relative)
        contained = node.get("contained", [])
        _require(isinstance(contained, list))
        _require(path == owner or not contained)
        ids = set()
        for index, child in enumerate(contained):
            _require(isinstance(child, dict) and _match(_ID, child.get("id")))
            _require(child["id"] not in ids)
            ids.add(child["id"])
            add(child, path + ("contained", index), owner)

    add(root, (), ())
    if root["resourceType"] == "Bundle":
        kind = root.get("type")
        _require(isinstance(kind, str) and kind in _BUNDLES)
        if "total" in root:
            _require(kind in {"searchset", "history"} and type(root["total"]) is int
                     and root["total"] >= 0)
        entries = root.get("entry", [])
        _require(isinstance(entries, list))
        seen = set()
        for index, entry in enumerate(entries):
            _require(isinstance(entry, dict))
            request, response = entry.get("request"), entry.get("response")
            _require(("request" in entry) == (kind in {"batch", "transaction", "history"}))
            _require(("response" in entry) == (kind in {"batch-response", "transaction-response", "history"}))
            _require("search" not in entry or kind == "searchset")
            if "request" in entry:
                _require(isinstance(request, dict) and isinstance(request.get("method"), str)
                         and request["method"] in _METHODS and isinstance(request.get("url"), str)
                         and bool(request["url"]))
            if "response" in entry:
                _require(isinstance(response, dict) and isinstance(response.get("status"), str)
                         and bool(response["status"]))
            full_url = entry.get("fullUrl")
            if "fullUrl" in entry:
                _require(isinstance(full_url, str) and bool(urlsplit(full_url).scheme)
                         and "/_history/" not in full_url
                         and not any(c.isspace() for c in full_url))
            if "resource" not in entry:
                _require((request or response) and kind not in {"document", "message"})
                continue
            if kind in {"document", "message", "collection"}:
                _require(full_url)
            path = ("entry", index, "resource")
            add(entry["resource"], path, path, full_url)
            if full_url:
                identity = (full_url, resources[path].version)
                _require(kind == "history" or identity not in seen)
                seen.add(identity)
        if kind == "document":
            _require(all(_identifier(root.get("identifier"))))
            _require(isinstance(root.get("timestamp"), str) and bool(root["timestamp"]))
        if kind in {"document", "message"}:
            first = resources.get(("entry", 0, "resource"))
            _require(first and first.node["resourceType"] ==
                     ("Composition" if kind == "document" else "MessageHeader"))
        patients = sum(info.node["resourceType"] == "Patient" for info in resources.values())
        if patients > 1:
            raise Reject("multi_patient_fhir_bundle")
    return resources


class ReferenceIndex:
    def __init__(self, resources, bundle):
        self.resources = resources
        self.bundle = bundle
        self.urls = defaultdict(list)
        self.relative = defaultdict(list)
        self.contained = {}
        self.identifiers = defaultdict(list)
        for path, info in resources.items():
            if info.path != info.owner:
                self.contained[(info.owner, info.node["id"])] = path
            else:
                if info.full_url:
                    self.urls[info.full_url].append(path)
                if info.relative:
                    self.relative[info.relative].append(path)
            identifiers = info.node.get("identifier", [])
            if isinstance(identifiers, dict):
                identifiers = [identifiers]
            _require(isinstance(identifiers, list))
            for index, identifier in enumerate(identifiers):
                system, value = _identifier(identifier)
                if value:
                    field = info.node["identifier"]
                    subpath = ("identifier", index) if isinstance(field, list) else ("identifier",)
                    self.identifiers[(system, value)].append(path + subpath)
                    if system:
                        self.identifiers[(None, value)].append(path + subpath)

    def literal(self, source, value):
        if value == "#":
            _require(source.path != source.owner)
            return source.owner
        if value.startswith("#"):
            target = self.contained.get((source.owner, value[1:]))
            _require(target is not None)
            return target
        rest = _match(_REST, value)
        base = self.resources[source.owner].base
        version = rest[3] if rest else None
        if value in self.urls:
            candidates = self.urls[value]
        elif rest and rest[1]:
            candidates = self.urls.get(f"{rest[1]}/{rest[2]}", ())
        elif rest and base:
            candidates = self.urls.get(f"{base}/{rest[2]}", ())
        elif rest:
            candidates = self.relative.get(rest[2], ())
        else:
            candidates = ()
        if version:
            candidates = [path for path in candidates if self.resources[path].version == version]
        _require(len(candidates) <= 1)
        if self.bundle and (value.startswith(("urn:uuid:", "urn:oid:")) or (rest and not rest[1])):
            _require(candidates)
        return candidates[0] if candidates else None

    def logical(self, source, identifier, reference_type):
        key = _identifier(identifier)
        candidates = self.identifiers.get(key, ())
        if isinstance(reference_type, str):
            kind = reference_type.rsplit("/", 1)[-1]
            candidates = [path for path in candidates
                          if _resource_at(self.resources, path).node["resourceType"] == kind]
        in_scope = []
        for path in candidates:
            resource = _resource_at(self.resources, path)
            if resource.owner in {source.owner, resource.path}:
                in_scope.append(path)
        candidates = in_scope
        _require(len(candidates) <= 1)
        return candidates[0] if candidates else None


def _resource_at(resources, path):
    while path not in resources:
        path = path[:-1]
    return resources[path]


def _reference_fields(tree, resources):
    def visit(node, path, source):
        source = resources.get(path, source)
        if isinstance(node, dict):
            for key, child in node.items():
                here = path + (key,)
                if key == "reference":
                    _require(isinstance(child, str) and bool(child)
                             and not any(c.isspace() for c in child))
                    yield here, source, "literal", child, None
                elif key == "identifier" and isinstance(child, dict) and all(
                    part in _REFERENCE_KEYS or part.startswith("_") for part in node
                ):
                    yield here, source, "logical", child, node.get("type")
                elif path[:1] == ("entry",) and len(path) == 3 and (
                    (path[2], key) in {("request", "url"), ("response", "location")}
                ):
                    _require(isinstance(child, str) and bool(child))
                    entry_resource = resources.get(("entry", path[1], "resource"), source)
                    yield here, entry_resource, "literal", child, None
                else:
                    yield from visit(child, here, source)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                yield from visit(child, path + (index,), source)
    return visit(tree, (), resources[()])


def validate_fhir(root):
    try:
        index = ReferenceIndex(_resources(root), root["resourceType"] == "Bundle")
        for _, source, mode, value, kind in _reference_fields(root, index.resources):
            if mode == "literal":
                index.literal(source, value)
            else:
                index.logical(source, value, kind)
    except (TypeError, ValueError, RecursionError):
        raise Reject("invalid_fhir") from None


def patient_managing_organization(root):
    """Return the name of the Organization the Patient explicitly references."""
    resources = _resources(root)
    patient = next((item for item in resources.values()
                    if item.node["resourceType"] == "Patient"), None)
    if patient is None:
        return None
    managing = patient.node.get("managingOrganization")
    if not isinstance(managing, dict):
        return None
    reference = managing.get("reference")
    if not isinstance(reference, str) or not reference:
        return None
    index = ReferenceIndex(resources, root["resourceType"] == "Bundle")
    target = index.literal(patient, reference)
    if target is None or resources[target].node["resourceType"] != "Organization":
        return None
    # A different explicit issuer makes a single facility scope unsafe.
    identifiers = patient.node.get("identifier", [])
    if isinstance(identifiers, dict):
        identifiers = [identifiers]
    for entry in identifiers:
        if isinstance(entry, dict) and "assigner" in entry:
            assigner = entry["assigner"]
            literal = assigner.get("reference") if isinstance(assigner, dict) else None
            if not isinstance(literal, str) or index.literal(patient, literal) != target:
                return None
    name = resources[target].node.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else None


def _updated_literal(value, before, after):
    if value == "#":
        return value
    if value.startswith("#"):
        return "#" + after.node["id"]
    rest = _match(_REST, value)
    if value == before.full_url or (rest and rest[1] and before.full_url):
        _require(after.full_url)
        result = after.full_url
    else:
        _require(after.relative)
        result = after.relative
    if rest and rest[3]:
        _require(after.version)
        result += "/_history/" + after.version
    return result


def _set_consistent(tree, path, replacement, explicit):
    container = get(tree, path[:-1])
    if path in explicit and container[path[-1]] != replacement:
        raise Reject("inconsistent_fhir_rewrite")
    container[path[-1]] = replacement


def resource_id_spans(tree, edited_ids):
    """Find ID substrings the reference writer will update when it changes a resource ID."""
    resources = _resources(tree)
    index = ReferenceIndex(resources, tree["resourceType"] == "Bundle")
    changed = {path[:-1] for path in edited_ids}
    spans = {}
    for path in changed:
        resource = resources.get(path)
        if resource and resource.base:
            url = _match(_REST, resource.full_url)
            end = url.end(2)
            spans[path[:-1] + ("fullUrl",)] = (end - len(resource.node["id"]), end)
    for path, source, mode, value, _ in _reference_fields(tree, resources):
        if mode != "literal":
            continue
        target = index.literal(source, value)
        if target not in changed:
            continue
        if value.startswith("#") and value != "#":
            spans[path] = (1, len(value))
        elif match := _match(_REST, value):
            end = match.end(2)
            spans[path] = (end - len(resources[target].node["id"]), end)
    return spans


def rewrite_references(original, rewritten, explicit):
    old = _resources(original)
    new = _resources(rewritten, check_urls=False)
    _require(old.keys() == new.keys())
    for path, before in old.items():
        after = new[path]
        _require(before.node["resourceType"] == after.node["resourceType"])
        if before.base and before.relative != after.relative and len(path) == 3 and path[0] == "entry":
            url_path = path[:-1] + ("fullUrl",)
            _require(after.relative)
            # A planned URL may choose a different base, but it must agree with id.
            if url_path not in explicit:
                _set_consistent(rewritten, url_path, f"{before.base}/{after.relative}", explicit)

    bundle = original["resourceType"] == "Bundle"
    old_index = ReferenceIndex(old, bundle)
    new_index = ReferenceIndex(_resources(rewritten), bundle)
    for path, source, mode, value, kind in _reference_fields(original, old):
        if mode == "literal":
            target = old_index.literal(source, value)
            if target is not None:
                expected = _updated_literal(value, old[target], new_index.resources[target])
                _set_consistent(rewritten, path, expected, explicit)
                if new_index.literal(new_index.resources[source.path], expected) != target:
                    raise Reject("inconsistent_fhir_rewrite")
        else:
            target = old_index.logical(source, value, kind)
            if target is None:
                continue
            system, identifier = _identifier(get(rewritten, target))
            if system and "system" in value:
                _set_consistent(rewritten, path + ("system",), system, explicit)
            if identifier:
                _set_consistent(rewritten, path + ("value",), identifier, explicit)
            observed = get(rewritten, path)
            if new_index.logical(new_index.resources[source.path], observed, kind) != target:
                raise Reject("inconsistent_fhir_rewrite")
