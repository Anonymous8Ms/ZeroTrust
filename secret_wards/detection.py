"""Find sensitive and protected targets against the unmodified parsed record.

Paths contain keys and indices relative to the record. The adapter identifies
hidden surfaces. Missing offsets select a whole field. Text offsets are
half-open Python string indices.
"""

from __future__ import annotations

from array import array
from base64 import b64decode
from binascii import Error as InvalidBase64
from bisect import bisect_right
from collections.abc import Mapping
from dataclasses import dataclass, field
import re
from typing import Iterable, Protocol, Union

from .normalization import birth_date, date_order_hint, matching_text, phone_number

Path = tuple[Union[str, int], ...]


class ParsedRecordView(Protocol):
    record_key: str
    source_file: object
    loc: str
    format: str
    content: object


@dataclass(frozen=True)
class TextSurface:
    """An adapter-supplied filename, header, key, metadata, or content value."""

    text: str = field(repr=False)
    channel: str = "content"
    path: Path = field(default=(), repr=False)
    label: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class Target:
    kind: str
    path: Path = field(repr=False)
    channel: str = "content"
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True)
class IdentityEvidence:
    kind: str
    value: str = field(repr=False)
    role: str = "patient"


@dataclass(frozen=True)
class DetectionResult:
    record_key: str = field(repr=False)
    identity_evidence: tuple[IdentityEvidence, ...] = field(repr=False)
    sensitive_targets: tuple[Target, ...] = field(repr=False)
    protected_clinical_targets: tuple[Target, ...] = field(repr=False)
    hospital: str | None = field(default=None, repr=False)
    day_first: bool | None = None
    fallback_day_first: bool | None = None


def _rules(groups: dict[str, str]) -> dict[str, str]:
    return {label: kind for kind, labels in groups.items() for label in labels.split("|")}


_LABELS = _rules({
    "PATIENT_NAME": "patient|name|patient name|patient s name|name of patient|name patient|full name|pt name|beneficiary name|naam|नाम|मरीज|मरीज़|रोगी|मरीज का नाम|मरीज़ का नाम|रोगी का नाम",
    "FIRST_NAME": "first|first name|firstname|given|given name|पहला नाम",
    "MIDDLE_NAME": "middle|middle name|middlename",
    "LAST_NAME": "last|last name|lastname|surname|family|family name|उपनाम",
    "RELATIVE_NAME": "relative|relative name|guardian|guardian name|attendant|attendant name|caller|caregiver|pita pati ka naam|care of|family member|अभिभावक|रिश्तेदार का नाम",
    "FATHER_NAME": "father|father name|fathers name|father s name|s o|पिता का नाम|पिता",
    "MOTHER_NAME": "mother|mother name|mothers name|mother s name|माता का नाम|माता",
    "SPOUSE_NAME": "spouse|spouse name|husband|husband name|wife name|w o|पति|पति का नाम|पत्नी का नाम",
    "RELATION": "relation|relationship|relative relation|रिश्ता|संबंध",
    "PHONE": "phone|phone number|telephone|mobile|mobile no|mobile number|contact|contact no|contact number|cell|whatsapp|फोन|फ़ोन|फोन नंबर|मोबाइल|मोबाइल नंबर|दूरभाष|संपर्क",
    "ADDRESS": "address|full address|postal address|residential address|home address|street|address note|address line|house no|house number|mohalla|pata|पता|घर का पता|मोहल्ला",
    "VILLAGE": "village|city|gram|gram mohalla|village mohalla|gaon|ग्राम|गांव|गाँव",
    "TEHSIL": "tehsil|taluk|block|तहसील",
    "DISTRICT": "district|distt|dist|jila|location|जिला|ज़िला",
    "PIN": "pin|pincode|pin code|zip|postal code|पिन|पिन कोड",
    "AADHAAR": "aadhaar|aadhar|adhaar|adhar|aadhar no|aadhaar no|aadhaar number|uidai|आधार|आधार संख्या",
    "ABHA_NUMBER": "abha|abha id|abha no|abha number|health id|आभा|आभा संख्या",
    "PAN": "pan|pan no|pan number|पैन|पैन नंबर",
    "MRN": "mrn|mrn no|medical record no|medical record number|medical record id|एमआरएन",
    "UHID": "uhid|uhid no|hospital id|hospital uhid|patient id|patient ref|registration id|registration no|registration number|reg no|यूएचआईडी|पंजीकरण सं|पंजीकरण संख्या",
    "ENCOUNTER_ID": "ipd no|ipd number|ipd id|visit no|visit number|visit id|encounter id|आईपीडी सं|आईपीडी संख्या",
    "INSURANCE_ID": "insurance|insurance no|insurance id|claim id|claim no|policy id|policy no|policy number|member id|tpa id|pmjay id|बीमा आईडी|बीमा संख्या|पॉलिसी नंबर",
    "REFERENCE_NAME": "patient reference display",
    "DOB": "dob|d o b|birthdate|birth date|birthdate|date of birth|janm tithi|जन्म तिथि|जन्म तारीख|जन्मतिथि",
    "AGE": "age|age years|umar|उम्र|आयु",
    "ADMISSION_DATE": "admission|admission date|date of admission|admit date|admitted|admitted on|प्रवेश|भर्ती|भर्ती की तिथि|भर्ती की तारीख",
    "DISCHARGE_DATE": "discharge|discharge date|date of discharge|discharged|discharged on|छुट्टी|छुट्टी की तिथि|छुट्टी की तारीख",
    "DATE": "date|visit date|registration date|reg date|registered|registered on|collection date|collected|collected on|reported on|report date|prescription date|दिनांक|तारीख",
    "EMAIL": "email|e mail|email address|ईमेल",
    "HOSPITAL": "hospital|hospital name|facility|facility name|अस्पताल|अस्पताल का नाम",
    "DOCTOR": "doctor|doctor name|physician|dr|consultant|clinician|practitioner|attending|डॉक्टर|चिकित्सक",
    "CLINICAL": "diagnosis|diagnoses|complaint|complaints|symptom|symptoms|procedure|procedures|medication|medications|medicines|medicine|drug|dose|dosage|frequency|rx|vitals|bp|pulse|hr|temperature|spo2|hba1c|hb|hemoglobin|creatinine|glucose|lab value|lab result|result|length of stay|los|निदान|दवा|शिकायत|खुराक",
})
DATE_KINDS = {"DOB", "DATE", "ADMISSION_DATE", "DISCHARGE_DATE", "TIMESTAMP_DATE"}
ENCOUNTER_DATES = {"ADMISSION_DATE", "DISCHARGE_DATE"}
_SOURCE_PATHS = {"source path", "source file", "file name", "filename", "export path"}
_ATTACHMENTS = {"attachment", "attachments", "document attachment"}
_METADATA = {"metadata", "meta", "export metadata", "export meta"} | _SOURCE_PATHS | _ATTACHMENTS
_UNKNOWN = {"none", "null", "unknown", "na", "n/a", "nil", "-", "--", "redacted", "अज्ञात"}
_IDENTITY = {"PATIENT_NAME", "RELATIVE_NAME", "PHONE", "AADHAAR", "ABHA_NUMBER", "PAN", "UHID", "MRN", "DOB"}
_NAME_PARTS = {"FIRST_NAME", "MIDDLE_NAME", "LAST_NAME"}
_RELATIVES = {"FATHER_NAME": "father", "MOTHER_NAME": "mother", "SPOUSE_NAME": "spouse", "RELATIVE_NAME": "relative"}

_WORD = r"[^\W\d_](?:[^\W\d_]|[\u0300-\u036f\u0900-\u0963.'’\-])*"
_NAME = rf"{_WORD}(?:[ \t]+{_WORD}){{0,5}}"
_NAME_PATTERN = re.compile(_NAME)
_TITLE = r"(?:mr|mrs|ms|shri|sri|smt|श्री|श्रीमती)\.?"
_HONORIFIC = r"(?:ji|sahab|saheb|sahib|didi|bhai|जी|साहब|दीदी)"
_EDGE = r"(?<![^\W_])"  # unlike a word boundary, accepts underscore-separated filenames
_END = r"(?![^\W_])"
_RX = re.IGNORECASE
# Match dotted labels in place so punctuation removal never shifts rewrite spans.
_DOTTED_ID_LABEL = r"(?:m\.[ \t]*r\.[ \t]*n|u\.[ \t]*h\.[ \t]*i\.[ \t]*d)"
_DOTTED_ID = re.compile(_EDGE + rf"(?P<abbr>{_DOTTED_ID_LABEL})\.?" + _END, _RX)
_ID_COMPATIBILITY = str.maketrans({
    **{chr(codepoint + 0xFEE0): chr(codepoint) for codepoint in range(0x21, 0x7F)},
    "\u2024": ".", "\ufe52": ".", "\u3002": ".", "\uff61": ".", "\u00a0": " ", "\u3000": " ",
})
_ID_FORMAT_CONTROLS = re.compile(r"[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_LABEL_IN_TEXT = re.compile(
    _EDGE + rf"({_DOTTED_ID_LABEL}|" + "|".join(
        re.escape(label) for label in sorted(_LABELS, key=lambda label: (-len(label), label))
        if label not in {"dr", "s o", "w o"}
    ) + r")\.?(?:[ \t]*\((?:attendant|guardian|caregiver|patient)\))?\s*[:=：]\s*(?=\S)", _RX,
)
_RELATION_IN_TEXT = re.compile(
    _EDGE + r"(?P<marker>[sdwc]\s*/\s*o|[sdwc]\s*\.\s*o\.?|son of|daughter of|wife of|husband of|care of|पुत्री?|पत्नी|पुत्र वधू)\s*[:：]?[ \t]+",
    _RX,
)
_RELATION_SUFFIX = re.compile(r"\s*/\s*o\b", _RX)
_CLINICAL_START = re.compile(
    r"(?:fevers?|bukhar|बुखार|ज्वर|खाँसी|खांसी|दर्द|उल्टी|दस्त|"
    r"cough|pain|vomiting|diarrh?oea|diarrhea|headache|rash|weakness|breathlessness|"
    r"cold|sore throat|shortness of breath|chest pain|abdominal pain|dyspn(?:ea|oea)|"
    r"dengue|malaria|diabetes|hypertension|asthma|nausea|giddiness|loose stools|"
    r"burning|swelling|bleeding|fracture|seizures?|loss of appetite|generalized weakness|"
    r"(?:joint|back|lower back|knee|stomach|leg|shoulder|pelvic|throat) pain|"
    r"breathing difficulty|sob|uti|palpitations|constipation|dysuria|vertigo|"
    r"Parkinson(?:['’]s)? disease|Addison(?:['’]s)? disease|post[- ]operative)"
    + _END, _RX,
)
_NAME_STOP = {
    "age", "aged", "gender", "sex", "dob", "phone", "mobile", "address", "mrn",
    "uhid", "abha", "aadhaar", "bp", "pulse", "temperature", "doctor", "dr",
    "admitted", "visited", "presents", "presented", "diagnosis", "dx", "rx",
    "for", "with", "from", "ka", "ki", "ko", "has", "on", "reports",
    "ji", "sahab", "saheb", "sahib", "didi", "bhai", "जी", "साहब", "दीदी",
    "नाम", "आयु", "उम्र", "पता", "का", "की", "को", "है", "दवा", "बीपी",
}
_DOCTOR = re.compile(_EDGE + rf"(?:dr\.?|doctor|डॉ\.?|डॉक्टर)[ \t]+(?P<name>{_NAME})", _RX)
_DOCTOR_SPECIALTY = re.compile(
    r"[ \t]*\([ \t]*(?:(?:m\.?[ \t]*s\.?|general|laparoscopic|cardiac|cardiothoracic|"
    r"plastic|vascular|paediatric|pediatric|orthopaedic|orthopedic|neurological|"
    r"trauma|dental|oral|maxillofacial|ent|gi|gastrointestinal|colorectal|"
    r"robotic|bariatric|oncologic|neuro|breast|endocrine|thoracic|urologic)[ \t]+"
    r"){1,2}surgery[ \t]*\)", _RX,
)
_UNPUNCTUATED_NAME = re.compile(
    rf"(?m)^[ \t]*(?:pt\.?|patient name|मरीज़ का नाम|मरीज का नाम|रोगी का नाम|नाम)[ \t]+(?P<name>{_NAME})",
    _RX,
)
_HOSPITAL_IN_TEXT = re.compile(
    r"(?im)^[ \t]*(?:hospital(?: name)?|facility(?: name)?|अस्पताल(?: का नाम)?)[ \t]*[:=：][ \t]*(?P<hospital>[^\r\n,;|]+)",
)
_HINGLISH_NAME = re.compile(
    _EDGE + rf"(?P<name>{_WORD}(?:[ \t]+{_WORD}){{0,2}})[ \t]+{_HONORIFIC}"
    r"(?=[ \t]*(?:[,;:\n]|$|(?:ka|ki|ko|age|bp|patient|का|की|को|आयु|बीपी)\b|\d))", _RX,
)
_TITLED_NAME = re.compile(_EDGE + rf"(?P<name>{_TITLE}[ \t]+{_NAME})", _RX)
_FRAGMENT = re.compile(rf"(?m)^[ \t]*(?P<name>{_NAME})[ \t]*,[ \t]*(?=[sdw]\s*/\s*o\b)", _RX)
_CALLER = re.compile(
    _EDGE + rf"(?:called|reported|brought|accompanied)[ \t]+by[ \t:]+(?P<name>{_NAME})",
    _RX,
)
_ATTENDANT = re.compile(
    rf"(?m)^[ \t]*(?:\d{{1,2}}:\d{{2}}[ \t]*[-–—][ \t]*)?(?P<name>{_NAME})"
    r"[ \t]*\([ \t]*(?:attendant|guardian|relative|caregiver|family member)\b",
    _RX,
)
_CHAT_SENDER = re.compile(
    rf"(?m)^[ \t]*\[\d{{1,2}}[/.-]\d{{1,2}}[/.-]\d{{2,4}},[ \t]*"
    rf"\d{{1,2}}:\d{{2}}[ \t]*(?:am|pm)?\][ \t]*(?P<name>{_NAME})[ \t]*:",
    _RX,
)
_ENCOUNTER_NAME = re.compile(
    rf"(?m)^[ \t]*(?:report of[ \t]+|\d{{1,2}}:\d{{2}}[ \t]*[-–—][ \t]*)"
    rf"(?P<name>{_NAME})(?=[ \t]+(?:\d{{1,3}}[ \t]*y\b|[-–—][ \t]*K/C/O\b))",
    _RX,
)
_PATIENT_IN_NOTE = re.compile(
    r"(?m)^[ \t]*(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}[ \t]+)?"
    r"(?:\d{1,2}:\d{2}[ \t]*[-–—][ \t]*)?"
    rf"(?P<name>{_NAME})(?=[ \t]+(?:ka[ \t]+BP\b|को[ \t]+\d+[ \t]+दिन\b))",
    _RX,
)
_PROGRESS_SUBJECT = re.compile(
    r"(?m)(?:^|(?<=[.!?]))[ \t]*"
    r"(?P<name>[A-Za-z\u0900-\u0963]+(?:[ \t]+[A-Za-z\u0900-\u0963]+){1,4})"
    r"(?=[ \t]+(?:ki[ \t]+(?:condition|tabiyat)|की[ \t]+हालत)\b)",
    _RX,
)
_SAMPLE_SUBJECT = re.compile(
    _EDGE + rf"sample[ \t]+received[ \t]+from[ \t]+(?P<name>{_NAME})(?=['’]s[ \t]+attendant\b)",
    _RX,
)
_NARRATIVE_SUBJECT = re.compile(
    rf">[ \t]*(?P<name>{_NAME}),[ \t]*(?P<age>\d{{1,3}})(?=[ \t]*(?:y|yrs?|years?)\b)", _RX,
)
_PHONE_SEPARATOR = r"[ .–-]?"
_PHONE_PREFIX = rf"(?:\+?[9९][1१]{_PHONE_SEPARATOR}|[0०]{{2}}[9९][1१]{_PHONE_SEPARATOR}|[0०]{_PHONE_SEPARATOR})?"
_PHONE = re.compile(
    _EDGE + _PHONE_PREFIX
    + rf"(?:\(?[6-9६-९]\d{{4}}\)?{_PHONE_SEPARATOR}\d{{5}}|"
    rf"\(?[6-9६-९]\d{{2}}\)?{_PHONE_SEPARATOR}\d{{3}}{_PHONE_SEPARATOR}\d{{4}}|"
    rf"\(?[6-9६-९]\d{{3}}\)?{_PHONE_SEPARATOR}\d{{6}}|"
    rf"\(?[6-9६-९]\d{{2}}\)?{_PHONE_SEPARATOR}\d{{7}})" + _END
)
_AADHAAR = re.compile(_EDGE + r"\d{4}[ -]?\d{4}[ -]?\d{4}" + _END)
_ABHA = re.compile(_EDGE + r"\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}" + _END)
_PAN = re.compile(_EDGE + r"[A-Z]{5}\d{4}[A-Z]" + _END, _RX)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_CODE = r"[A-Z0-9\u0966-\u096f][A-Z0-9\u0966-\u096f./_-]{1,31}(?![A-Z0-9\u0966-\u096f./_-])"
_CODE_VALUE = re.compile(_CODE, _RX)
_VALUE_PATTERNS = {
    "PHONE": _PHONE, "AADHAAR": _AADHAAR, "ABHA_NUMBER": _ABHA, "PAN": _PAN,
    "MRN": _CODE_VALUE, "UHID": _CODE_VALUE, "ENCOUNTER_ID": _CODE_VALUE,
    "INSURANCE_ID": _CODE_VALUE, "EMAIL": _EMAIL,
}
_BARE_ID = re.compile(
    _EDGE + r"(?:[A-Z]{2,8}[-/](?:\d{2,4}[-/]\d{3,10}|\d{5,10})|[A-Z]{2,8}\d{6,10})" + _END,
    _RX,
)
_LABELLED_ID = re.compile(
    _EDGE + rf"(?P<label>{_DOTTED_ID_LABEL}\.?|mrn|uhid|patient id|hospital id|"
    r"registration no\.?|claim id|policy no\.?|insurance id)"
    rf"(?:[ \t]*[:=#][ \t]*|[ \t]+)(?P<value>{_CODE})", _RX,
)
_SCHEMA_ID_LABELS = (
    "medical record number", "medical record no", "medical record id",
    "registration number", "registration no", "registration id",
    "patient id", "hospital id", "claim id", "policy no", "policy id", "insurance id", "mrn", "uhid",
)
_SCHEMA_ID_PATTERN = "|".join(r"[ \t_./-]+".join(map(re.escape, label.split()))
                              for label in _SCHEMA_ID_LABELS)
_HIDDEN_LABELLED_ID = re.compile(
    _EDGE + rf"(?P<label>{_DOTTED_ID_LABEL}\.?|{_SCHEMA_ID_PATTERN})"
    r"[ \t_./:=#^-]+(?P<value>[^\W_][\w./-]{2,95})(?![\w./-])", _RX,
)
_BASE64_PAYLOAD = re.compile(r"[A-Za-z0-9+/_-]+={0,2}")
_MAX_METADATA_PAYLOAD = 64 * 1024
_DATE = re.compile(r"\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}(?!\d)")
_TIMESTAMP_DATE = re.compile(
    r"(?m)^[ \t]*\[?(?P<date>\d{4}[/.-]\d{1,2}[/.-]\d{1,2}|\d{1,2}[/.-]\d{1,2}[/.-](?:\d{4}|\d{2}))"
    r"(?=,?[ \t]+\d{1,2}:\d{2}\b)"
)
_DATE_LABEL = re.compile(_EDGE + r"(?P<label>dob|born on|birth date|birthdate|date of birth|जन्मतिथि|जन्म तिथि|admitted(?: on)?|discharged(?: on)?|visit date|भर्ती|छुट्टी)[ \t]*[:=]?[ \t]+(?=\d)", _RX)
_ADDRESS = re.compile(
    _EDGE + r"(?:h\.?[ \t]*no\.?|house (?:no\.?|number)|mohalla|village|gram|tehsil|distt?\.?|district|पता|ग्राम|गाँव|गांव|मोहल्ला|तहसील|जिला|ज़िला)"
    r"[ \t]*[:=]?[ \t]+[^\n,;|]{1,100}", _RX,
)
_AGE_NUMBER = re.compile(
    r"-?\d{1,3}(?=[ \t]*(?:$|(?:years?|yrs?\.?|y|वर्ष|साल)(?![^\W_])"
    r"|/[ \t]*(?:f(?:emale)?|m(?:ale)?|महिला|पुरुष)(?![^\W_])))",
    _RX,
)
_CLINICAL = re.compile(
    _EDGE + r"(?:"
    r"(?:BP|बीपी|blood pressure)[ \t]*[:=]?[ \t]*\d{2,3}\s*/\s*\d{2,3}|"
    r"\d+(?:\.\d+)?[ \t]*(?:mg/dL|mmol/L|g/dL|mg/L|mEq/L|mmHg|cells/(?:µL|uL)|"
    r"ng/mL|pg/mL|U/L|IU/L|µg|mcg|mg|mL|kg|bpm|°[CF]|%)|"
    r"[01½][ \t]*-[ \t]*[01½][ \t]*-[ \t]*[01½]|"
    r"(?:(?:Dolo|paracetamol|ramipril)[ \t]+)?\d{2,4}[ \t]+(?:BD|BID|OD|TDS|TID|QID|HS|SOS|PRN)(?:[ \t]+x[ \t]+\d+[ \t]+days?)?|"
    r"(?:ramipril|paracetamol|Dolo)[ \t]+\d+(?:\.\d+)?[ \t]*(?:mg|mcg)|"
    r"(?:Parkinson|Addison|Alzheimer|Crohn|Hodgkin)(?:['’]s)?[ \t]+(?:disease|syndrome|lymphoma)"
    r")" + _END, _RX,
)


def _label(value: str) -> str:
    if not value.isascii():
        value = _ID_FORMAT_CONTROLS.sub("", value.translate(_ID_COMPATIBILITY))
    if "." in value:
        value = _DOTTED_ID.sub(lambda match: re.sub(r"[. \t]", "", match["abbr"]), value)
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    return re.sub(r"[^a-z0-9\u0900-\u097f]+", " ", matching_text(value)).strip()


def _kind(label: str) -> str:
    if date_order_hint(label) is not None:
        label = label.rsplit(" ", 3)[0]
    kind = _LABELS.get(label)
    if kind:
        return kind
    if re.fullmatch(r"(?:phone|mobile|contact)(?: number| no)? ?\d|(?:alternate|primary|secondary) (?:phone|mobile|contact)", label):
        return "PHONE"
    if re.fullmatch(r"(?:address line|addr(?:ess)?) ?\d", label):
        return "ADDRESS"
    if re.fullmatch(r"(?:a[ad]+h?aar|abha|pan|uhid|mrn)(?: no| number| id)?", label):
        return _LABELS.get(label.split()[0], "AADHAAR")
    return ""


def _span_name(text: str, start: int, end: int) -> tuple[int, int] | None:
    while start < end and text[start] in " \t:-,;":
        start += 1
    if _CLINICAL_START.match(text, start, end):
        return None
    match = _NAME_PATTERN.match(text, start, end)
    if not match:
        return None
    last = start
    for token in re.finditer(_WORD, match[0]):
        token_start = start + token.start()
        if matching_text(token[0]).strip(".") in _NAME_STOP or _CLINICAL_START.match(text, token_start, end) or (
            token.end() == len(match[0]) and _RELATION_SUFFIX.match(text, match.end())
        ):
            break
        last = start + token.end()
    while last > start and text[last - 1] in ".'’-":
        last -= 1
    return (start, last) if last > start else None


def _relation(value: str) -> str:
    marker = re.sub(r"[\s./]", "", matching_text(value))
    if marker in {"so", "do", "sonof", "daughterof", "पुत्र", "पुत्री", "father", "पिता"}:
        return "father"
    if marker in {"mother", "माता"}:
        return "mother"
    if marker in {"wo", "wifeof", "husbandof", "पत्नी", "spouse", "पति"}:
        return "spouse"
    return "relative"


def _trim(text: str, start: int, end: int) -> tuple[int, int]:
    while start < end and text[start].isspace():
        start += 1
    while end > start and (text[end - 1].isspace() or text[end - 1] in ",;|।"):
        end -= 1
    return start, end


def _identifier_scan_view(text: str):
    """Fold one-to-one compatibility characters and map omitted controls."""
    if text.isascii():
        return text, ()
    folded = text.translate(_ID_COMPATIBILITY)
    omitted = array("I", (m.start() - i for i, m in enumerate(_ID_FORMAT_CONTROLS.finditer(folded))))
    return (_ID_FORMAT_CONTROLS.sub("", folded) if omitted else folded), omitted


def _scan_text(
    surface: TextSurface,
    role: str,
    known_names: tuple[tuple[str, str], ...],
) -> tuple[list[tuple[Target, str]], list[Target]]:
    text = surface.text
    sensitive: list[tuple[Target, str]] = []
    protected: list[Target] = []

    def protect(kind: str, start: int, end: int) -> None:
        protected.append(Target(kind, surface.path, surface.channel, start, end))

    def add(kind: str, start: int, end: int, role: str = "patient") -> None:
        start, end = _trim(text, start, end)
        if start != end and matching_text(text[start:end]) not in _UNKNOWN:
            sensitive.append((Target(kind, surface.path, surface.channel, start, end), role))

    def protect_doctor(start: int, end: int) -> None:
        specialty = _DOCTOR_SPECIALTY.match(text, end)
        protect("DOCTOR", start, specialty.end() if specialty else end)

    for match in _CLINICAL.finditer(text):
        protect("CLINICAL", *match.span())
    for match in _DOCTOR.finditer(text):
        bounds = _span_name(text, *match.span("name"))
        if bounds:
            protect_doctor(match.start(), bounds[1])
    labels = list(_LABEL_IN_TEXT.finditer(text))
    for index, match in enumerate(labels):
        kind = _kind(_label(match[1]))
        start = match.end()
        label_end = labels[index + 1].start() if index + 1 < len(labels) else len(text)
        end = label_end
        delimiters = r"[\r\n;|]" if kind == "ADDRESS" else r"[\r\n,;|]"
        stop = re.search(delimiters, text[start:end])
        if stop:
            end = start + stop.start()
        relation = _RELATION_IN_TEXT.search(text, start, end)
        if relation and kind in {"DOCTOR", "CLINICAL"}:
            end = relation.start()
        if kind in {"DOCTOR", "CLINICAL"}:
            bounds = _span_name(text, start, end) if kind == "DOCTOR" else _trim(text, start, end)
            if bounds and bounds[0] < bounds[1]:
                if kind == "DOCTOR":
                    protect_doctor(*bounds)
                else:
                    protect(kind, *bounds)
        elif kind in _RELATIVES or kind in _NAME_PARTS or kind == "PATIENT_NAME":
            bounds = _span_name(text, start, end)
            if bounds:
                if kind == "PATIENT_NAME" and end < label_end and text[end] == ",":
                    tail = re.match(r"[ \t]*[^\r\n,;|]+", text[end + 1:label_end])
                    if tail and not _RELATION_IN_TEXT.search(tail[0]):
                        tail_end = end + 1 + tail.end()
                        second = _span_name(text, end + 1, tail_end)
                        if second and not text[second[1]:tail_end].strip(" .\t"):
                            bounds = (bounds[0], second[1])
                if kind in _RELATIVES:
                    add("RELATIVE_NAME", *bounds, _RELATIVES[kind])
                else:
                    add("RELATIVE_NAME" if role == "relative" else "PATIENT_NAME", *bounds, role)
        elif kind in DATE_KINDS:
            date_match = _DATE.match(text, start, end)
            if date_match:
                add(kind, *date_match.span(), role)
        elif kind == "AGE":
            age = _AGE_NUMBER.match(text, start, end)
            add(kind, *(age.span() if age else (start, end)), role)
        elif kind in _VALUE_PATTERNS:
            value = _VALUE_PATTERNS[kind].match(text, start, end)
            if value and (kind != "PHONE" or phone_number(value[0])):
                add(kind, *value.span(), role)
            else:
                add(kind, start, end, role)
        elif kind not in {"HOSPITAL", "RELATION"}:
            add(kind, start, end, role)

    for match in _RELATION_IN_TEXT.finditer(text):
        marker = re.sub(r"[\s./]", "", matching_text(match["marker"]))
        if marker == "co" and re.search(r"k\s*/\s*$", text[max(0, match.start() - 6):match.start()], _RX):
            continue
        complaint = _CLINICAL_START.match(text, match.end())
        if complaint:
            protect("CLINICAL", *complaint.span())
            continue
        bounds = _span_name(text, match.end(), len(text))
        if bounds:
            add("RELATIVE_NAME", *bounds, _relation(match["marker"]))

    for kind, name_role, patterns in (
        ("RELATIVE_NAME", "relative", (_CALLER, _ATTENDANT, _CHAT_SENDER)),
        ("PATIENT_NAME", role, (
            _FRAGMENT, _HINGLISH_NAME, _TITLED_NAME, _UNPUNCTUATED_NAME,
            _ENCOUNTER_NAME, _PATIENT_IN_NOTE, _PROGRESS_SUBJECT, _SAMPLE_SUBJECT,
        )),
    ):
        for pattern in patterns:
            for match in pattern.finditer(text):
                bounds = _span_name(text, *match.span("name"))
                if bounds:
                    add(kind, *bounds, name_role)

    if surface.label == "FHIR narrative":
        for match in _NARRATIVE_SUBJECT.finditer(text):
            bounds = _span_name(text, *match.span("name"))
            if bounds:
                add("REFERENCE_NAME", *bounds)
                add("AGE", *match.span("age"))
    for timestamp in _TIMESTAMP_DATE.finditer(text):
        add("TIMESTAMP_DATE", *timestamp.span("date"), role)
    for match in _DATE_LABEL.finditer(text):
        date_match = _DATE.match(text, match.end())
        if date_match:
            kind = _kind(_label(match["label"])) or "DOB"
            add(kind, *date_match.span(), role)
    identifier_text, omitted = _identifier_scan_view(text)

    def add_labelled_id(match: re.Match) -> None:
        start, end = match.span("value")
        # An omission at the end boundary belongs to the following text.
        add(_kind(_label(match["label"])), start + bisect_right(omitted, start),
            end + bisect_right(omitted, end - 1), role)

    for match in _LABELLED_ID.finditer(identifier_text):
        if any(char.isdecimal() for char in match["value"]):
            add_labelled_id(match)
    if surface.channel in {"filename", "header", "key", "metadata"}:
        for match in _HIDDEN_LABELLED_ID.finditer(identifier_text):
            value = match["value"]
            if sum(char.isalnum() for char in value) >= 4 and any(char.isdecimal() for char in value):
                add_labelled_id(match)
    for pattern, kind in (
        (_EMAIL, "EMAIL"), (_ABHA, "ABHA_NUMBER"), (_AADHAAR, "AADHAAR"),
        (_PAN, "PAN"), (_PHONE, "PHONE"), (_BARE_ID, "MRN"),
    ):
        for match in pattern.finditer(text):
            if kind != "PHONE" or phone_number(match[0]):
                add(kind, *match.span(), role)
    for line in re.finditer(r"(?m)^[^\r\n]+", text):
        address_parts = list(_ADDRESS.finditer(line[0]))
        for part in address_parts:
            add("ADDRESS", line.start() + part.start(), line.start() + part.end(), role)
        if (len(address_parts) >= 2 and line[0].count(",") >= 2
                and not line[0][:address_parts[0].start()].strip()):
            add("ADDRESS", *line.span(), role)
    for kind, name in known_names:
        words = re.findall(_WORD, name)
        if len(words) < 2:
            continue
        pattern = _EDGE + r"[\s_-]+".join(re.escape(word) for word in words) + _END
        for match in re.finditer(pattern, text, _RX):
            add(kind, *match.span(), role)
    return sensitive, protected


def _sensitive_metadata_payload(surface: TextSurface, names: tuple[tuple[str, str], ...]) -> bool:
    """Inspect one level of standalone Base64 in metadata without releasing decoded text."""
    compact = "".join(surface.text.split())
    if len(compact) < 24 or not _BASE64_PAYLOAD.fullmatch(compact):
        return False
    if len(compact) > _MAX_METADATA_PAYLOAD:
        return True
    try:
        decoded = b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True)
        text = decoded.decode("utf-8")
    except (InvalidBase64, UnicodeDecodeError):
        return False
    decoded_surface = TextSurface(text, "metadata", surface.path)
    hits, clinical = _scan_text(decoded_surface, "patient", names)
    return bool(_select_spans(hits, clinical))


_PRIORITY = {
    kind: index for index, kind in enumerate((
        "RELATIVE_NAME", "PATIENT_NAME", "ADDRESS", "ABHA_NUMBER", "AADHAAR",
        "UHID", "INSURANCE_ID", "MRN", "PHONE",
    ))
}


def _select_spans(
    sensitive: list[tuple[Target, str]], protected: list[Target],
) -> list[tuple[Target, str]]:
    intervals: list[tuple[int, int]] = []
    for target in sorted(protected, key=lambda target: (target.start, target.end)):
        if intervals and target.start <= intervals[-1][1]:
            start, end = intervals[-1]
            intervals[-1] = start, max(end, target.end)
        else:
            intervals.append((target.start, target.end))
    ends = [end for _, end in intervals]
    selected = []
    last_end = 0
    for target, role in sorted(sensitive, key=lambda item: (
        item[0].start, -item[0].end, _PRIORITY.get(item[0].kind, 100), item[0].kind, item[1],
    )):
        if target.start < last_end:
            continue
        index = bisect_right(ends, target.start)
        if index < len(intervals) and intervals[index][0] < target.end:
            continue
        selected.append((target, role))
        last_end = target.end
    return selected


def detect_record(
    record: ParsedRecordView,
    *,
    surfaces: Iterable[TextSurface] = (),
    hospital: str | None = None,
    day_first: bool | None = None,
) -> DetectionResult:
    """Collect original targets and in-memory evidence for one parsed record.

    Pass a canonical hospital scope and the source's date order when known.
    Hidden text surfaces can contribute targets without supplying linkage clues.
    """
    identity: list[IdentityEvidence] = []
    sensitive: list[Target] = []
    protected: list[Target] = []
    name_parts: dict[tuple[Path, str], dict[str, list[str]]] = {}
    hospital_labels: set[str] = set()
    hidden: list[TextSurface] = []

    def collect(kind: str, value: str, role: str, path: Path) -> None:
        if kind in _NAME_PARTS:
            parts = name_parts.setdefault((path, role), {})
            parts.setdefault(kind, []).append(value)
        elif kind == "RELATIVE_NAME" and role != "clinician":
            identity.append(IdentityEvidence(kind, value, role if role != "patient" else "relative"))
        elif kind in (_IDENTITY | ENCOUNTER_DATES) and role == "patient":
            identity.append(IdentityEvidence(kind, value))

    def scan(
        surface: TextSurface,
        role: str = "patient",
        names: tuple[tuple[str, str], ...] = (),
    ) -> None:
        hits, clinical = _scan_text(surface, role, names)
        protected.extend(clinical)
        for target, hit_role in _select_spans(hits, clinical):
            sensitive.append(target)
            if surface.channel == "content":
                collect(target.kind, surface.text[target.start:target.end], hit_role, surface.path)
        if surface.channel == "content":
            for match in _HOSPITAL_IN_TEXT.finditer(surface.text):
                hospital_labels.add(match["hospital"].strip())

    pending = [((), record.content, "", "content", "patient", "", ())]
    while pending:
        path, value, label, channel, role, relation, name_path = pending.pop()
        kind = _kind(label)
        if label in _METADATA:
            channel = "metadata"
        if isinstance(value, Mapping):
            resource_type = value.get("resourceType")
            if resource_type in ("Practitioner", "PractitionerRole", "Organization"):
                role = "clinician"
            elif resource_type == "Patient":
                role = "patient"
            elif resource_type == "RelatedPerson":
                role = "relative"
            elif isinstance(resource_type, str):
                role = "nonpatient"
            elif label == "contact":
                role = "relative"
            relation = next((
                _relation(item) for key, item in value.items()
                if isinstance(key, str) and _kind(_label(key)) == "RELATION" and isinstance(item, str)
            ), relation)
            system = value.get("system")
            is_phone = isinstance(system, str) and system.casefold() in {"phone", "sms", "fax"}
            reference = value.get("reference")
            patient_reference = isinstance(reference, str) and (
                bool(re.search(r"(?:^|/)(?:Patient|RelatedPerson)/", reference))
                or (record.format == "fhir" and label in {"subject", "patient", "beneficiary"}
                    and reference.startswith("urn:"))
            )
            extension_url = value.get("url")
            relative_extension = ""
            if record.format == "fhir" and label == "extension" and isinstance(extension_url, str):
                field = _label(extension_url.rsplit("/", 1)[-1])
                if _kind(field) in _RELATIVES:
                    relative_extension = field
            encoded_attachment = label in _ATTACHMENTS or resource_type == "Binary" or (
                isinstance(value.get("contentType"), str) and "data" in value
            )
            for key, item in reversed(list(value.items())):
                if not isinstance(key, str):
                    continue
                child_label = _label(key)
                if record.format == "fhir" and resource_type == "Encounter" and key == "period":
                    child_label = "encounter period"
                if label == "encounter period" and key in {"start", "end"}:
                    child_label = "admission date" if key == "start" else "discharge date"
                if key == "value" and is_phone:
                    child_label = "phone"
                elif key == "value" and label == "identifier" and role == "patient":
                    child_label = next((
                        name for name in ("aadhaar", "abha", "pan", "mrn", "uhid", "insurance")
                        if isinstance(system, str) and re.search(rf"\b{name}\b", system, _RX)
                    ), "uhid")
                if key in {"text", "local", "latin", "native", "english", "hindi"} and label == "name":
                    child_label = "name"
                if key == "display" and patient_reference:
                    child_label = "patient reference display"
                if key == "valueString" and relative_extension:
                    child_label = relative_extension
                if key in {"data", "base64", "payload"} and encoded_attachment:
                    child_label = "encoded attachment data"
                if key == "source" and label == "meta" and record.format == "fhir":
                    child_label = "source path"
                if key == "id" and resource_type == "Patient":
                    child_label = "uhid"
                if key in {"text", "line", "city", "district", "state"} and label == "address":
                    child_label = "address"
                child_name_path = path if _kind(child_label) in _NAME_PARTS else name_path
                pending.append((path + (key,), item, child_label, channel, role, relation, child_name_path))
            continue
        if isinstance(value, (list, tuple)):
            for index in reversed(range(len(value))):
                pending.append((path + (index,), value[index], label, channel, role, relation, name_path))
            continue
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            continue
        text = str(value).strip()
        if not text or matching_text(text) in _UNKNOWN:
            continue
        if label == "encoded attachment data" and isinstance(value, str):
            sensitive.append(Target("ATTACHMENT_DATA", path, "metadata"))
            continue
        if label in _SOURCE_PATHS and isinstance(value, str):
            sensitive.append(Target("SOURCE_PATH", path, "metadata"))
            continue
        if channel != "content":
            if isinstance(value, str):
                hidden.append(TextSurface(value, channel, path, label))
            continue
        if role in {"clinician", "nonpatient"} and kind in _NAME_PARTS | {"PATIENT_NAME"}:
            if role == "clinician":
                protected.append(Target("DOCTOR", path))
        elif kind in {"DOCTOR", "CLINICAL"}:
            protected.append(Target(kind, path))
        elif kind == "HOSPITAL":
            hospital_labels.add(text)
        elif kind and kind != "RELATION":
            target_kind = kind
            evidence_role = role
            if kind in _RELATIVES:
                target_kind = "RELATIVE_NAME"
                evidence_role = _RELATIVES[kind] if kind != "RELATIVE_NAME" else relation or "relative"
            elif role == "relative" and kind == "PATIENT_NAME":
                target_kind = "RELATIVE_NAME"
            if kind == "AGE" and isinstance(value, str):
                age = _AGE_NUMBER.match(value, len(value) - len(value.lstrip()))
                if age and age[0] != text:
                    sensitive.append(Target(kind, path, start=age.start(), end=age.end()))
                    continue
            if kind in DATE_KINDS and isinstance(value, str):
                prefix = _DATE.match(value)
                if prefix and value[prefix.end():prefix.end() + 1] in {"T", "t"}:
                    sensitive.append(Target(kind, path, start=prefix.start(), end=prefix.end()))
                    if kind in ENCOUNTER_DATES:
                        collect(kind, prefix[0], role, path)
                    continue
            sensitive.append(Target("PATIENT_NAME" if kind in _NAME_PARTS else target_kind, path))
            if target_kind in ENCOUNTER_DATES | {"DOB"} and path and isinstance(path[-1], str):
                day_order = date_order_hint(path[-1])
                if day_order is not None:
                    text = birth_date(text, day_order)
            if text:
                collect(target_kind, text, evidence_role, name_path)
        elif isinstance(value, str):
            surface_label = None
            if record.format == "fhir" and path[-2:] == ("text", "div"):
                surface_label = "FHIR narrative"
            scan(TextSurface(value, path=path, label=surface_label), role)

    for (_, role), parts in name_parts.items():
        words = [word for kind in ("FIRST_NAME", "MIDDLE_NAME", "LAST_NAME") for word in parts.get(kind, ())]
        collect("RELATIVE_NAME" if role == "relative" else "PATIENT_NAME", " ".join(words), role, ())
    names = tuple(dict.fromkeys(
        (item.kind, item.value) for item in identity if item.kind in {"PATIENT_NAME", "RELATIVE_NAME"}
    ))
    for surface in (*hidden, *surfaces):
        if surface.channel == "metadata" and _sensitive_metadata_payload(surface, names):
            sensitive.append(Target("ATTACHMENT_DATA", surface.path, "metadata"))
        elif surface.channel != "content" and surface.label and _kind(_label(surface.label)) in (
            _IDENTITY | _NAME_PARTS | set(_RELATIVES) | {"ADDRESS", "INSURANCE_ID", "EMAIL"}
        ):
            kind = _kind(_label(surface.label))
            if kind in _NAME_PARTS:
                kind = "PATIENT_NAME"
            elif kind in _RELATIVES:
                kind = "RELATIVE_NAME"
            sensitive.append(Target(kind, surface.path, surface.channel, 0, len(surface.text)))
        else:
            scan(surface, names=names if surface.channel != "content" else ())
    if not hospital and len(hospital_labels) == 1:
        hospital = next(iter(hospital_labels))
    return DetectionResult(
        record.record_key, tuple(dict.fromkeys(identity)), tuple(dict.fromkeys(sensitive)),
        tuple(dict.fromkeys(protected)), hospital, day_first,
    )
