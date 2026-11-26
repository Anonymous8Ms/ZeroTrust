"""Matching forms for identity evidence. No source value is modified."""

from __future__ import annotations

from datetime import date
import re
import unicodedata


_FORMAT_CONTROLS = re.compile(r"[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")


def matching_text(value: str) -> str:
    value = _FORMAT_CONTROLS.sub("", unicodedata.normalize("NFKC", value))
    return "".join(
        str(unicodedata.decimal(char)) if char.isdecimal() else char
        for char in value
    ).casefold()


def phone_number(value: str) -> str:
    value = matching_text(value)
    if not re.fullmatch(r"[+\d().\s–-]+", value):
        return ""
    digits = re.sub(r"\D", "", value)
    if len(digits) == 14 and digits.startswith("0091"):
        digits = digits[4:]
    elif len(digits) == 13 and digits.startswith("091"):
        digits = digits[3:]
    elif len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    return digits if len(digits) == 10 and digits[0] in "6789" else ""


def identifier(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", matching_text(value))


_DATE_FORMAT_SUFFIX = re.compile(r"\b(dd|mm)[ /.-]+(dd|mm)[ /.-]+yyyy\)?\s*$", re.IGNORECASE)


def date_order_hint(label: str) -> bool | None:
    match = _DATE_FORMAT_SUFFIX.search(label)
    if match and match[1].lower() != match[2].lower():
        return match[1].lower() == "dd"
    return None


def birth_date(
    value: str, day_first: bool | None = None, *, fallback_day_first: bool | None = None,
) -> str:
    parts = re.fullmatch(r"(\d{1,4})[-/.](\d{1,2})[-/.](\d{1,4})", matching_text(value.strip()))
    if not parts:
        return ""
    first, second, third = parts.groups()
    if len(first) == 4:
        year, month, day = int(first), int(second), int(third)
    elif len(third) == 4:
        year = int(third)
        a, b = int(first), int(second)
        if day_first is None:
            if a <= 12 and b <= 12 and a != b:
                if fallback_day_first is None:
                    return ""
                day_first = fallback_day_first
            else:
                day_first = a >= b
        day, month = (a, b) if day_first else (b, a)
    else:
        return ""
    try:
        return date(year, month, day).isoformat()
    except ValueError:
        return ""


_CONSONANTS = dict(zip(
    "कखगघङचछजझञटठडढणतथदधनपफबभमयरलवशषसहळ",
    "k kh g gh n ch chh j jh n t th d dh n t th d dh n p ph b bh m y r l v sh sh s h l".split(),
))
_VOWELS = dict(zip("अआइईउऊऋएऐओऔऑऍ", "a aa i i u u ri e ai o au o e".split()))
_VOWEL_SIGNS = dict(zip("ािीुूृेैोौॉॅ", "aa i ee u oo ri e ai o au o e".split()))
_NUKTA = {"क": "q", "ख": "kh", "ग": "g", "ज": "z", "ड": "r", "ढ": "r", "फ": "f"}


def _romanize(value: str) -> str:
    chars = unicodedata.normalize("NFD", value)
    pieces = []
    index = 0
    while index < len(chars):
        char = chars[index]
        index += 1
        if char in _CONSONANTS:
            sound = _CONSONANTS[char]
            if index < len(chars) and chars[index] == "़":
                sound = _NUKTA.get(char, sound)
                index += 1
            after_vowel = bool(pieces and pieces[-1] in {"a", "aa", "i", "ee", "u", "oo", "ri", "e", "ai", "o", "au"})
            pieces.append(sound)
            if index < len(chars) and chars[index] in _VOWEL_SIGNS:
                pieces.append(_VOWEL_SIGNS[chars[index]])
                index += 1
            elif index < len(chars) and chars[index] == "्":
                index += 1
            elif not (
                char == "य"
                and after_vowel
                and (index == len(chars) or (not chars[index].isalpha() and chars[index] not in "ंँ"))
            ):
                pieces.append("a")
        elif char in _VOWELS:
            pieces.append(_VOWELS[char])
        elif char in "ंँ":
            following = chars[index] if index < len(chars) else ""
            pieces.append("m" if following in {"प", "फ", "ब", "भ", "म"} else "n")
        elif not unicodedata.combining(char):
            pieces.append(char)
    return "".join(pieces)


_TITLES = {
    "mr", "mrs", "ms", "miss", "shri", "sri", "shree", "smt", "shrimati",
    "shrimaati", "shreematee", "ji", "jee", "sahab", "saahab", "saahaba",
    "sahib", "saheb", "didi", "deedee", "bhai", "bhaaee", "kumari", "kumaari",
    "pt", "km",
}
_FAMILIAR_SUFFIXES = {"amma", "ammaa", "babu", "baabu", "behenji", "behanji", "bahanji", "behenjee", "behanjee"}
_MOHAMMAD = {
    "md", "mohd", "mhd", "mohammad", "mohammed", "muhammad", "mohamad",
    "muhammed", "mohammada", "muhammada", "mohamada",
}
_TOKEN_SOUNDS = re.compile(r"chh|ch|sh|ph|[kgtdbj]h|[qwzx]")
_SIMILAR_SOUNDS = {"chh": "c", "ch": "c", "sh": "s", "ph": "f", "q": "k", "w": "v", "z": "j", "x": "ks"}


def _name_sound(token: str) -> str:
    if token in _MOHAMMAD:
        return "mhmd"
    sound = _TOKEN_SOUNDS.sub(
        lambda match: _SIMILAR_SOUNDS.get(match[0], match[0][0]), token
    )
    if len(sound) == 1:
        return sound
    consonants = sound[0] + re.sub(r"(.)\1+", r"\1", re.sub(r"[aeiou]", "", sound[1:]))
    # A final y can represent the same vowel as i or e in romanized names.
    if len(consonants) > 2 and sound.endswith("y"):
        return consonants[:-1]
    return consonants


def name_form(value: str) -> tuple[str, ...]:
    tokens = [token for token in re.findall(r"[a-z]+", _romanize(matching_text(value)))
              if token not in _TITLES]
    if len(tokens) > 1 and tokens[-1] in _FAMILIAR_SUFFIXES:
        tokens.pop()
    names = tuple(sorted(_name_sound(token) for token in tokens))
    return names if 0 < len(names) <= 6 and any(len(token) > 1 for token in names) else ()


def name_similarity(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    """3 for equal full names, 2 for compatible initials, 1 for fragments, 0 for conflict."""
    if not left or not right:
        return 0
    common = {part for part in set(left) & set(right) if len(part) > 1}
    if not common:
        return 0
    if left == right:
        if sum(len(part) > 1 for part in left) > 1:
            return 3
        return 2 if len(left) > 1 else 1
    if len(left) == len(right):
        remainder = list(right)
        for token in left:
            if token in remainder:
                remainder.remove(token)
        unmatched = list(left)
        for token in right:
            if token in unmatched:
                unmatched.remove(token)
        if sorted(token[0] for token in unmatched) == sorted(token[0] for token in remainder):
            for initial in {token[0] for token in unmatched}:
                full_count = sum(
                    len(token) > 1 and token[0] == initial for token in unmatched + remainder
                )
                if full_count > sum(token[0] == initial for token in unmatched):
                    return 0
            return 2
    shorter, longer = sorted((left, right), key=len)
    if len(shorter) < len(longer) and all(
        longer.count(token) >= shorter.count(token) for token in set(shorter)
    ):
        return 2 if len(common) >= 2 else 1

    # Handle compound joined names (e.g. "Omprakash Sharma" vs "Om Prakash Sharma")
    # and missing/extra single-letter middle initials (e.g. "M. R. Kapoor" vs "Meera Kapoor").
    unmatched = list(left)
    remainder = list(right)
    for token in list(unmatched):
        if token in remainder:
            unmatched.remove(token)
            remainder.remove(token)
    if len(unmatched) == 1 and len(remainder) == 2 and unmatched[0] in (
        remainder[0] + remainder[1], remainder[1] + remainder[0],
    ):
        return 2
    if len(remainder) == 1 and len(unmatched) == 2 and remainder[0] in (
        unmatched[0] + unmatched[1], unmatched[1] + unmatched[0],
    ):
        return 2

    def _initials_match(a_tokens: list[str], b_tokens: list[str]) -> bool:
        a_full = [t for t in a_tokens if len(t) > 1]
        b_full = [t for t in b_tokens if len(t) > 1]
        if (a_full and b_full) or (len(a_tokens) > len(a_full) and len(b_tokens) > len(b_full)):
            return False
        fulls, inits = (a_full, list(b_tokens)) if a_full else (b_full, list(a_tokens))
        if not fulls or not all(len(t) == 1 for t in inits):
            return False
        for token in fulls:
            if token[0] not in inits:
                return False
            inits.remove(token[0])
        return True

    if _initials_match(unmatched, remainder):
        return 1
    return 0
