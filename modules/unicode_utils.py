import unicodedata
from collections import Counter

ZERO_WIDTH_CHARS = [
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\ufeff",  # zero width no-break space / BOM
]

SCRIPT_KEYWORDS = {
    "LATIN": "latin",
    "CYRILLIC": "cyrillic",
    "GREEK": "greek",
    "ARMENIAN": "armenian",
    "HEBREW": "hebrew",
    "ARABIC": "arabic",
    "HIRAGANA": "cjk",
    "KATAKANA": "cjk",
    "CJK": "cjk",
    "HANGUL": "hangul",
    "DEVANAGARI": "devanagari",
    "THAI": "thai",
    "GEORGIAN": "georgian",
}


def count_zero_width_chars(text: str) -> int:
    if not text:
        return 0
    return sum(text.count(ch) for ch in ZERO_WIDTH_CHARS)


def has_zero_width_chars(text: str) -> bool:
    return count_zero_width_chars(text) > 0


def classify_script(char: str) -> str:
    if not char or char.isspace():
        return "whitespace"
    try:
        name = unicodedata.name(char)
    except ValueError:
        return "unknown"
    for keyword, script in SCRIPT_KEYWORDS.items():
        if keyword in name:
            return script
    if "LATIN" in name:
        return "latin"
    if "DIGIT" in name:
        return "digit"
    if "NUMBER" in name:
        return "digit"
    if "SYMBOL" in name or "PUNCTUATION" in name:
        return "symbol"
    return "other"


def analyze_script_mix(text: str) -> dict:
    counts = Counter()
    if text:
        for ch in text:
            script = classify_script(ch)
            counts[script] += 1
    # ignore whitespace counts when computing diversity
    filtered_counts = {k: v for k, v in counts.items() if v > 0 and k not in {"whitespace", "symbol"}}
    unique_scripts = len([k for k in filtered_counts if k not in {"digit"}])

    latin = filtered_counts.get("latin", 0) > 0
    cyrillic = filtered_counts.get("cyrillic", 0) > 0
    greek = filtered_counts.get("greek", 0) > 0

    return {
        "script_counts": filtered_counts,
        "script_diversity": unique_scripts,
        "has_mixed_scripts": 1 if unique_scripts > 1 else 0,
        "mixed_latin_cyrillic": 1 if latin and cyrillic else 0,
        "mixed_latin_greek": 1 if latin and greek else 0,
    }


