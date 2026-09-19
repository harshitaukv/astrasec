"""Text normalisation, de-obfuscation and numeric feature extraction.

This module is the shared "sensory layer" of AstraSec. Every engine looks at a prompt through the same
lens: first normalise (Unicode tricks, invisible characters, homoglyphs), then peel encodings (base64, hex,
rot13, reversed text, leetspeak, typoglycemia), then compute behavioural features.

All functions are pure and module-level so scikit-learn pipelines that reference them can be pickled.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
import unicodedata
from urllib.parse import unquote
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

# --------------------------------------------------------------------------------------------------
# Lexicons
# --------------------------------------------------------------------------------------------------
OVERRIDE_RE = re.compile(
    r"\b(ignore|disregard|forget|override|overrule|bypass|obey|new instructions?|from now on|"
    r"previous instructions?|prior instructions?|above instructions?|instead)\b", re.I)
SENSITIVE_RE = re.compile(
    r"\b(system prompt|system message|hidden (?:prompt|rules|instructions)|password|api[ _-]?key|secret|"
    r"credentials?|confidential|admin(?:istrator)?|internal|initial instructions?|access token|private key)\b", re.I)
PERSONA_RE = re.compile(
    r"\b(dan|do anything now|developer mode|unrestricted|unfiltered|uncensored|no restrictions|roleplay|role-play|"
    r"pretend|stay in character|jailbreak(?:ed)?|amoral|evil|no ethical|without (?:any )?(?:rules|limits|filters))\b", re.I)
EXTRACTION_RE = re.compile(
    r"\b(logits?|logprobs?|model weights|weights|training (?:data|set|corpus)|embedding|parameters?|architecture|"
    r"verbatim|probabilit(?:y|ies)|gradients?|fine-?tun(?:e|ing)|hyper-?parameters?|distill)\b", re.I)
IMPERATIVE_START = {
    "ignore", "disregard", "forget", "reveal", "print", "output", "repeat", "show", "tell", "give", "list", "dump",
    "pretend", "act", "enable", "stop", "obey", "send", "execute", "run", "decode", "answer", "respond", "write", "simulate",
}
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
MARKER_RE = re.compile(r"(###|<\|.*?\|>|\[/?(?:INST|SYSTEM)\]|</?(?:system|assistant|user|user_input)>|^\s*(?:system|assistant)\s*:)",
                       re.I | re.M)

# --------------------------------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------------------------------
_INVISIBLE = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
     0x2066, 0x2067, 0x2068, 0x2069] + list(range(0xE0000, 0xE0080)), None)
_INVISIBLE_SET = set(_INVISIBLE)

# Cyrillic / Greek look-alikes commonly used to dodge keyword filters
_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d",
    "һ": "h", "ԛ": "q", "ԝ": "w", "ѵ": "v", "ո": "n", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ѕ": "S", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o",
    "ν": "v", "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})
_SPACED_RE = re.compile(r"(?<![A-Za-z])(?:[A-Za-z][ .\-_*]){2,}[A-Za-z](?![A-Za-z])")

_KEYWORD_VOCAB = [
    "ignore", "previous", "instructions", "system", "prompt", "reveal", "bypass", "override", "disregard", "password",
    "restrictions", "unrestricted", "guidelines", "forget", "confidential", "secret", "hidden", "developer", "administrator",
    "jailbreak", "credentials", "verbatim", "training",
]
_TYPO_INDEX = {(w[0], w[-1], "".join(sorted(w[1:-1]))): w for w in _KEYWORD_VOCAB}
_KW_COUNT_RE = re.compile(r"\b(" + "|".join(_KEYWORD_VOCAB + ["instruction", "rules", "unfiltered", "prompt"]) + r")\b", re.I)


def keyword_count(text: str) -> int:
    return len(_KW_COUNT_RE.findall(text))


def count_invisible(text: str) -> int:
    return sum(1 for ch in text if ord(ch) in _INVISIBLE_SET)


def normalize_text(text: str) -> tuple[str, list[str]]:
    """Unicode NFKC, strip invisible/bidi characters, map homoglyphs, collapse spaced-out letters."""
    flags: list[str] = []
    if not text:
        return "", flags
    t = unicodedata.normalize("NFKC", text)
    if t != text and any(ord(c) > 0xFF00 for c in text):
        flags.append("fullwidth")
    if count_invisible(t):
        flags.append("invisible_chars")
        t = t.translate(_INVISIBLE)
    mapped = t.translate(_HOMOGLYPHS)
    if mapped != t:
        flags.append("homoglyphs")
        t = mapped

    runs = list(_SPACED_RE.finditer(t))
    # short runs ("a l l") are only collapsed when the text also holds a long spaced-out run
    min_letters = 3 if any(len(re.sub(r"[ .\-_*]", "", m.group(0))) >= 5 for m in runs) else 5

    def _collapse(m: re.Match) -> str:
        letters = re.sub(r"[ .\-_*]", "", m.group(0))
        return letters if len(letters) >= min_letters else m.group(0)

    collapsed = _SPACED_RE.sub(_collapse, t)
    if collapsed != t:
        flags.append("spaced_letters")
        t = collapsed
    return t, flags


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\t")
    return ok / len(s)


_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){10,}(?![0-9A-Fa-f])")


def _try_b64(token: str) -> str | None:
    pad = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(pad, validate=True)
        s = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    if len(s) >= 6 and _printable_ratio(s) > 0.95 and sum(c.isalpha() or c == " " for c in s) / len(s) > 0.6:
        return s
    return None


def _try_hex(token: str) -> str | None:
    try:
        s = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if len(s) >= 6 and _printable_ratio(s) > 0.95:
        return s
    return None


def _unscramble(text: str) -> tuple[str, bool]:
    changed = False

    def fix(m: re.Match) -> str:
        nonlocal changed
        w = m.group(0)
        lw = w.lower()
        if len(lw) >= 5:
            key = (lw[0], lw[-1], "".join(sorted(lw[1:-1])))
            target = _TYPO_INDEX.get(key)
            if target and target != lw:
                changed = True
                return target
        return w

    return re.sub(r"[A-Za-z]{5,}", fix, text), changed


def _leet_decode(text: str) -> str:
    out = []
    for tok in text.split(" "):
        if len(tok) >= 3 and re.search(r"[A-Za-z]", tok) and re.search(r"[013457@$|]", tok):
            out.append(tok.translate(_LEET))
        else:
            out.append(tok)
    return " ".join(out)


@dataclass
class Deobfuscation:
    original: str
    normalized: str
    text: str                       # normalised + every decoded view: what classifiers & signatures read
    transforms: list[str] = field(default_factory=list)
    decoded_segments: list[str] = field(default_factory=list)


def deobfuscate(text: str) -> Deobfuscation:
    """Peel obfuscation layers and return a combined view of the prompt."""
    if not text:
        return Deobfuscation("", "", "", [], [])
    norm, transforms = normalize_text(text)
    views: list[str] = []

    # encodings ------------------------------------------------------------------------------------
    for m in _B64_RE.finditer(norm):
        dec = _try_b64(m.group(0))
        if dec:
            views.append(dec)
            transforms.append("base64")
    for m in _HEX_RE.finditer(norm):
        dec = _try_hex(m.group(0))
        if dec:
            views.append(dec)
            transforms.append("hex")

    if len(re.findall(r"%[0-9A-Fa-f]{2}", norm)) >= 3:
        dec = unquote(norm)
        if dec != norm:
            views.append(dec)
            transforms.append("urlencoded")
    if len(re.findall(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", norm)) >= 2:
        dec = re.sub(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1) or m.group(2), 16)), norm)
        if dec != norm:
            views.append(dec)
            transforms.append("unicode_escape")

    base_kw = keyword_count(norm)

    # rot13 / reversed: only adopt when they surface more attack vocabulary than the original --------
    rot = codecs.decode(norm, "rot_13")
    if keyword_count(rot) > base_kw:
        views.append(rot)
        transforms.append("rot13")
    rev = norm[::-1]
    if keyword_count(rev) > base_kw:
        views.append(rev)
        transforms.append("reversed")

    # leetspeak & typoglycemia ----------------------------------------------------------------------
    leet = _leet_decode(norm)
    if leet != norm and keyword_count(leet) > base_kw:
        views.append(leet)
        transforms.append("leetspeak")
    unscr, changed = _unscramble(norm)
    if changed and keyword_count(unscr) > base_kw:
        views.append(unscr)
        transforms.append("typoglycemia")

    combined = norm
    for v in views:
        combined += "\n[decoded] " + v
    return Deobfuscation(text, norm, combined, sorted(set(transforms)), views)


# --------------------------------------------------------------------------------------------------
# Numeric features
# --------------------------------------------------------------------------------------------------
FEATURE_NAMES = [
    "log_chars", "log_words", "avg_word_len", "upper_ratio", "digit_ratio", "punct_ratio", "nonascii_ratio",
    "invisible_chars", "entropy", "override_kw", "sensitive_kw", "persona_kw", "extraction_kw", "imperative_start",
    "question_marks", "newlines", "max_char_run", "unique_word_ratio", "url_count", "special_markers",
    "encoded_tokens", "transforms_applied", "sentence_count", "symbol_run_ratio",
]

_WORD_RE = re.compile(r"[A-Za-z']+")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _max_run(s: str) -> int:
    best = cur = 0
    prev = ""
    for ch in s:
        cur = cur + 1 if ch == prev else 1
        prev = ch
        best = max(best, cur)
    return best


def behavior_features(text: str, deob: Deobfuscation | None = None) -> np.ndarray:
    """Return a fixed-length numeric vector describing *how* a prompt looks (not what it means)."""
    text = text or ""
    d = deob or deobfuscate(text)
    n = max(len(text), 1)
    words = _WORD_RE.findall(d.normalized)
    nw = max(len(words), 1)
    upper = sum(c.isupper() for c in text) / n
    digits = sum(c.isdigit() for c in text) / n
    punct = sum((not c.isalnum()) and (not c.isspace()) for c in text) / n
    nonascii = sum(ord(c) > 127 for c in text) / n
    first = words[0].lower() if words else ""
    view = d.text
    sym_runs = re.findall(r"[^\w\s]{3,}", text)
    feats = [
        math.log1p(len(text)),
        math.log1p(len(words)),
        float(np.mean([len(w) for w in words])) if words else 0.0,
        upper, digits, punct, nonascii,
        float(count_invisible(text)),
        _entropy(text),
        float(len(OVERRIDE_RE.findall(view))),
        float(len(SENSITIVE_RE.findall(view))),
        float(len(PERSONA_RE.findall(view))),
        float(len(EXTRACTION_RE.findall(view))),
        1.0 if first in IMPERATIVE_START else 0.0,
        float(text.count("?")),
        float(text.count("\n")),
        float(_max_run(text)),
        len(set(w.lower() for w in words)) / nw,
        float(len(URL_RE.findall(text))),
        float(len(MARKER_RE.findall(text))),
        float(sum(1 for t in d.transforms if t in ("base64", "hex"))),
        float(len(d.transforms)),
        float(len(re.findall(r"[.!?]+(?:\s|$)", text)) or 1),
        sum(len(r) for r in sym_runs) / n,
    ]
    return np.asarray(feats, dtype=float)


# --- module-level callables used by sklearn FunctionTransformers (must be picklable) -----------------
def view_normalized(texts: Iterable[str]) -> list[str]:
    return [deobfuscate(t).text for t in texts]


def view_raw(texts: Iterable[str]) -> list[str]:
    return [t if isinstance(t, str) else "" for t in texts]


def view_numeric(texts: Iterable[str]) -> np.ndarray:
    texts = list(texts)
    if not texts:
        return np.zeros((0, len(FEATURE_NAMES)))
    return np.vstack([behavior_features(t) for t in texts])
