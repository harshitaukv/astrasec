"""Signature engine: fast, explainable pattern matching that complements the ML classifier.

Static signatures encode well-known attack phrasing. *Learned* signatures are added at runtime by the
self-healing engine (see engines/memory.py) after they pass a false-positive check against benign traffic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .features import deobfuscate, Deobfuscation


@dataclass(frozen=True)
class Signature:
    sid: str
    label: str
    pattern: str
    weight: float
    source: str = "static"      # static | learned | llm

    def compiled(self) -> re.Pattern:
        return re.compile(self.pattern, re.I | re.S)


_INSTR = r"(?:instructions?|prompts?|rules|guidelines|directions?|directives|context|programming|constraints|policies)"
_QUAL = r"(?:all|any|the|your|previous|prior|above|earlier|preceding|initial|original|system|safety)"

STATIC_SIGNATURES: list[Signature] = [
    # ---- prompt injection ------------------------------------------------------------------------
    Signature("PI-001", "prompt_injection",
              rf"\b(?:ignore|disregard|forget|override|bypass|overrule|abandon|discard)\b(?:\W+\w+){{0,4}}?\W+{_QUAL}\b(?:\W+\w+){{0,3}}?\W+{_INSTR}", 0.93),
    Signature("PI-002", "prompt_injection",
              r"\b(?:reveal|show|print|display|repeat|output|leak|expose|tell me|give me|share|disclose)\b(?:\W+\w+){0,6}?\W+(?:system|initial|hidden|original|secret|internal)\W+(?:prompt|instructions?|message|rules|configuration|setup)", 0.92),
    Signature("PI-003", "prompt_injection", r"\b(?:new|updated|revised)\s+(?:system\s+)?(?:instructions?|prompt|directives?)\s*(?:[:\-]|from)", 0.88),
    Signature("PI-004", "prompt_injection", r"(?:</?\s*(?:system|assistant)\s*>|\[\s*/?\s*(?:inst|system)\s*\]|<\|im_(?:start|end)\|>|^\s*system\s*:)", 0.90),
    Signature("PI-005", "prompt_injection", r"\b(?:note|message|instruction|attention)s?\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|language model|llm|model|agents?)\b|\b(?:ai|llm)\s+agents?\s*:", 0.85),
    Signature("PI-006", "prompt_injection", r"\bfrom now on\b.{0,40}\b(?:you|only|always|respond|answer)\b", 0.72),
    Signature("PI-007", "prompt_injection", r"\b(?:repeat|print|output|show|copy)\b(?:\W+\w+){0,3}?\W+(?:everything|the (?:words|text|message|content)|all (?:text|content|of it))\W+(?:above|before|prior|preceding)", 0.92),
    Signature("PI-008", "prompt_injection", r"\b(?:send|forward|email|post|upload|exfiltrate|leak)\b.{0,60}\b(?:conversation|chat history|history|customer|database|records|data|secrets?|credentials)\b.{0,60}(?:https?://|@\w+|\bto\s+\S+@)", 0.90),
    Signature("PI-009", "prompt_injection", r"\b(?:i am|i'm|this is)\s+(?:the\s+)?(?:developer|administrator|admin|owner|creator|engineer)\b.{0,80}\b(?:authori[sz]e|override|allow|must|require|disable|unlock)", 0.86),
    Signature("PI-010", "prompt_injection", r"\b(?:what|which)\s+(?:was|were|is|are)\s+(?:the\s+)?(?:first|initial|very first)\s+(?:message|instruction|line|words?)s?\b.{0,40}\b(?:conversation|above|given|verbatim|exact)", 0.85),
    Signature("PI-011", "prompt_injection", r"\b(?:ignora|ignorez|ignoriere|ignorar|ignorer)\b.{0,40}\b(?:instrucci\w+|anweisungen|pr[ée]c[ée]dent\w*|anteriores|vorherigen|previas|reglas)\b|\b(?:pichhle|purane)\b.{0,30}\bnirdesh\b|\bnirdesh\b.{0,20}\bignore\b", 0.90),
    Signature("PI-012", "prompt_injection", r"\bdo not (?:mention|reveal|disclose|tell)\b.{0,30}\b(?:these|this|the)\s+instructions?\b", 0.80),
    Signature("PI-013", "prompt_injection", r"\b(?:call|invoke|execute|use)\s+(?:the\s+)?(?:\w+_)+\w+\s*(?:function|tool|api)?\b.{0,20}\b(?:now|immediately)\b|\bdelete[_ ]all\b", 0.82),
    Signature("PI-014", "prompt_injection", r"!\[[^\]]*\]\(https?://[^)]*\{[^)]*\}[^)]*\)|!\[[^\]]*\]\(https?://[^)]*(?:steal|exfil|leak|collect)[^)]*\)", 0.90),
    Signature("PI-015", "prompt_injection", r"\byou (?:will|must|shall) obey\b|\bobey (?:every|all|only)\b.{0,30}\b(?:command|instruction)", 0.82),
    # ---- jailbreak -------------------------------------------------------------------------------
    Signature("JB-001", "jailbreak", r"\bdo anything now\b|\bDAN\b(?:\W+\w+){0,6}?\W+(?:mode|no restrictions|never refuses|jailbr\w+)|\byou are (?:now )?DAN\b", 0.95),
    Signature("JB-002", "jailbreak", r"\b(?:enable|activate|enter|switch to)\s+(?:developer|dev|god|jailbreak|admin|debug|unrestricted)\s+mode\b|\bdeveloper mode\b.{0,60}\b(?:ignore|no|without|any)\b", 0.92),
    Signature("JB-003", "jailbreak", r"\b(?:no|without|free from|freed from|free of|zero|remove all|disable (?:all|your))\s+(?:any\s+|your\s+|usual\s+|all\s+)?(?:ethical\s+)?(?:restrictions|filters?|limitations?|guidelines|censorship|safety (?:filters|guidelines|measures)|content polic(?:y|ies)|moral)", 0.88),
    Signature("JB-004", "jailbreak", r"\b(?:pretend|imagine|act|behave|roleplay|role-play)\b.{0,60}\b(?:no (?:rules|restrictions|limits|ethical)|unrestricted|unfiltered|uncensored|evil|amoral|without (?:any )?(?:rules|restrictions|filters))", 0.90),
    Signature("JB-005", "jailbreak", r"\b(?:never|don'?t|do not|without)\s+(?:ever\s+)?(?:say|refuse|apologi[sz]e|mention|add|include|give)\b.{0,50}\b(?:can'?t|cannot|sorry|unable|as an ai|warnings?|disclaimers?|refus\w+)", 0.90),
    Signature("JB-006", "jailbreak", r"\bstay in character\b|\bunfiltered\b|\buncensored\b|\byou(?:'re| are)?\s+(?:now\s+)?jailbr(?:oken|eak)\w*|\bjailbreak\s+(?:mode|prompt|yourself|you)\b|\b(?:this is a|use this|the)\s+jailbreak\s+prompt\b", 0.82),
    Signature("JB-007", "jailbreak", r"\b(?:two|2|dual)\s+(?:responses|answers|replies)\b.{0,80}\b(?:unfiltered|unrestricted|ignores? (?:all )?rules|jailbr\w+|no restrictions|amoral)", 0.92),
    Signature("JB-008", "jailbreak", r"\byou have\s+\d+\s+tokens\b|\bcease to exist\b.{0,30}\b(?:refuse|token)|\bloses?\s+\d+\s+tokens?\b", 0.90),
    Signature("JB-009", "jailbreak", r"\b(?:opposite|reverse)\s+mode\b|\bsimulate\s+(?:a\s+)?(?:terminal|shell|linux)\b.{0,60}\b(?:no|without)\b.{0,20}\b(?:safety|filter|restriction)", 0.88),
    Signature("JB-010", "jailbreak", r"\b(?:for\s+(?:purely\s+)?(?:educational|research|academic|fictional)\s+purposes?(?:\s+only)?)\b.{0,80}\b(?:ignor\w+|without|bypass\w*)\b.{0,30}\b(?:safety|guidelines|restrictions|rules|filters)", 0.86),
    Signature("JB-011", "jailbreak", r"\b(?:AIM|STAN|DUDE|EvilBot|BetterDAN|Mongo Tom)\b.{0,80}\b(?:unfiltered|amoral|never|no (?:rules|restrictions))", 0.90),
    Signature("JB-012", "jailbreak", r"\b(?:late|deceased|dead)\s+(?:grandmother|grandma|grandfather|mother|father)\b.{0,100}\b(?:used to|would)\b.{0,60}\b(?:hack|malware|ransomware|weapon|phishing|steal|exploit|bypass)", 0.86),
    # ---- adversarial (structure-based; encoded-payload detection is done in code) ---------------------
    Signature("AD-001", "adversarial", r"describing\.?\\?\s*\+\s*similarly|write oppositeley|\]\(\s*Me giving|revert with\s+\"?\\!--", 0.95),
    Signature("AD-002", "adversarial", r"(?:\\!|\]\(|\*\*ONE|\}\]|\[/\*|=\[/)", 0.55),
    Signature("AD-003", "adversarial", r"<(?:div|span|p)[^>]*(?:display\s*:\s*none|hidden|visibility\s*:\s*hidden|font-size\s*:\s*0)[^>]*>", 0.96),
    Signature("AD-005", "adversarial", r"(\S{1,8})(?:\s+\1){25,}", 0.96),
    Signature("AD-004", "adversarial", r"\b(?:let\s+)?[a-z]\s*=\s*['\"][^'\"]{4,}['\"];?\s*(?:let\s+)?[b-z]\s*=\s*['\"][^'\"]{4,}['\"].{0,60}\b(?:a\s*\+\s*b|concat|combine|join|execute|do)", 0.85),
    # ---- model extraction ------------------------------------------------------------------------
    Signature("ME-001", "model_extraction", r"\b(?:raw\s+)?(?:logits?|logprobs?|log-probabilit\w+|token probabilit\w+|softmax (?:output|values|scores))\b.{0,60}\b(?:output|return|give|print|show|dump|list|top)|\b(?:output|return|give|print|show|dump|list)\b(?:(?!\b(?:explanation|explain|difference|meaning|understand|beginner)\b).){0,60}\b(?:raw\s+)?(?:logits?|logprobs?|token probabilit\w+)", 0.90),
    Signature("ME-002", "model_extraction", r"\b(?:training|fine-?tuning|pre-?training)\s+(?:data|set|corpus|dataset)\b.{0,60}\b(?:verbatim|exact(?:ly)?|list|dump|reveal|examples?|reproduce|memori[sz]ed)|\b(?:verbatim|exact(?:ly)?|list|dump|reveal|reproduce)\b.{0,60}\b(?:training|fine-?tuning|pre-?training)\s+(?:data|set|corpus|dataset)", 0.88),
    Signature("ME-003", "model_extraction", r"\b(?:dump|export|output|print|reveal|give me|download|extract)\b.{0,40}\b(?:model\s+)?(?:weights|parameters|hyper-?parameters|checkpoint|layers?|architecture)\b", 0.88),
    Signature("ME-004", "model_extraction", r"\brepeat\b.{0,30}\b(?:word|token|letter)\b.{0,30}(?:forever|indefinitely|without stopping|\d{3,}\s*times|over and over)|\bforever\b.{0,20}\brepeat\b", 0.90),
    Signature("ME-005", "model_extraction", r"\b(?:embedding|hidden state|activation)s?\s+(?:vector|values?)\b|\bgradients?\s+of\s+(?:your|the)\s+(?:loss|output)|\ball dimensions\b", 0.86),
    Signature("ME-006", "model_extraction", r"\bwas\s+(?:the\s+following|this)\s+(?:text|passage|sentence|document|paragraph)\s+(?:part\s+of|in)\s+your\s+training", 0.92),
    Signature("ME-007", "model_extraction", r"\bquery\s+\d+\s*(?:/|of)\s*\d+\b|\b(?:input|response)[- ]output pairs\b.{0,60}\b(?:train|clone|copy|replicate|fine-?tune)\b|\btrain\s+my\s+own\s+(?:copy|clone|model)", 0.90),
    Signature("ME-008", "model_extraction", r"\b(?:full|complete|entire)\s+(?:probability distribution|confidence (?:scores?|values?)|score vector)\b|\bconfidence (?:scores?|percentages?)\b.{0,40}\bfor (?:each|every|all)\b", 0.86),
    Signature("ME-009", "model_extraction", r"\b(?:print|reveal|output|show|list)\b.{0,30}\b(?:inference|model|full)\s+config(?:uration)?\b.{0,80}\b(?:temperature|top_p|stop tokens|safety thresholds?|fine-?tun\w+)", 0.86),
    Signature("ME-010", "model_extraction", r"\bfine-?tune\s+my\s+own\b|\buse your outputs to (?:train|fine-?tune|distill)\b|\bdistill(?:ation)?\b.{0,40}\b(?:your|this) model\b", 0.86),
]


@dataclass
class SignatureHit:
    sid: str
    label: str
    weight: float
    matched: str
    source: str = "static"


class SignatureEngine:
    def __init__(self, learned: list[Signature] | None = None) -> None:
        self._static = [(s, s.compiled()) for s in STATIC_SIGNATURES]
        self._learned: list[tuple[Signature, re.Pattern]] = []
        if learned:
            self.set_learned(learned)

    def set_learned(self, sigs: list[Signature]) -> None:
        compiled = []
        for s in sigs:
            try:
                compiled.append((s, s.compiled()))
            except re.error:
                continue
        self._learned = compiled

    @property
    def counts(self) -> dict[str, int]:
        return {"static": len(self._static), "learned": len(self._learned)}

    def scan(self, text: str | Deobfuscation) -> list[SignatureHit]:
        d = text if isinstance(text, Deobfuscation) else deobfuscate(text)
        hits: list[SignatureHit] = []
        for sig, rx in self._static + self._learned:
            m = rx.search(d.text)
            if not m:
                continue
            weight = sig.weight
            label = sig.label
            # Attack phrasing that only appears after normalisation / decoding is, by definition, an evasion attempt.
            if d.transforms and not rx.search(d.original) and sig.label in ("prompt_injection", "jailbreak", "model_extraction"):
                label = "adversarial"
                weight = min(0.97, weight + 0.03)
            hits.append(SignatureHit(sig.sid, label, weight, m.group(0)[:120], sig.source))
        return hits

    def best(self, text: str | Deobfuscation) -> dict[str, float]:
        """Highest signature weight per label."""
        out: dict[str, float] = {}
        for h in self.scan(text):
            out[h.label] = max(out.get(h.label, 0.0), h.weight)
        return out
