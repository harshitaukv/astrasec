import pytest

from astrasec.signatures import STATIC_SIGNATURES, Signature, SignatureEngine
from .conftest import ATTACKS, BENIGN


@pytest.fixture
def eng():
    return SignatureEngine()


@pytest.mark.parametrize("label", list(ATTACKS))
def test_canonical_attacks_hit_their_own_class(eng, label):
    best = eng.best(ATTACKS[label])
    assert best.get(label, 0) > 0.5, best


@pytest.mark.parametrize("text", BENIGN)
def test_ordinary_shop_questions_have_no_hits(eng, text):
    assert eng.scan(text) == []


@pytest.mark.parametrize("text", [
    "Can you explain what a jailbreak is and why AI companies worry about it?",
    "What is a jailbreak on an iPhone?",
    "Explain the difference between logits and probabilities for a beginner.",
])
def test_educational_questions_are_not_flagged(eng, text):
    assert eng.best(text) == {}


def test_signature_ids_are_unique_and_compile():
    ids = [s.sid for s in STATIC_SIGNATURES]
    assert len(ids) == len(set(ids))
    for s in STATIC_SIGNATURES:
        s.compiled  # noqa: B018  (raises if the regex is invalid)


def test_learned_signature_can_be_added(eng):
    sig = Signature("LN-9001", "prompt_injection", r"zebra\s+protocol\s+override", 0.8, "learned")
    eng.set_learned([sig])
    assert any(h.sid == "LN-9001" for h in eng.scan("please run the zebra protocol override now"))
