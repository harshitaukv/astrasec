"""MODULE 3 - Threat Prediction Engine.

Pipeline:  raw prompt -> de-obfuscation -> [word TF-IDF | char TF-IDF | 24 behavioural features]
           -> Logistic Regression / Random Forest / soft-voting ensemble -> class probabilities.

The ML probabilities are then *fused* with the signature engine (static + learned signatures) so that a
well-known attack phrase can never be missed because of a quirk in the model, and a novel paraphrase can
still be caught by the model even if no signature matches.  Explanations come from the linear model's
per-term contributions.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

import joblib
import numpy as np
from scipy import sparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, MinMaxScaler

from ..config import ATTACK_LABELS, LABELS
from ..features import FEATURE_NAMES, deobfuscate, view_normalized, view_numeric, view_raw
from ..signatures import SignatureEngine

SEVERITY_BASE = {"prompt_injection": 0.95, "jailbreak": 0.92, "adversarial": 0.85, "model_extraction": 0.80}


def build_feature_union() -> FeatureUnion:
    return FeatureUnion([
        ("word", Pipeline([
            ("view", FunctionTransformer(view_normalized, validate=False)),
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, lowercase=True, max_features=30000)),
        ])),
        ("char", Pipeline([
            ("view", FunctionTransformer(view_raw, validate=False)),
            ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, sublinear_tf=True, max_features=50000)),
        ])),
        ("num", Pipeline([
            ("view", FunctionTransformer(view_numeric, validate=False)),
            ("scale", MinMaxScaler(clip=True)),
        ])),
    ])


def make_lr(C: float = 20.0) -> LogisticRegression:
    return LogisticRegression(C=C, max_iter=3000, class_weight="balanced")


def make_rf(n: int = 150, seed: int = 42) -> RandomForestClassifier:
    return RandomForestClassifier(n_estimators=n, class_weight="balanced_subsample", n_jobs=-1, random_state=seed, min_samples_leaf=1)


def feature_names(union: FeatureUnion) -> list[str]:
    names: list[str] = []
    for name, tr in union.transformer_list:
        if name == "num":
            names += [f"num:{n}" for n in FEATURE_NAMES]
        else:
            names += [f"{name}:{t}" for t in tr.named_steps["tfidf"].get_feature_names_out()]
    return names


def order_proba(clf_classes, proba: np.ndarray) -> np.ndarray:
    out = np.zeros((proba.shape[0], len(LABELS)))
    for j, c in enumerate(clf_classes):
        out[:, LABELS.index(c)] = proba[:, j]
    return out


class Ensemble:
    """Soft-voting wrapper so the (LR, RF) pair behaves like one classifier. Picklable."""

    def __init__(self, members: list, weights: list[float] | None = None) -> None:
        self.members = members
        self.weights = weights or [1.0] * len(members)
        self.classes_ = np.array(members[0].classes_)

    def predict_proba(self, X):
        w = np.array(self.weights) / sum(self.weights)
        return sum(wi * m.predict_proba(X) for wi, m in zip(w, self.members))


@dataclass
class ThreatBundle:
    union: FeatureUnion
    clf: object                # LR / RF / Ensemble
    explainer: LogisticRegression   # always a linear model (used for term-level explanations)
    names: list[str]
    kind: str                  # "logreg" | "random_forest" | "ensemble"
    trained_on: int = 0

    def save(self, path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path) -> "ThreatBundle":
        return joblib.load(path)


class ThreatPredictor:
    def __init__(self, bundle: ThreatBundle, signatures: SignatureEngine) -> None:
        self.bundle = bundle
        self.sig = signatures

    # ------------------------------------------------------------------------------------------
    def ml_proba(self, texts: list[str]) -> np.ndarray:
        X = self.bundle.union.transform(texts)
        return order_proba(self.bundle.clf.classes_, self.bundle.clf.predict_proba(X))

    def _explain(self, text: str, label: str, k: int = 6) -> list[dict]:
        ex = self.bundle.explainer
        X = self.bundle.union.transform([text])
        row = sparse.csr_matrix(X)
        cls_idx = list(ex.classes_).index(label)
        contrib = row.multiply(ex.coef_[cls_idx]).tocoo()
        items = []
        for j, v in zip(contrib.col, contrib.data):
            n = self.bundle.names[j]
            if v > 0.02 and not n.startswith("char:"):
                items.append((n.split(":", 1)[1], float(v)))
        items.sort(key=lambda t: -t[1])
        return [{"term": t, "weight": round(w, 3)} for t, w in items[:k]]

    @staticmethod
    def severity(label: str, confidence: float, hits: int = 0) -> tuple[str, float]:
        if label == "safe":
            return "none", 0.0
        score = SEVERITY_BASE.get(label, 0.8) * confidence
        if hits >= 2:
            score = min(1.0, score + 0.05)
        return ("high" if score >= 0.70 else "medium" if score >= 0.45 else "low"), round(score, 3)

    def predict(self, text: str, flag: float = 0.50, explain: bool = True) -> dict:
        t0 = time.perf_counter()
        d = deobfuscate(text)
        ml = self.ml_proba([text])[0]
        hits = self.sig.scan(d)

        scores = {lab: float(ml[LABELS.index(lab)]) for lab in ATTACK_LABELS}
        p_attack_mass = float(1.0 - ml[LABELS.index("safe")])
        for h in hits:
            scores[h.label] = max(scores[h.label], h.weight)
        top_attack = max(ATTACK_LABELS, key=lambda l: scores[l])
        # confidence = strongest evidence that the request is hostile (single class, signature, or total attack mass)
        confidence = max(scores[top_attack], p_attack_mass)
        flagged = confidence >= flag
        label = top_attack if flagged else "safe"
        sev, sev_score = self.severity(label, confidence, len(hits))
        final_scores = dict(scores)
        final_scores["safe"] = round(max(0.0, 1.0 - confidence), 4)
        final_scores = {k: round(v, 4) for k, v in final_scores.items()}
        expl = self._explain(text, label if label != "safe" else top_attack) if (explain and flagged) else []
        return {
            "label": label,
            "flagged": bool(flagged),
            "confidence": round(confidence if flagged else 1.0 - confidence, 4),
            "attack_confidence": round(confidence, 4),
            "scores": final_scores,
            "ml_scores": {LABELS[i]: round(float(ml[i]), 4) for i in range(len(LABELS))},
            "severity": sev,
            "severity_score": sev_score,
            "signature_hits": [{"id": h.sid, "label": h.label, "weight": h.weight, "matched": h.matched, "source": h.source} for h in hits],
            "explanation": expl,
            "obfuscation": d.transforms,
            "model": self.bundle.kind,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
        }

    def predict_many(self, texts: list[str], flag: float = 0.50) -> list[dict]:
        """Batch prediction without explanations (used by evaluation and sanitisation)."""
        if not texts:
            return []
        proba = self.ml_proba(texts)
        out = []
        for text, ml in zip(texts, proba):
            d = deobfuscate(text)
            hits = self.sig.scan(d)
            scores = {lab: float(ml[LABELS.index(lab)]) for lab in ATTACK_LABELS}
            mass = float(1.0 - ml[LABELS.index("safe")])
            for h in hits:
                scores[h.label] = max(scores[h.label], h.weight)
            top = max(ATTACK_LABELS, key=lambda l: scores[l])
            conf = max(scores[top], mass)
            out.append({"label": top if conf >= flag else "safe", "attack_confidence": conf, "flagged": conf >= flag,
                        "signature_hits": len(hits)})
        return out


def fit_bundle(texts: list[str], labels: list[str], kind: str = "ensemble", C: float = 20.0, rf_trees: int = 150,
               sample_weight: np.ndarray | None = None, precomputed: tuple | None = None) -> ThreatBundle:
    """Fit the feature union + classifier(s) on labelled text. `kind` in {logreg, random_forest, ensemble}."""
    if precomputed is not None:
        union, X = precomputed
    else:
        union = build_feature_union()
        X = union.fit_transform(texts)
    lr = make_lr(C).fit(X, labels, sample_weight=sample_weight)
    if kind == "logreg":
        clf = lr
    else:
        rf = make_rf(rf_trees).fit(X, labels, sample_weight=sample_weight)
        clf = rf if kind == "random_forest" else Ensemble([lr, rf])
    return ThreatBundle(union=union, clf=clf, explainer=lr, names=feature_names(union), kind=kind, trained_on=len(texts))
