"""Train and evaluate every learned component of AstraSec.

    python -m training.train_all            # full run (a few minutes on one CPU core)
    python -m training.train_all --fast     # smaller RF, useful for CI

Outputs
    models/threat_model.joblib      Threat Prediction Engine (feature union + classifier)
    models/behavior_model.joblib    Behaviour Learning Engine (Isolation Forest baseline)
    models/metrics.json             every number shown on the dashboard's "Model lab" page
    data/dataset.csv                the generated corpus (text, label, family, split)
    data/benign_reference.json      benign sample used for false-positive checks on learned signatures
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import time
from collections import Counter

import numpy as np
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import GroupKFold, cross_val_predict

from astrasec.config import ATTACK_LABELS, DATA_DIR, LABELS, MODELS_DIR, SETTINGS
from astrasec.data.generator import build_dataset, split_by_family
from astrasec.engines.behavior import PromptBaseline
from astrasec.engines.threat import (Ensemble, ThreatPredictor, build_feature_union, fit_bundle, make_lr, make_rf, order_proba)
from astrasec.features import behavior_features
from astrasec.signatures import SignatureEngine


def _report(y_true, y_pred) -> dict:
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=LABELS, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=LABELS)
    is_att_t = np.array([y != "safe" for y in y_true])
    is_att_p = np.array([y != "safe" for y in y_pred])
    tp = int((is_att_t & is_att_p).sum())
    fn = int((is_att_t & ~is_att_p).sum())
    fp = int((~is_att_t & is_att_p).sum())
    tn = int((~is_att_t & ~is_att_p).sum())
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "macro_f1": round(float(f1_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)), 4),
        "per_class": {LABELS[i]: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                                   "f1": round(float(f[i]), 4), "support": int(s[i])} for i in range(len(LABELS))},
        "confusion_matrix": cm.tolist(),
        "binary": {"detection_rate": round(tp / max(tp + fn, 1), 4), "false_positive_rate": round(fp / max(fp + tn, 1), 4),
                   "precision": round(tp / max(tp + fp, 1), 4), "tp": tp, "fn": fn, "fp": fp, "tn": tn},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    t_start = time.time()
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rf_trees = 60 if args.fast else 150

    # ------------------------------------------------------------------ data
    print("[1/6] Generating dataset ...")
    data = build_dataset(seed=args.seed)
    train, test = split_by_family(data)
    print(f"      total={len(data)}  train={len(train)}  test(held-out families)={len(test)}")
    print("      train:", dict(Counter(s.label for s in train)))
    print("      test :", dict(Counter(s.label for s in test)))
    test_fams = {s.family for s in test}
    with open(DATA_DIR / "dataset.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["text", "label", "family", "split"])
        for s in data:
            w.writerow([s.text, s.label, s.family, "test" if s.family in test_fams else "train"])

    Xtr_text = [s.text for s in train]
    ytr = [s.label for s in train]
    groups = [s.family for s in train]
    Xte_text = [s.text for s in test]
    yte = [s.label for s in test]

    # ------------------------------------------------------------------ model selection (grouped CV)
    print("[2/6] Featurising + grouped cross-validation (folds hold out whole template families) ...")
    union = build_feature_union()
    Xtr = union.fit_transform(Xtr_text)
    print(f"      feature matrix: {Xtr.shape[0]} x {Xtr.shape[1]}")
    gkf = GroupKFold(n_splits=3)
    cv_results = {}
    cv_proba = {}
    for name, factory in [("logreg", lambda: make_lr(20.0)), ("random_forest", lambda: make_rf(rf_trees))]:
        t0 = time.time()
        proba = cross_val_predict(factory(), Xtr, ytr, groups=groups, cv=gkf, method="predict_proba")
        classes = sorted(set(ytr))
        cv_proba[name] = order_proba(classes, proba)
        cv_results[name] = time.time() - t0
    cv_proba["ensemble"] = (cv_proba["logreg"] + cv_proba["random_forest"]) / 2
    comparison = []
    for name in ["logreg", "random_forest", "ensemble"]:
        pred = [LABELS[i] for i in cv_proba[name].argmax(1)]
        comparison.append({
            "model": name,
            "cv_accuracy": round(float(accuracy_score(ytr, pred)), 4),
            "cv_macro_f1": round(float(f1_score(ytr, pred, labels=LABELS, average="macro")), 4),
            "cv_seconds": round(cv_results.get(name, sum(cv_results.values())), 1),
        })
        print(f"      {name:14s} CV acc={comparison[-1]['cv_accuracy']:.4f}  macro-F1={comparison[-1]['cv_macro_f1']:.4f}")
    best = max(comparison, key=lambda c: c["cv_macro_f1"])["model"]
    print(f"      -> selected: {best}")

    # ------------------------------------------------------------------ held-out evaluation
    print("[3/6] Fitting selected model on the training split and evaluating on held-out families ...")
    eval_bundle = fit_bundle(Xtr_text, ytr, kind=best, rf_trees=rf_trees, precomputed=(union, Xtr))
    sig = SignatureEngine()
    predictor = ThreatPredictor(eval_bundle, sig)
    ml_proba = predictor.ml_proba(Xte_text)
    ml_pred = [LABELS[i] for i in ml_proba.argmax(1)]
    fused = predictor.predict_many(Xte_text, flag=SETTINGS.thresholds.flag)
    fused_pred = [f["label"] for f in fused]
    sig_only = []
    for t in Xte_text:
        b = sig.best(t)
        sig_only.append(max(b, key=b.get) if b else "safe")
    ml_report = _report(yte, ml_pred)
    fused_report = _report(yte, fused_pred)
    sig_report = _report(yte, sig_only)
    # per-label ROC-AUC (one-vs-rest) for the ML probabilities
    aucs = {}
    for i, lab in enumerate(LABELS):
        y_bin = [1 if y == lab else 0 for y in yte]
        aucs[lab] = round(float(roc_auc_score(y_bin, ml_proba[:, i])), 4)
    print(f"      ML only      acc={ml_report['accuracy']:.4f} macro-F1={ml_report['macro_f1']:.4f}")
    print(f"      Signatures   acc={sig_report['accuracy']:.4f} macro-F1={sig_report['macro_f1']:.4f}")
    print(f"      Fused (prod) acc={fused_report['accuracy']:.4f} macro-F1={fused_report['macro_f1']:.4f}  "
          f"detect={fused_report['binary']['detection_rate']:.3f} FPR={fused_report['binary']['false_positive_rate']:.3f}")

    # ------------------------------------------------------------------ behaviour engine
    print("[4/6] Training Behaviour Learning Engine (Isolation Forest on benign traffic only) ...")
    benign_train = [s.text for s in train if s.label == "safe"]
    Fb = np.vstack([behavior_features(t) for t in benign_train])
    baseline = PromptBaseline().fit(Fb)
    benign_test = [s.text for s in test if s.label == "safe"]
    attack_test = [s for s in test if s.label != "safe"]
    Fbt = np.vstack([behavior_features(t) for t in benign_test])
    Fat = np.vstack([behavior_features(s.text) for s in attack_test])
    sb = baseline.score_matrix(Fbt)
    sa = baseline.score_matrix(Fat)
    y_bin = np.r_[np.zeros(len(sb)), np.ones(len(sa))]
    auc = float(roc_auc_score(y_bin, np.r_[sb, sa]))
    thr = SETTINGS.thresholds.anomaly_flag
    per_label = {lab: round(float((baseline.score_matrix(np.vstack([behavior_features(s.text) for s in attack_test if s.label == lab])) >= thr).mean()), 4)
                 for lab in ATTACK_LABELS if any(s.label == lab for s in attack_test)}
    behavior_metrics = {
        "algorithm": "Isolation Forest (300 trees) on 24 behavioural features, benign-only training",
        "trained_on": int(len(benign_train)),
        "roc_auc_attack_vs_benign": round(auc, 4),
        "threshold": thr,
        "benign_false_alarm_rate": round(float((sb >= thr).mean()), 4),
        "attack_flag_rate": round(float((sa >= thr).mean()), 4),
        "flag_rate_by_class": per_label,
        "note": "Unsupervised: the forest never saw an attack. It is a first-line 'this looks odd' signal, not a classifier.",
    }
    print(f"      AUC={auc:.3f}  benign false alarms={behavior_metrics['benign_false_alarm_rate']:.3f}  attacks flagged={behavior_metrics['attack_flag_rate']:.3f}")

    # ------------------------------------------------------------------ explainability sample
    lr = eval_bundle.explainer
    top_terms = {}
    names = eval_bundle.names
    for i, lab in enumerate(lr.classes_):
        if lab == "safe":
            continue
        coefs = lr.coef_[i]
        idx = [j for j in np.argsort(-coefs) if names[j].startswith("word:")][:8]
        top_terms[lab] = [{"term": names[j].split(":", 1)[1], "coef": round(float(coefs[j]), 2)} for j in idx]

    # ------------------------------------------------------------------ final models on ALL data
    print("[5/6] Refitting deployment models on all data ...")
    all_text = [s.text for s in data]
    all_y = [s.label for s in data]
    final = fit_bundle(all_text, all_y, kind=best, rf_trees=rf_trees)
    final.save(MODELS_DIR / "threat_model.joblib")
    benign_all = [s.text for s in data if s.label == "safe"]
    baseline_final = PromptBaseline().fit(np.vstack([behavior_features(t) for t in benign_all]))
    baseline_final.save(MODELS_DIR / "behavior_model.joblib")
    rng = random.Random(1)
    ref = rng.sample(benign_all, min(2500, len(benign_all)))
    (DATA_DIR / "benign_reference.json").write_text(json.dumps(ref), encoding="utf-8")

    # ------------------------------------------------------------------ persist metrics
    print("[6/6] Writing metrics ...")
    metrics = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_seconds": round(time.time() - t_start, 1),
        "dataset": {"total": len(data), "train": len(train), "test": len(test),
                    "label_counts": dict(Counter(all_y)), "families": len({s.family for s in data}),
                    "held_out_families": sorted(test_fams),
                    "note": "Synthetic template corpus. Test set = whole template families never seen in training."},
        "selected_model": best,
        "model_comparison": comparison,
        "held_out": {"ml_only": ml_report, "signatures_only": sig_report, "fused": fused_report, "roc_auc_ovr": aucs},
        "behavior_engine": behavior_metrics,
        "top_terms": top_terms,
        "feature_count": int(Xtr.shape[1]),
        "labels": LABELS,
    }
    (MODELS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Done in {time.time() - t_start:.0f}s. Artifacts in {MODELS_DIR}")


if __name__ == "__main__":
    main()
