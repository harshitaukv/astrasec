"""MODULE 1 - Behavior Learning Engine.

Learns what "normal" traffic to an AI application looks like and scores how far a new request deviates.

* Prompt behaviour: an Isolation Forest trained ONLY on benign prompts (no attack labels needed) over 24
  behavioural features (length, entropy, override/persona vocabulary, encoding artefacts, ...).
* API behaviour: per-client request-rate tracking plus running mean/variance of payload and response sizes
  (Welford's algorithm) to spot bursts, floods and scraping.
* Continuous learning: requests judged safe are buffered; every `refit_every` observations the forest is refit
  on (original baseline + recent safe traffic), so the baseline follows legitimate drift.
"""
from __future__ import annotations

import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ..features import FEATURE_NAMES, behavior_features, deobfuscate


class PromptBaseline:
    def __init__(self, n_estimators: int = 300, random_state: int = 42) -> None:
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.forest: IsolationForest | None = None
        self.train_scores = np.array([])
        self.base_matrix = np.zeros((0, len(FEATURE_NAMES)))
        self.buffer: list[np.ndarray] = []
        self.refits = 0
        self.trained_on = 0

    # -- training ---------------------------------------------------------------------------------
    def fit(self, X: np.ndarray) -> "PromptBaseline":
        self.base_matrix = np.asarray(X, dtype=float)
        self._refit(self.base_matrix)
        return self

    def _refit(self, X: np.ndarray) -> None:
        Xs = self.scaler.fit_transform(X)
        self.forest = IsolationForest(n_estimators=self.n_estimators, max_samples=min(512, len(X)), contamination="auto",
                                      random_state=self.random_state, n_jobs=1).fit(Xs)
        self.train_scores = np.sort(self.forest.score_samples(Xs))
        self.trained_on = len(X)

    # -- scoring ----------------------------------------------------------------------------------
    def score_matrix(self, X: np.ndarray) -> np.ndarray:
        """Anomaly score in [0,1]: 0 = looks like the middle of the baseline, 1 = more extreme than any training sample."""
        s = self.forest.score_samples(self.scaler.transform(X))
        p = np.searchsorted(self.train_scores, s, side="right") / len(self.train_scores)   # empirical CDF
        return np.clip(1.0 - p / 0.20, 0.0, 1.0)

    def explain(self, x: np.ndarray, k: int = 3) -> list[dict]:
        z = (x - self.scaler.mean_) / np.where(self.scaler.scale_ == 0, 1.0, self.scaler.scale_)
        idx = np.argsort(-np.abs(z))[:k]
        return [{"feature": FEATURE_NAMES[i], "value": round(float(x[i]), 3), "z": round(float(z[i]), 2)} for i in idx if abs(z[i]) >= 2.0]

    # -- continual learning ----------------------------------------------------------------------
    def observe_safe(self, x: np.ndarray, refit_every: int) -> bool:
        self.buffer.append(x)
        if len(self.buffer) >= refit_every:
            self._refit(np.vstack([self.base_matrix, np.vstack(self.buffer)]))
            self.buffer.clear()
            self.refits += 1
            return True
        return False

    def save(self, path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path) -> "PromptBaseline":
        return joblib.load(path)


@dataclass
class _Welford:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    def z(self, x: float) -> float:
        if self.n < 20:
            return 0.0
        sd = math.sqrt(self.m2 / (self.n - 1)) or 1.0
        return (x - self.mean) / sd


class ApiMonitor:
    """Tracks request cadence and payload / response sizes per client."""

    def __init__(self, window_s: int = 60) -> None:
        self.window_s = window_s
        self.times: dict[str, deque] = defaultdict(deque)
        self.req_len = _Welford()
        self.resp_len = _Welford()
        self._lock = threading.Lock()

    def record_request(self, client: str, prompt_len: int, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        with self._lock:
            dq = self.times[client]
            dq.append(now)
            while dq and now - dq[0] > self.window_s:
                dq.popleft()
            rate = len(dq)
            z_len = self.req_len.z(prompt_len)
            self.req_len.update(prompt_len)
        anomaly = min(1.0, max(0.0, (rate - 12) / 30.0, (z_len - 3.0) / 6.0))
        return {"requests_last_minute": rate, "length_z": round(z_len, 2), "api_anomaly": round(anomaly, 3)}

    def record_response(self, resp_len: int) -> float:
        with self._lock:
            z = self.resp_len.z(resp_len)
            self.resp_len.update(resp_len)
        return z


class BehaviorLearningEngine:
    def __init__(self, baseline: PromptBaseline, anomaly_flag: float = 0.60, refit_every: int = 200) -> None:
        self.baseline = baseline
        self.api = ApiMonitor()
        self.anomaly_flag = anomaly_flag
        self.refit_every = refit_every
        self._lock = threading.Lock()

    def analyze(self, text: str, client_id: str = "anon") -> dict:
        d = deobfuscate(text)
        x = behavior_features(text, d)
        with self._lock:
            score = float(self.baseline.score_matrix(x.reshape(1, -1))[0])
            top = self.baseline.explain(x)
        api = self.api.record_request(client_id, len(text))
        suspicious = score >= self.anomaly_flag or api["api_anomaly"] >= 0.6
        return {
            "anomaly_score": round(score, 3),
            "suspicious": bool(suspicious),
            "deviations": top,
            "obfuscation": d.transforms,
            "api": api,
            "features": x,          # stripped before returning to API callers
        }

    def learn(self, features: np.ndarray, safe: bool) -> bool:
        """Feed a verified-safe request back into the baseline. Returns True when a refit happened."""
        if not safe:
            return False
        with self._lock:
            return self.baseline.observe_safe(features, self.refit_every)

    def stats(self) -> dict:
        return {
            "baseline_samples": int(self.baseline.trained_on),
            "buffered_safe_requests": len(self.baseline.buffer),
            "refits": self.baseline.refits,
            "refit_every": self.refit_every,
            "trees": self.baseline.n_estimators,
        }
