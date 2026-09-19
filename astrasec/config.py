"""Central configuration for AstraSec. Everything can be overridden with environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = Path(os.getenv("ASTRASEC_MODELS", ROOT / "models"))
DATA_DIR = Path(os.getenv("ASTRASEC_DATA", ROOT / "data"))
WEB_DIR = ROOT / "web"
DB_PATH = os.getenv("ASTRASEC_DB", str(DATA_DIR / "astrasec.db"))

LABELS = ["safe", "prompt_injection", "jailbreak", "adversarial", "model_extraction"]
ATTACK_LABELS = LABELS[1:]

LABEL_TITLES = {
    "safe": "Safe",
    "prompt_injection": "Prompt injection",
    "jailbreak": "Jailbreak",
    "adversarial": "Adversarial input",
    "model_extraction": "Model extraction",
}

# --- runtime settings (env-overridable) ---------------------------------------------------------
LLM_BACKEND = os.getenv("ASTRASEC_LLM", "mock")            # "mock" | "ollama"
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
API_KEY = os.getenv("ASTRASEC_API_KEY", "")                # empty = auth disabled (demo mode)


@dataclass
class Thresholds:
    """Adaptive thresholds. The self-healing engine moves these within [min, max] bounds."""
    flag: float = 0.50            # ML/signature confidence above which a request is treated as an attack
    flag_min: float = 0.35
    flag_max: float = 0.70
    block_high_conf: float = 0.90  # jailbreak / extraction above this are blocked outright
    memory_similarity: float = 0.75  # immune-memory recall similarity
    anomaly_flag: float = 0.60     # behavioural anomaly score considered suspicious


@dataclass
class RateLimit:
    capacity: int = 20             # burst size (tokens)
    refill_per_sec: float = 0.5    # sustained rate = 30 requests / minute
    strike_limit: int = 3          # attacks inside `strike_window_s` that trigger quarantine
    strike_window_s: int = 300
    quarantine_s: int = 120


@dataclass
class HealthWeights:
    prompt: float = 0.35
    api: float = 0.20
    config: float = 0.25
    dependencies: float = 0.20


@dataclass
class Settings:
    thresholds: Thresholds = field(default_factory=Thresholds)
    rate: RateLimit = field(default_factory=RateLimit)
    health: HealthWeights = field(default_factory=HealthWeights)
    behavior_refit_every: int = 200   # safe requests observed before Isolation Forest is refit
    signature_learn_every: int = 5    # new attack cases before signature learning runs
    posture_window_s: int = 300


SETTINGS = Settings()
