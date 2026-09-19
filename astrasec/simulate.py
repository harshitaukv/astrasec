"""Traffic simulator: populates the request log with a realistic day of legitimate users and attackers.

Timestamps are back-dated over `hours` with a diurnal shape and an attack burst near the end (so the forecast has
something to warn about).  Prompts come from the generator (in-distribution) and from the independent red-team /
hold-out sets (out-of-distribution, so some slip through, exercising the emerging-threat and feedback paths).
"""
from __future__ import annotations

import math
import random
import time

from .data.generator import build_dataset
from .data.holdout import FRESH
from .data.redteam import RED_TEAM


def run_simulation(app, n: int = 240, hours: int = 24, attack_ratio: float = 0.28, seed: int = 11) -> dict:
    rng = random.Random(seed)
    data = build_dataset(seed=seed + 100)
    gen_safe = [s.text for s in data if s.label == "safe"]
    gen_att = [(s.text, s.label) for s in data if s.label != "safe"]
    ood_att = [(t, y) for t, y in RED_TEAM + FRESH if y != "safe"]
    ood_safe = [t for t, y in RED_TEAM + FRESH if y == "safe"]
    now = time.time()
    events = []
    for i in range(n):
        # diurnal traffic curve + burst in the most recent 3 hours
        frac = rng.random()
        hour_of_day = (frac * hours) % 24
        weight = 0.4 + 0.6 * math.sin(math.pi * hour_of_day / 24) ** 2
        if rng.random() > weight:
            frac = rng.random()
        burst = rng.random() < 0.18
        ts = now - (rng.random() * 3 * 3600 if burst else (1 - frac) * hours * 3600)
        is_attack = rng.random() < (attack_ratio + (0.35 if burst else 0.0))
        if is_attack:
            text, truth = rng.choice(ood_att) if rng.random() < 0.35 else rng.choice(gen_att)
            client = f"attacker-{rng.randint(1, 12):02d}"
        else:
            text, truth = (rng.choice(ood_safe) if rng.random() < 0.25 else rng.choice(gen_safe)), "safe"
            client = f"user-{rng.randint(1, 60):02d}"
        events.append((ts, text, truth, client))
    events.sort()
    stats = {"requests": 0, "attacks_sent": 0, "flagged": 0, "blocked": 0}
    for ts, text, truth, client in events:
        try:
            r = app.protect(text, client_id=client, forward=True, ts_override=ts)
        except ValueError:
            continue
        stats["requests"] += 1
        stats["attacks_sent"] += truth != "safe"
        stats["flagged"] += r["decision"]["flagged"]
        stats["blocked"] += not r["decision"]["allowed"]
    app.healer.escalate_policy()
    return stats
