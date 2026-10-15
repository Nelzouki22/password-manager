"""Password strength scoring and vault-wide security checks.

All analysis runs in memory on decrypted data; nothing computed here is persisted.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

LABELS = ("Very weak", "Weak", "Fair", "Strong", "Very strong")

COMMON_PASSWORDS = frozenset(
    """password password1 password123 passw0rd p@ssw0rd p@ssword 123456 1234567 12345678 123456789
    1234567890 111111 000000 123123 654321 qwerty qwerty123 qwertyuiop asdfgh asdfghjkl zxcvbnm
    abc123 abcd1234 iloveyou admin admin123 administrator welcome welcome1 login letmein monkey
    dragon master sunshine princess football baseball superman batman trustno1 shadow michael
    jordan freedom whatever hello hello123 secret changeme default test test123 guest root toor
    summer winter spring autumn 1q2w3e4r 1qaz2wsx qazwsx zaq12wsx""".split()
)
COMMON_FRAGMENTS = ("password", "passwd", "qwerty", "letmein", "welcome", "admin", "iloveyou", "123456")
_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm")


@dataclass(frozen=True)
class Strength:
    score: int                    # 0 (very weak) .. 4 (very strong)
    label: str
    entropy_bits: float
    feedback: tuple[str, ...]

    @property
    def is_weak(self) -> bool:
        return self.score < 2

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "label": self.label,
            "entropy_bits": self.entropy_bits,
            "feedback": list(self.feedback),
            "is_weak": self.is_weak,
        }


def _sequence_penalty(lowered: str) -> int:
    """Count 3-character ascending/descending runs (abc, 321, qwe ...)."""
    penalty = 0
    for seq in _SEQUENCES:
        for i in range(len(seq) - 2):
            chunk = seq[i : i + 3]
            if chunk in lowered or chunk[::-1] in lowered:
                penalty += 1
    return penalty


def calculate_strength(password: str) -> Strength:
    """Estimate password strength from character pool, length, repeats and common patterns."""
    if not password:
        return Strength(0, LABELS[0], 0.0, ("Password is empty.",))

    has_lower = any("a" <= c <= "z" for c in password)
    has_upper = any("A" <= c <= "Z" for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    pool = 26 * has_lower + 26 * has_upper + 10 * has_digit + 33 * has_symbol
    if any(c.isalpha() and not c.isascii() for c in password):
        pool += 64  # non-ASCII letters widen the alphabet
    pool = max(pool, 10)

    lowered = password.lower()
    unique = len(set(password))
    effective_length = max(1.0, len(password) - 0.5 * (len(password) - unique) - _sequence_penalty(lowered))
    entropy = effective_length * math.log2(pool)

    feedback: list[str] = []
    if lowered in COMMON_PASSWORDS:
        entropy = min(entropy, 10.0)
        feedback.append("This is one of the most commonly used passwords.")
    elif any(fragment in lowered for fragment in COMMON_FRAGMENTS):
        entropy -= 15
        feedback.append("Avoid common words and patterns such as 'password' or 'qwerty'.")

    if len(password) < 12:
        feedback.append("Use at least 12 characters.")
    if sum((has_lower, has_upper, has_digit, has_symbol)) < 3 and len(password) < 16:
        feedback.append("Mix uppercase, lowercase, numbers and symbols.")
    if unique < len(password) / 2:
        feedback.append("Too many repeated characters.")

    entropy = max(0.0, entropy)
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 80:
        score = 3
    else:
        score = 4
    return Strength(score, LABELS[score], round(entropy, 1), tuple(feedback))


def find_duplicates(entries: Iterable[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group entries that share the same password. Each entry needs id, account_name, password."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        if entry.get("password"):
            groups.setdefault(entry["password"], []).append(
                {"id": entry["id"], "account_name": entry["account_name"]}
            )
    return [group for group in groups.values() if len(group) > 1]


def audit_vault(
    entries: list[dict[str, Any]],
    *,
    old_after_days: int = 180,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a vault-wide security report.

    ``entries`` are dicts with id, account_name, password and updated_at (ISO-8601 UTC).
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=old_after_days)

    strengths: dict[int, dict[str, Any]] = {}
    weak: list[dict[str, Any]] = []
    old: list[dict[str, Any]] = []
    for entry in entries:
        strength = calculate_strength(entry["password"])
        strengths[entry["id"]] = strength.as_dict()
        if strength.is_weak:
            weak.append({"id": entry["id"], "account_name": entry["account_name"], "label": strength.label})
        try:
            updated = datetime.strptime(entry["updated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if updated < cutoff:
            old.append({"id": entry["id"], "account_name": entry["account_name"], "updated_at": entry["updated_at"]})

    duplicates = find_duplicates(entries)
    duplicate_count = sum(len(group) for group in duplicates)
    total = len(entries)

    score = None
    if total:
        penalty = (0.5 * len(weak) + 0.3 * duplicate_count + 0.2 * len(old)) / total
        score = max(0, min(100, round(100 * (1 - penalty))))

    return {
        "total": total,
        "strengths": strengths,
        "weak": weak,
        "duplicates": duplicates,
        "duplicate_count": duplicate_count,
        "old": old,
        "old_after_days": old_after_days,
        "score": score,
    }
