"""Cryptographically secure password generator (uses the ``secrets`` module only)."""
from __future__ import annotations

import secrets
import string

UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
AMBIGUOUS = "Il1O0o"

MIN_LENGTH = 8
MAX_LENGTH = 128


def generate_password(
    length: int = 20,
    *,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Return a random password containing at least one character of every selected type."""
    if not isinstance(length, int) or not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    pools = [
        pool
        for enabled, pool in (
            (use_upper, UPPERCASE),
            (use_lower, LOWERCASE),
            (use_digits, DIGITS),
            (use_symbols, SYMBOLS),
        )
        if enabled
    ]
    if not pools:
        raise ValueError("Select at least one character type.")
    if exclude_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    # Guarantee one character from each selected pool, fill the rest from the union.
    chars = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
