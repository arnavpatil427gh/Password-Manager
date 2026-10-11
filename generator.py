import secrets
import string

SYMBOLS = "@$%^&*!?-_"


def generate_password(length=16, lower=True, upper=True, digits=True, symbols=True):
    """Uniform pick from one combined pool, with at least one char per chosen category."""
    pools = [p for on, p in ((lower, string.ascii_lowercase), (upper, string.ascii_uppercase),
                             (digits, string.digits), (symbols, SYMBOLS)) if on]
    if not pools:
        raise ValueError("Select at least one character type.")
    if length < len(pools):
        raise ValueError("Length is too short for the selected character types.")
    allowed = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(allowed) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
