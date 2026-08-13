"""Email validation & normalization."""
from __future__ import annotations

import re

EMAIL_RE = re.compile(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
                       r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


class InvalidEmailError(ValueError):
    pass


def validate_and_normalize(email: str) -> tuple[str, str, str]:
    """
    Returns (normalized_email, local_part, domain).
    Raises InvalidEmailError if the address is malformed.
    """
    email = email.strip()
    if not EMAIL_RE.match(email):
        raise InvalidEmailError(f"'{email}' is not a syntactically valid email address")

    local_part, domain = email.rsplit("@", 1)
    domain = domain.lower()
    normalized = f"{local_part}@{domain}"
    return normalized, local_part, domain
