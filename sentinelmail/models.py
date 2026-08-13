"""
Core data models used throughout SentinelMail.

Every fact the tool reports is wrapped in a Finding object so the
evidence, source, and confidence travel with the claim instead of
being lost in free-text output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Confidence(str, Enum):
    VERIFIED = "VERIFIED"     # Confirmed directly by an authoritative source (e.g. DNS record)
    HIGH = "HIGH"             # Strong, specific match (e.g. exact email in public commit metadata)
    MEDIUM = "MEDIUM"         # Plausible but not conclusive (e.g. username pattern match)
    LOW = "LOW"               # Weak signal, included for completeness only
    UNVERIFIED = "UNVERIFIED" # Could not be checked (e.g. API key missing)


class Category(str, Enum):
    EMAIL_VALIDATION = "email_validation"
    DOMAIN_DNS = "domain_dns"
    DOMAIN_SECURITY = "domain_security"
    MAIL_PROVIDER = "mail_provider"
    PUBLIC_PROFILE = "public_profile"
    BREACH_EXPOSURE = "breach_exposure"
    REPUTATION = "reputation"
    AVATAR = "avatar"
    CERTIFICATE = "certificate_transparency"


@dataclass
class Finding:
    """A single, sourced piece of intelligence."""
    category: Category
    description: str
    source: str
    confidence: Confidence
    url: Optional[str] = None
    evidence: Optional[str] = None
    provider: str = "sentinelmail"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "description": self.description,
            "source": self.source,
            "confidence": self.confidence.value,
            "url": self.url,
            "evidence": self.evidence,
            "provider": self.provider,
            "first_seen": self.first_seen.isoformat(),
        }


@dataclass
class InvestigationResult:
    email: str
    local_part: str
    domain: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def by_category(self, category: Category) -> list[Finding]:
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "local_part": self.local_part,
            "domain": self.domain,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
