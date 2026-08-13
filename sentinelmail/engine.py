"""Runs all registered providers against a validated email and returns results."""
from __future__ import annotations

from sentinelmail.models import Category, Confidence, Finding, InvestigationResult
from sentinelmail.providers import ALL_PROVIDERS
from sentinelmail.validation import validate_and_normalize


def run_investigation(email: str, progress_callback=None) -> InvestigationResult:
    normalized, local_part, domain = validate_and_normalize(email)
    result = InvestigationResult(email=normalized, local_part=local_part, domain=domain)

    result.add(Finding(
        category=Category.EMAIL_VALIDATION,
        description="Email address is syntactically valid",
        source="SentinelMail validator",
        confidence=Confidence.VERIFIED,
        evidence=f"local_part='{local_part}', domain='{domain}'",
        provider="core",
    ))

    for provider_cls in ALL_PROVIDERS:
        provider = provider_cls()
        if progress_callback:
            progress_callback(provider.name, "running")

        if not provider.is_available():
            if provider.requires_api_key:
                if progress_callback:
                    progress_callback(provider.name, "skipped (no api key)")
                continue

        try:
            provider.collect(result)
        except Exception as exc:  # provider promised not to raise, but be defensive anyway
            result.errors.append(f"[{provider.name}] unexpected error: {exc}")

        if progress_callback:
            progress_callback(provider.name, "done")

    return result
