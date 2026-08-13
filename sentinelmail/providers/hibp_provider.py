"""
HaveIBeenPwned provider.

HIBP is the legitimate, widely-trusted breach-notification service.
As of their API v3 it requires a paid subscription key (their revenue
model, not a workaround) — SentinelMail reads it from the
HIBP_API_KEY environment variable if you have one. Without a key this
provider clearly reports itself as unavailable rather than silently
skipping or faking data.

We only ever surface: service name, breach date, and the categories
of data exposed (e.g. "Email addresses, Passwords") as returned by
HIBP itself — never actual passwords, hashes, or tokens, which HIBP's
API does not expose anyway.
"""
from __future__ import annotations

import os

import requests

from sentinelmail.models import Category, Confidence, Finding, InvestigationResult
from sentinelmail.providers.base import Provider

HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"


class HIBPProvider(Provider):
    name = "hibp"
    requires_api_key = True

    def is_available(self) -> bool:
        return bool(os.environ.get("HIBP_API_KEY"))

    def collect(self, result: InvestigationResult) -> None:
        api_key = os.environ.get("HIBP_API_KEY")
        if not api_key:
            result.add(Finding(
                category=Category.BREACH_EXPOSURE,
                description="Breach check skipped: no HIBP_API_KEY configured",
                source="HaveIBeenPwned",
                confidence=Confidence.UNVERIFIED,
                evidence="Get a key at https://haveibeenpwned.com/API/Key and set "
                         "HIBP_API_KEY to enable this check. SentinelMail never uses "
                         "unofficial or scraped breach data.",
                provider=self.name,
            ))
            return

        try:
            headers = {"hibp-api-key": api_key, "user-agent": "SentinelMail-OSINT-Tool"}
            resp = requests.get(
                HIBP_URL.format(email=result.email),
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=10,
            )

            if resp.status_code == 404:
                result.add(Finding(
                    category=Category.BREACH_EXPOSURE,
                    description="No known breaches found for this email",
                    source="HaveIBeenPwned API",
                    confidence=Confidence.VERIFIED,
                    provider=self.name,
                ))
                return

            if resp.status_code == 401:
                result.add(Finding(
                    category=Category.BREACH_EXPOSURE,
                    description="Breach check failed: invalid HIBP_API_KEY",
                    source="HaveIBeenPwned API",
                    confidence=Confidence.UNVERIFIED,
                    provider=self.name,
                ))
                return

            if resp.status_code == 429:
                result.add(Finding(
                    category=Category.BREACH_EXPOSURE,
                    description="Breach check rate-limited by HIBP, try again shortly",
                    source="HaveIBeenPwned API",
                    confidence=Confidence.UNVERIFIED,
                    provider=self.name,
                ))
                return

            if resp.status_code != 200:
                result.errors.append(f"[hibp] unexpected status {resp.status_code}")
                return

            breaches = resp.json()
            for breach in breaches:
                data_classes = ", ".join(breach.get("DataClasses", []))
                result.add(Finding(
                    category=Category.BREACH_EXPOSURE,
                    description=f"Exposure found: {breach.get('Name')} ({breach.get('BreachDate', 'date unknown')})",
                    source="HaveIBeenPwned API",
                    confidence=Confidence.VERIFIED,
                    url="https://haveibeenpwned.com/PwnedWebsites",
                    evidence=f"Data categories exposed: {data_classes}. "
                             f"Password/credential data is never displayed by this tool.",
                    provider=self.name,
                ))

        except Exception as exc:
            result.errors.append(f"[hibp] {exc}")
