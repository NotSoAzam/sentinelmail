"""
Reputation provider — disposable/throwaway email domain detection.

Uses the free, public disposable-email-domains list (open-source,
community-maintained) fetched once and cached locally. No API key,
no per-lookup external call to a third party for this signal.
"""
from __future__ import annotations

import time
from pathlib import Path

import requests

from sentinelmail.models import Category, Confidence, Finding, InvestigationResult
from sentinelmail.providers.base import Provider

DISPOSABLE_LIST_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/"
    "disposable-email-domains/master/disposable_email_blocklist.conf"
)
CACHE_PATH = Path.home() / ".cache" / "sentinelmail" / "disposable_domains.txt"
CACHE_TTL_SECONDS = 24 * 60 * 60


class ReputationProvider(Provider):
    name = "reputation"
    requires_api_key = False

    def is_available(self) -> bool:
        return True

    def _load_disposable_domains(self) -> set[str]:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        if CACHE_PATH.exists() and (time.time() - CACHE_PATH.stat().st_mtime) < CACHE_TTL_SECONDS:
            return set(CACHE_PATH.read_text().splitlines())

        resp = requests.get(DISPOSABLE_LIST_URL, timeout=10)
        resp.raise_for_status()
        domains = {line.strip().lower() for line in resp.text.splitlines() if line.strip()}
        CACHE_PATH.write_text("\n".join(sorted(domains)))
        return domains

    def collect(self, result: InvestigationResult) -> None:
        try:
            disposable = self._load_disposable_domains()
            is_disposable = result.domain.lower() in disposable

            result.add(Finding(
                category=Category.REPUTATION,
                description=f"Disposable/throwaway domain: {'YES' if is_disposable else 'no'}",
                source="Community disposable-domain blocklist",
                confidence=Confidence.HIGH if is_disposable else Confidence.MEDIUM,
                url="https://github.com/disposable-email-domains/disposable-email-domains",
                evidence="Domain matched a known disposable-email provider list."
                         if is_disposable else
                         "Domain not present in the known disposable-email list "
                         "(absence from the list is not proof of legitimacy).",
                provider=self.name,
            ))
        except Exception as exc:
            result.errors.append(f"[reputation] {exc}")
