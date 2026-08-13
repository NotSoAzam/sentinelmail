"""
Certificate Transparency provider via crt.sh.

CT logs are public-by-design (every publicly trusted TLS cert is logged
there). This surfaces subdomains that have had certificates issued —
useful for understanding a domain's real infrastructure footprint —
without touching anything private.
"""
from __future__ import annotations

import requests

from sentinelmail.models import Category, Confidence, Finding, InvestigationResult
from sentinelmail.providers.base import Provider

CRTSH_URL = "https://crt.sh/?q={domain}&output=json"


class CertificateTransparencyProvider(Provider):
    name = "crtsh"
    requires_api_key = False

    def is_available(self) -> bool:
        return True

    def collect(self, result: InvestigationResult) -> None:
        domain = result.domain
        try:
            resp = requests.get(CRTSH_URL.format(domain=domain), timeout=15)
            if resp.status_code != 200 or not resp.text.strip():
                result.add(Finding(
                    category=Category.CERTIFICATE,
                    description="No certificate transparency data returned",
                    source="crt.sh",
                    confidence=Confidence.UNVERIFIED,
                    provider=self.name,
                ))
                return

            entries = resp.json()
            subdomains = set()
            for entry in entries:
                name_value = entry.get("name_value", "")
                for line in name_value.split("\n"):
                    line = line.strip().lower()
                    if line and not line.startswith("*"):
                        subdomains.add(line)

            if subdomains:
                sample = sorted(subdomains)[:25]
                result.add(Finding(
                    category=Category.CERTIFICATE,
                    description=f"{len(subdomains)} distinct hostname(s) found in public certificate logs",
                    source="crt.sh (Certificate Transparency logs)",
                    confidence=Confidence.VERIFIED,
                    evidence=", ".join(sample) + (" ... (truncated)" if len(subdomains) > 25 else ""),
                    url=f"https://crt.sh/?q={domain}",
                    provider=self.name,
                ))
            else:
                result.add(Finding(
                    category=Category.CERTIFICATE,
                    description="No hostnames found in certificate transparency logs",
                    source="crt.sh",
                    confidence=Confidence.VERIFIED,
                    provider=self.name,
                ))

        except Exception as exc:
            result.errors.append(f"[crtsh] {exc}")
