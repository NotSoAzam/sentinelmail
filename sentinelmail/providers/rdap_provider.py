"""
RDAP provider — domain registration data via the free, public RDAP
protocol (the modern, structured replacement for WHOIS). No API key,
no scraping; RDAP.org bootstraps the request to the correct registry.
"""
from __future__ import annotations

import requests

from sentinelmail.models import Category, Confidence, Finding, InvestigationResult
from sentinelmail.providers.base import Provider

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"


class RDAPProvider(Provider):
    name = "rdap"
    requires_api_key = False

    def is_available(self) -> bool:
        return True

    def collect(self, result: InvestigationResult) -> None:
        domain = result.domain
        try:
            resp = requests.get(RDAP_BOOTSTRAP.format(domain=domain), timeout=8,
                                 headers={"Accept": "application/rdap+json"})
            if resp.status_code != 200:
                result.add(Finding(
                    category=Category.DOMAIN_SECURITY,
                    description="RDAP registration data not available for this domain",
                    source="RDAP",
                    confidence=Confidence.UNVERIFIED,
                    evidence=f"HTTP {resp.status_code} from rdap.org",
                    provider=self.name,
                ))
                return

            data = resp.json()
            events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
            registration_date = events.get("registration")
            expiration_date = events.get("expiration")
            statuses = data.get("status", [])
            entities = data.get("entities", [])

            registrar = None
            for entity in entities:
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray")
                    if vcard and len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                registrar = field[3]

            desc_parts = []
            if registration_date:
                desc_parts.append(f"registered {registration_date[:10]}")
            if expiration_date:
                desc_parts.append(f"expires {expiration_date[:10]}")
            description = "Domain registration: " + (", ".join(desc_parts) if desc_parts else "dates not disclosed by registry")

            result.add(Finding(
                category=Category.DOMAIN_SECURITY,
                description=description,
                source="RDAP (public registry data)",
                confidence=Confidence.VERIFIED,
                evidence=f"Registrar: {registrar or 'not disclosed'}; Status: {', '.join(statuses) if statuses else 'none listed'}",
                url=RDAP_BOOTSTRAP.format(domain=domain),
                provider=self.name,
            ))

        except Exception as exc:
            result.errors.append(f"[rdap] {exc}")
