"""
DNS / mail-security provider.

Uses only standard public DNS resolution (dnspython) — no private data,
no authentication, no rate-limited third-party API required. This is
the same information any mail server on the internet already queries.
"""
from __future__ import annotations

import dns.resolver

from sentinelmail.models import Category, Confidence, Finding, InvestigationResult
from sentinelmail.providers.base import Provider

KNOWN_MAIL_PROVIDERS = {
    "google.com": "Gmail / Google Workspace",
    "googlemail.com": "Gmail / Google Workspace",
    "outlook.com": "Microsoft 365 / Outlook",
    "protection.outlook.com": "Microsoft 365 / Outlook",
    "proton.me": "Proton Mail",
    "protonmail.ch": "Proton Mail",
    "zoho.com": "Zoho Mail",
    "mail.zoho.com": "Zoho Mail",
}


class DNSProvider(Provider):
    name = "dns"
    requires_api_key = False

    def is_available(self) -> bool:
        return True

    def _query(self, domain: str, rtype: str) -> list[str]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5.0)
            return [r.to_text() for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        except Exception:
            return []

    def collect(self, result: InvestigationResult) -> None:
        domain = result.domain
        try:
            mx_records = self._query(domain, "MX")
            a_records = self._query(domain, "A")
            aaaa_records = self._query(domain, "AAAA")
            ns_records = self._query(domain, "NS")
            txt_records = self._query(domain, "TXT")
            caa_records = self._query(domain, "CAA")

            result.add(Finding(
                category=Category.DOMAIN_DNS,
                description=f"MX records: {'present' if mx_records else 'absent'}"
                            + (f" ({len(mx_records)} record(s))" if mx_records else ""),
                source="DNS (MX lookup)",
                confidence=Confidence.VERIFIED,
                evidence="; ".join(mx_records) if mx_records else "No MX records resolved",
                provider=self.name,
            ))

            if a_records or aaaa_records:
                result.add(Finding(
                    category=Category.DOMAIN_DNS,
                    description="Domain resolves to an IP address",
                    source="DNS (A/AAAA lookup)",
                    confidence=Confidence.VERIFIED,
                    evidence=", ".join(a_records + aaaa_records),
                    provider=self.name,
                ))

            if ns_records:
                result.add(Finding(
                    category=Category.DOMAIN_DNS,
                    description=f"{len(ns_records)} nameserver(s) found",
                    source="DNS (NS lookup)",
                    confidence=Confidence.VERIFIED,
                    evidence="; ".join(ns_records),
                    provider=self.name,
                ))

            spf = [t for t in txt_records if "v=spf1" in t.lower()]
            result.add(Finding(
                category=Category.DOMAIN_SECURITY,
                description=f"SPF: {'present' if spf else 'not found'}",
                source="DNS (TXT lookup)",
                confidence=Confidence.VERIFIED,
                evidence=spf[0] if spf else "No v=spf1 record in domain TXT records",
                provider=self.name,
            ))

            dmarc_records = self._query(f"_dmarc.{domain}", "TXT")
            dmarc = [t for t in dmarc_records if "v=dmarc1" in t.lower()]
            result.add(Finding(
                category=Category.DOMAIN_SECURITY,
                description=f"DMARC: {'present' if dmarc else 'not found'}",
                source="DNS (_dmarc TXT lookup)",
                confidence=Confidence.VERIFIED,
                evidence=dmarc[0] if dmarc else f"No TXT record at _dmarc.{domain}",
                provider=self.name,
            ))

            result.add(Finding(
                category=Category.DOMAIN_SECURITY,
                description=f"CAA: {'present' if caa_records else 'not found'}",
                source="DNS (CAA lookup)",
                confidence=Confidence.VERIFIED,
                evidence="; ".join(caa_records) if caa_records else "No CAA records — any CA may issue certs for this domain",
                provider=self.name,
            ))

            # DKIM has no fixed selector, so we can only say it's unverifiable
            # without knowing the selector the domain uses.
            result.add(Finding(
                category=Category.DOMAIN_SECURITY,
                description="DKIM: cannot verify without a known selector",
                source="DNS",
                confidence=Confidence.UNVERIFIED,
                evidence="DKIM selectors are not discoverable from the domain alone; "
                         "would require a sample email header to identify the selector.",
                provider=self.name,
            ))

            # Mail provider detection from MX hostnames
            provider_label = None
            for mx in mx_records:
                mx_lower = mx.lower()
                for suffix, label in KNOWN_MAIL_PROVIDERS.items():
                    if suffix in mx_lower:
                        provider_label = label
                        break
                if provider_label:
                    break

            if provider_label:
                result.add(Finding(
                    category=Category.MAIL_PROVIDER,
                    description=f"Mail provider appears to be {provider_label}",
                    source="DNS (MX hostname pattern)",
                    confidence=Confidence.HIGH,
                    evidence="; ".join(mx_records),
                    provider=self.name,
                ))
            elif mx_records:
                result.add(Finding(
                    category=Category.MAIL_PROVIDER,
                    description="Mail provider appears to be self-hosted or a provider not in the known-pattern list",
                    source="DNS (MX hostname pattern)",
                    confidence=Confidence.MEDIUM,
                    evidence="; ".join(mx_records),
                    provider=self.name,
                ))

        except Exception as exc:  # pragma: no cover - defensive
            result.errors.append(f"[dns] {exc}")
