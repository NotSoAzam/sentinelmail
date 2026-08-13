"""
Gravatar provider.

Gravatar is opt-in: a person must have deliberately created a public
profile tied to an MD5/SHA256 hash of their email. We only report
existence + explicitly public profile fields Gravatar itself serves,
and always label it as a "publicly associated avatar", per spec.
"""
from __future__ import annotations

import hashlib

import requests

from sentinelmail.models import Category, Confidence, Finding, InvestigationResult
from sentinelmail.providers.base import Provider


class GravatarProvider(Provider):
    name = "gravatar"
    requires_api_key = False

    def is_available(self) -> bool:
        return True

    def collect(self, result: InvestigationResult) -> None:
        try:
            normalized = result.email.strip().lower()
            email_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
            profile_url = f"https://en.gravatar.com/{email_hash}.json"

            resp = requests.get(profile_url, timeout=8)
            if resp.status_code == 200:
                data = resp.json().get("entry", [{}])[0]
                display_name = data.get("displayName")
                profile_link = data.get("profileUrl")
                result.add(Finding(
                    category=Category.AVATAR,
                    description="Publicly associated avatar / profile found on Gravatar",
                    source="Gravatar (public profile API)",
                    confidence=Confidence.HIGH,
                    url=profile_link or f"https://gravatar.com/{email_hash}",
                    evidence=f"Display name: {display_name}" if display_name else "Profile exists; no display name set",
                    provider=self.name,
                ))
            else:
                result.add(Finding(
                    category=Category.AVATAR,
                    description="No public Gravatar profile associated with this email",
                    source="Gravatar",
                    confidence=Confidence.VERIFIED,
                    provider=self.name,
                ))
        except Exception as exc:
            result.errors.append(f"[gravatar] {exc}")
