"""
GitHub provider.

Uses GitHub's public commit-search API to find commits whose author
metadata is exactly this email address. This is metadata developers
have chosen to make public by pushing to public repos with `git config
user.email` set — it is not enumeration and does not touch private
data. An optional GITHUB_TOKEN raises the (very low) unauthenticated
rate limit but is not required.
"""
from __future__ import annotations

import os

import requests

from sentinelmail.models import Category, Confidence, Finding, InvestigationResult
from sentinelmail.providers.base import Provider

SEARCH_URL = "https://api.github.com/search/commits"


class GitHubProvider(Provider):
    name = "github"
    requires_api_key = False  # works unauthenticated, just rate-limited harder

    def is_available(self) -> bool:
        return True

    def collect(self, result: InvestigationResult) -> None:
        try:
            headers = {"Accept": "application/vnd.github.cloak-preview+json"}
            token = os.environ.get("GITHUB_TOKEN")
            if token:
                headers["Authorization"] = f"token {token}"

            params = {"q": f"author-email:{result.email}", "per_page": 5}
            resp = requests.get(SEARCH_URL, params=params, headers=headers, timeout=10)

            if resp.status_code == 403:
                result.add(Finding(
                    category=Category.PUBLIC_PROFILE,
                    description="GitHub commit search skipped (rate limited)",
                    source="GitHub Search API",
                    confidence=Confidence.UNVERIFIED,
                    evidence="Unauthenticated GitHub search has a low rate limit. "
                             "Set GITHUB_TOKEN to increase it.",
                    provider=self.name,
                ))
                return

            if resp.status_code != 200:
                result.add(Finding(
                    category=Category.PUBLIC_PROFILE,
                    description="GitHub commit search returned no usable data",
                    source="GitHub Search API",
                    confidence=Confidence.UNVERIFIED,
                    evidence=f"HTTP {resp.status_code}",
                    provider=self.name,
                ))
                return

            data = resp.json()
            total = data.get("total_count", 0)
            items = data.get("items", [])

            if total == 0:
                result.add(Finding(
                    category=Category.PUBLIC_PROFILE,
                    description="No public GitHub commits found with this exact author email",
                    source="GitHub Search API",
                    confidence=Confidence.VERIFIED,
                    provider=self.name,
                ))
                return

            usernames = set()
            repos = set()
            for item in items:
                author = item.get("author") or {}
                if author.get("login"):
                    usernames.add(author["login"])
                repo = item.get("repository", {}).get("full_name")
                if repo:
                    repos.add(repo)

            result.add(Finding(
                category=Category.PUBLIC_PROFILE,
                description=f"Found {total} public commit(s) authored with this email",
                source="GitHub Search API (public commit metadata)",
                confidence=Confidence.HIGH,
                url=f"https://github.com/search?q=author-email:{result.email}&type=commits",
                evidence=(f"Associated GitHub username(s): {', '.join(sorted(usernames))}. "
                          if usernames else "Author account not linked to a GitHub username. ")
                         + (f"Sample repos: {', '.join(sorted(repos)[:5])}" if repos else ""),
                provider=self.name,
            ))

        except Exception as exc:
            result.errors.append(f"[github] {exc}")
