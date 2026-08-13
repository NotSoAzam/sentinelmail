"""
Transparent risk scoring.

The score is a simple, documented sum of weighted signals — never an
opaque or invented number. Every contribution is returned alongside
the total so the CLI/report can show exactly why the score is what it is.
"""
from __future__ import annotations

from dataclasses import dataclass

from sentinelmail.models import Category, Confidence, InvestigationResult


@dataclass
class RiskContribution:
    reason: str
    points: int


def score_investigation(result: InvestigationResult) -> tuple[int, list[RiskContribution]]:
    contributions: list[RiskContribution] = []

    # Breach exposure — biggest weight, one point of exposure counts,
    # more breaches count more but with diminishing weight.
    breach_findings = [
        f for f in result.by_category(Category.BREACH_EXPOSURE)
        if f.confidence == Confidence.VERIFIED and "Exposure found" in f.description
    ]
    if breach_findings:
        pts = min(40, 15 + 5 * (len(breach_findings) - 1))
        contributions.append(RiskContribution(
            f"{len(breach_findings)} confirmed breach exposure(s)", pts))

    # Disposable domain -> low risk to the *person*, but flagged for context
    for f in result.by_category(Category.REPUTATION):
        if "YES" in f.description:
            contributions.append(RiskContribution("Domain is a known disposable/throwaway provider", 10))

    # Missing SPF/DMARC = domain security weakness (relevant if investigating your own domain)
    for f in result.by_category(Category.DOMAIN_SECURITY):
        if f.description.startswith("SPF: not found"):
            contributions.append(RiskContribution("No SPF record on domain", 8))
        if f.description.startswith("DMARC: not found"):
            contributions.append(RiskContribution("No DMARC record on domain", 8))

    # Public exposure surface
    public_high_conf = [
        f for f in result.by_category(Category.PUBLIC_PROFILE)
        if f.confidence in (Confidence.HIGH, Confidence.VERIFIED) and "Found" in f.description
    ]
    if public_high_conf:
        contributions.append(RiskContribution(
            "Email appears in publicly indexed developer metadata (e.g. GitHub commits)", 10))

    total = min(100, sum(c.points for c in contributions))
    return total, contributions


def risk_label(score: int) -> str:
    if score <= 20:
        return "Very Low"
    if score <= 40:
        return "Low"
    if score <= 60:
        return "Moderate"
    if score <= 80:
        return "High"
    return "Critical"
