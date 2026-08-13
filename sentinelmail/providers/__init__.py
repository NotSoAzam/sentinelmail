from sentinelmail.providers.base import Provider
from sentinelmail.providers.crtsh_provider import CertificateTransparencyProvider
from sentinelmail.providers.dns_provider import DNSProvider
from sentinelmail.providers.github_provider import GitHubProvider
from sentinelmail.providers.gravatar_provider import GravatarProvider
from sentinelmail.providers.hibp_provider import HIBPProvider
from sentinelmail.providers.rdap_provider import RDAPProvider
from sentinelmail.providers.reputation_provider import ReputationProvider

# Order matters only for display; all providers run independently.
ALL_PROVIDERS: list[type[Provider]] = [
    DNSProvider,
    RDAPProvider,
    CertificateTransparencyProvider,
    ReputationProvider,
    GravatarProvider,
    GitHubProvider,
    HIBPProvider,
]

__all__ = ["Provider", "ALL_PROVIDERS"]
