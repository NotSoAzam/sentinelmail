"""
Common interface every intelligence provider implements.

Adding a new legitimate data source means writing one class here and
registering it in providers/__init__.py — the core engine and CLI
never need to change.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from sentinelmail.models import InvestigationResult


class Provider(ABC):
    name: str = "base"
    #: Set to True if this provider needs an API key that may not be present.
    requires_api_key: bool = False

    @abstractmethod
    def is_available(self) -> bool:
        """Return False if required config (e.g. API key) is missing."""
        raise NotImplementedError

    @abstractmethod
    def collect(self, result: InvestigationResult) -> None:
        """
        Run the provider's checks and append Finding objects to `result`.
        Must never raise — providers catch and record their own errors
        in result.errors so one failing source doesn't kill the run.
        """
        raise NotImplementedError
