"""Errors shared across pgremedy."""

from __future__ import annotations

import requests


class SourceUnavailable(Exception):
    """A data source could not be reached or gave an unusable answer.

    Any result that depends on the source is abandoned when this is raised:
    reporting "no CVEs found" for a lookup that never happened is worse than
    reporting nothing.
    """

    def __init__(self, source: str, reason: str):
        self.source = source
        self.reason = reason
        super().__init__(f"{source}: {reason}")


def describe(exc: BaseException) -> str:
    """A short, readable reason for a failed HTTP request."""
    if isinstance(exc, requests.exceptions.Timeout):
        return "the request timed out"
    if isinstance(exc, requests.exceptions.ProxyError):
        return "the proxy refused the connection"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS handshake failed"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "could not connect"
    text = " ".join(str(exc).split())
    return text[:200] or type(exc).__name__
