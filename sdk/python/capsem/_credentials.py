"""Explicit host credential injection; returns only opaque broker references."""
from __future__ import annotations

from . import _operations as api
from . import models
from ._transport import Transport


class Credentials:
    def __init__(self, transport: Transport) -> None:
        self._transport = transport

    async def inject(
        self, provider: str, value: str, *, storage: str = "file",
        binding: str | None = None, request_timeout: float | None = None,
    ) -> models.CredentialInjectResponse:
        """Register host material and use its reference in a VM environment.

        Memory storage lasts for this service lifetime. This operation never
        retries or starts consent, and does not refresh supplied OAuth tokens.
        Provider ``"http"`` requires ``binding``, the id of a host-declared
        ``[credential_bindings.<id>]`` entry; the reference works only there.
        """
        if not isinstance(value, str) or not value:
            raise ValueError("credential value must be a nonempty string")
        if (provider == "http") != (isinstance(binding, str) and bool(binding)):
            raise ValueError("a credential binding is required with, and only with, provider http")
        try:
            wire_provider = models.CredentialInjectProvider(provider)
            wire_storage = models.CredentialStorage(storage)
        except (ValueError, TypeError):
            raise ValueError("invalid credential provider or storage") from None
        return await api.inject_credential(
            self._transport,
            body=models.CredentialInjectRequest(
                provider=wire_provider, value=value, storage=wire_storage,
                **({} if binding is None else {"binding": binding}),
            ),
            request_timeout=request_timeout,
        )
