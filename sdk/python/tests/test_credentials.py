"""Credential injection is one authenticated request and returns no material."""
import asyncio

import pytest
from capsem import HttpError, Hypervisor

from .test_images import gateway


def test_injection_file_and_memory_preserve_exact_host_request_and_reference():
    async def run():
        reference = "credential:blake3:" + "a" * 64
        for storage in ["file", "memory"]:
            async with gateway(response={"credential_ref": reference, "storage": storage}) as (url, received):
                async with Hypervisor(url, "gateway-token") as hv:
                    response = await hv.credentials.inject("openai", "private-test-key", storage=storage)
                    assert response.credential_ref == reference
                    assert response.storage == storage
                    assert "private-test-key" not in repr(response)
                assert received == [("POST", "/credentials/inject", {
                    "provider": "openai", "value": "private-test-key", "storage": storage,
                })]
    asyncio.run(run())


def test_injection_refusal_is_not_replayed():
    async def run():
        async with gateway(response={"error": "credential handoff unavailable"}, status=503) as (url, received), Hypervisor(url, "gateway-token") as hv:
            with pytest.raises(HttpError):
                await hv.credentials.inject("google", "private-test-key", storage="memory")
            assert len(received) == 1
    asyncio.run(run())


def test_bound_injection_names_its_binding_and_requires_it_only_for_http():
    async def run():
        reference = "credential:blake3:" + "b" * 64
        async with gateway(response={"credential_ref": reference, "storage": "file"}) as (url, received):
            async with Hypervisor(url, "gateway-token") as hv:
                response = await hv.credentials.inject("http", "private-bound-key", binding="stripe")
                assert response.credential_ref == reference
                for provider, binding in [("http", None), ("http", ""), ("openai", "stripe")]:
                    with pytest.raises(ValueError):
                        await hv.credentials.inject(provider, "private-bound-key", binding=binding)
            assert received == [("POST", "/credentials/inject", {
                "provider": "http", "binding": "stripe", "value": "private-bound-key", "storage": "file",
            })]
    asyncio.run(run())
