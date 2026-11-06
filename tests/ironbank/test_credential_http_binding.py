"""Ironbank proof for host-declared HTTP credential bindings.

A host secret for an API outside the built-in providers reaches the bound
upstream only in the declared header or query key, on the declared host,
method and path. The guest, the ledger and every log hold the reference
only, and every other use of the reference is refused with a ledger record.
"""

from __future__ import annotations

import json
import shlex
from contextlib import closing
from urllib.parse import parse_qs

import pytest
from helpers.gateway import GatewayInstance, TcpHttpClient
from helpers.image_session import image_session, workload_exec
from helpers.mock_server import start_mock_server, stop_process
from helpers.service import ServiceInstance, vm_name, vm_session_dir
from log_streams import read_log_stream

from tests.ironbank.test_credential_store_lifecycle import _credential_reference
from tests.ironbank.test_http_protocol_ledger import (
    EXPECTED_NET_COLUMNS,
    EXPECTED_SUBSTITUTION_COLUMNS,
    _connect_session_db,
    _eventually,
    _table_columns,
)

pytestmark = pytest.mark.integration

BOUND = "api.binding.capsem.test"
LIMITED = "limited.binding.capsem.test"
UNBOUND = "unbound.capsem.test"
HOSTS = (BOUND, LIMITED, UNBOUND)
REFUSED = "credential binding refused"
UNBOUND_REFUSAL = "no provider binding for this destination"

SECRETS = {
    "ib-bearer": "capsem_test_binding_bearer_secret",
    "ib-key": "capsem_test_binding_header_secret",
    "ib-query": "capsem_test_binding_query/secret+value",
    "ib-limited": "capsem_test_binding_limited_secret",
}


def _corp(ready: dict) -> str:
    overrides = "".join(
        f'[network.upstream_overrides."{host}:443"]\ndial = {json.dumps(ready["http_addr"])}\nprotocol = "http"\n'
        for host in HOSTS
    )
    hosts = " || ".join(f'http.host == "{host}"' for host in HOSTS)
    return f'''
refresh_policy = "24h"
[network.dns]
upstreams = [{json.dumps(ready["dns_udp_addr"])}]
{overrides}
[corp.rules.allow_ironbank_credential_bindings]
name = "allow_ironbank_credential_bindings"
action = "allow"
priority = -100
detection_level = "informational"
reason = "Hermetic HTTP credential binding fixture."
match = '({hosts}) && tcp.port == "443" && http.path == "/echo"'

[credential_bindings.ib-bearer]
hosts = ["{BOUND}"]
placement = {{ header = "authorization", scheme = "Bearer" }}
methods = ["POST"]
path_prefixes = ["/"]

[credential_bindings.ib-key]
hosts = ["{BOUND}"]
placement = {{ header = "x-api-key" }}

[credential_bindings.ib-query]
hosts = ["*.binding.capsem.test"]
placement = {{ query = "api_key" }}

[credential_bindings.ib-limited]
hosts = ["{LIMITED}"]
placement = {{ header = "authorization", scheme = "Bearer" }}
methods = ["GET"]
path_prefixes = ["/v1/"]
'''


# Each case: (name, host, headers, query, expected status). Headers and query
# name references by binding id; the workload fills them from its env.
CASES = [
    ("bearer", BOUND, {"authorization": "Bearer {ib-bearer}"}, "", 200),
    ("header", BOUND, {"x-api-key": "{ib-key}"}, "", 200),
    ("query", BOUND, {}, "api_key={ib-query}", 200),
    ("unbound_host", UNBOUND, {"authorization": "Bearer {ib-bearer}"}, "", 502),
    ("other_header", BOUND, {"x-other-key": "{ib-key}"}, "", 502),
    ("wrong_scheme", BOUND, {"authorization": "Token {ib-bearer}"}, "", 502),
    ("wrong_query_key", BOUND, {}, "key={ib-query}", 502),
    ("cross_binding", BOUND, {"x-api-key": "{ib-bearer}"}, "", 502),
    ("method_and_path", LIMITED, {"authorization": "Bearer {ib-limited}"}, "", 502),
]

WORKLOAD = r'''
import json, os, urllib.error, urllib.parse, urllib.request
refs = json.loads(os.environ["IRONBANK_BINDING_REFS"])
cases = json.loads(os.environ["IRONBANK_BINDING_CASES"])
results = {}
for name, host, headers, query, _ in cases:
    headers = {key: value.format(**refs) for key, value in headers.items()}
    query = query.format(**{key: urllib.parse.quote(value, safe="") for key, value in refs.items()})
    url = f"https://{host}/echo" + (f"?{query}" if query else "")
    request = urllib.request.Request(url, data=b"binding proof", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            results[name] = {"status": response.status, "body": json.load(response)}
    except urllib.error.HTTPError as error:
        results[name] = {"status": error.code, "body": error.read().decode()}
print(json.dumps({"results": results, "environment": dict(os.environ)}))
'''


def _inject(client: TcpHttpClient, body: dict) -> tuple[int, dict]:
    return client.call_json("POST", "/credentials/inject", body, timeout=30)


def test_http_credential_bindings_substitute_only_where_declared_blackbox(monkeypatch) -> None:
    service = ServiceInstance()
    gateway = GatewayInstance(uds_path=service.uds_path)
    upstream = None
    markers = tuple(SECRETS.values())
    try:
        upstream, ready = start_mock_server(request_log=service.tmp_dir / "upstream.jsonl")
        assert set(HOSTS) <= set(ready["dns_fixtures"])
        corp = service.tmp_dir / "corp.toml"
        corp.write_text(_corp(ready))
        monkeypatch.setenv("CAPSEM_CORP_CONFIG", str(corp))
        service.start()
        gateway.start()
        client = TcpHttpClient(gateway.base_url, gateway.token)

        # Ingest contract: http needs a declared binding, and only http takes one.
        for body in (
            {"provider": "http", "binding": "undeclared", "value": "capsem_test_refused_a"},
            {"provider": "http", "value": "capsem_test_refused_b"},
            {"provider": "openai", "binding": "ib-key", "value": "capsem_test_refused_c"},
        ):
            status, response = _inject(client, body)
            assert status == 400, (body, response)
            assert "credential_ref" not in response
            assert body["value"] not in json.dumps(response)

        # File-backed material exists before the VM, and its reference is the
        # only thing the workload's configuration ever carries.
        status, response = _inject(client, {
            "provider": "http", "binding": "ib-bearer", "value": SECRETS["ib-bearer"], "storage": "file",
        })
        assert status == 200, response
        assert response == {
            "credential_ref": _credential_reference("http:ib-bearer", SECRETS["ib-bearer"]),
            "storage": "file",
        }
        references = {"ib-bearer": response["credential_ref"]}

        with image_session(service, service.tmp_dir / "registry", vm_name("http-binding"), client=client) as vm_id:
            for binding in ("ib-key", "ib-query", "ib-limited"):
                status, response = _inject(client, {
                    "provider": "http", "binding": binding, "value": SECRETS[binding], "storage": "memory",
                })
                assert status == 200, response
                assert response == {
                    "credential_ref": _credential_reference(f"http:{binding}", SECRETS[binding]),
                    "storage": "memory",
                }
                references[binding] = response["credential_ref"]

            environment = {
                "IRONBANK_BINDING_REFS": json.dumps(references),
                "IRONBANK_BINDING_CASES": json.dumps(CASES),
            }
            command = " ".join(f"{key}={shlex.quote(value)}" for key, value in environment.items())
            command += " python3 -c " + shlex.quote(WORKLOAD)
            assert all(secret not in command for secret in markers)
            result = workload_exec(client, vm_id, command, timeout=120)
            assert result["exit_code"] == 0, result
            output = result["stdout_text"]
            assert all(secret not in output for secret in markers), "a secret reached the guest"
            observed = json.loads(output)["results"]
            assert {name: observed[name]["status"] for name, *_ in CASES} == {
                name: status for name, *_, status in CASES
            }

            echo = {name: observed[name]["body"] for name in ("bearer", "header", "query")}
            assert echo["bearer"]["has_authorization"] is True
            assert echo["bearer"]["authorization_is_broker_ref"] is False
            assert echo["header"]["has_x_api_key"] is True
            assert echo["query"]["query_has_broker_ref"] is False
            for name, host, *_ in CASES[3:]:
                body = observed[name]["body"]
                assert (UNBOUND_REFUSAL if host == UNBOUND else REFUSED) in body, (name, body)

            # Upstream saw raw material for the three admitted requests and
            # nothing at all for the refused ones.
            records = [json.loads(line) for line in (service.tmp_dir / "upstream.jsonl").read_text().splitlines()]
            requests = [row for row in records if row.get("path") == "/echo"]
            assert len(requests) == 3, requests
            bearer, header, query = requests
            assert bearer["headers"]["authorization"] == "Bearer " + SECRETS["ib-bearer"]
            assert header["headers"]["x-api-key"] == SECRETS["ib-key"]
            assert parse_qs(query["query"]) == {"api_key": [SECRETS["ib-query"]]}
            transcript = json.dumps(requests)
            assert "credential:blake3:" not in transcript
            assert SECRETS["ib-limited"] not in transcript

            with closing(_connect_session_db(service, vm_id)) as ledger:
                assert _table_columns(ledger, "net_events") == EXPECTED_NET_COLUMNS
                assert _table_columns(ledger, "substitution_events") == EXPECTED_SUBSTITUTION_COLUMNS
                rows = _eventually(lambda: ledger.execute(
                    "SELECT * FROM net_events WHERE path='/echo' ORDER BY id"
                ).fetchall(), lambda rows: len(rows) == len(CASES))
                expected_refs = {
                    "bearer": "ib-bearer", "header": "ib-key", "query": "ib-query",
                    "unbound_host": "ib-bearer", "other_header": "ib-key", "wrong_scheme": "ib-bearer",
                    "wrong_query_key": "ib-query", "cross_binding": "ib-bearer", "method_and_path": "ib-limited",
                }
                for row, (name, host, _, _, status) in zip(rows, CASES, strict=True):
                    assert row["domain"] == host and row["port"] == 443, name
                    assert row["method"] == "POST" and row["conn_type"] == "https-mitm", name
                    assert row["status_code"] == status, name
                    assert row["credential_ref"] == references[expected_refs[name]], name
                    assert row["event_id"] and row["trace_id"], name
                    if status == 200:
                        assert row["decision"] == "allowed", name
                        assert row["policy_rule"] == "corp.rules.allow_ironbank_credential_bindings", name
                    else:
                        assert row["decision"] == "error", name
                        refusal = UNBOUND_REFUSAL if host == UNBOUND else REFUSED
                        assert refusal in row["matched_rule"], (name, row["matched_rule"])
                injections = ledger.execute(
                    "SELECT provider, substitution_ref, source FROM substitution_events "
                    "WHERE outcome='injected' ORDER BY id"
                ).fetchall()
                # Each admitted use names the binding it went through; refused
                # requests write no injection.
                assert [tuple(row) for row in injections] == [
                    ("http:ib-bearer", references["ib-bearer"], "http.header.authorization"),
                    ("http:ib-key", references["ib-key"], "http.header.x-api-key"),
                    ("http:ib-query", references["ib-query"], "http.query.api_key"),
                ]
                for table in ("net_events", "security_rule_events", "substitution_events"):
                    serialized = repr([tuple(row) for row in ledger.execute(f"SELECT * FROM {table}")])
                    assert all(secret not in serialized for secret in markers), table

            info = client.get("/plugins/credential_broker/credentials/info")
            assert all(secret not in json.dumps(info) for secret in markers)
            session = vm_session_dir(service.tmp_dir, client, vm_id)
            for name in ("process.log", "owner/logs/serial.log"):
                text = read_log_stream(session / name)
                assert text, name
                assert all(secret not in text for secret in markers), name

        store = service.home_dir / "credential-store.json"
        persisted = store.read_text()
        assert SECRETS["ib-bearer"] in persisted, "file storage persists"
        assert all(SECRETS[binding] not in persisted for binding in ("ib-key", "ib-query", "ib-limited"))
        gateway_log = gateway.stop_and_read_log()
        service_log = service.stop_and_read_log()
        assert all(secret not in gateway_log + service_log for secret in markers)
        for log in service.tmp_dir.rglob("*.log"):
            assert all(secret not in read_log_stream(log) for secret in markers), log
    finally:
        gateway.stop()
        service.stop()
        stop_process(upstream)
