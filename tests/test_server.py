import ipaddress
import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization

from proxy_runtime import _native_request, _signed
from server import Rejected, Server
from server_config import load

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def pair(tmp_path):
    out = tmp_path / "pair"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/create_pair.py"),
            "--deployment-mode",
            "test",
            "--edge-peer-cidr",
            "127.0.0.1/32",
            "--edge-id",
            "edge-test",
            "--proxy-id",
            "proxy-test",
            "--endpoint-id",
            "endpoint-test",
            "--source-ip",
            "127.0.0.1",
            "--server-name",
            "proxy.test",
            "--allowed-destination-cidr",
            "127.0.0.1/32",
            "--output",
            str(out),
        ],
        check=True,
        capture_output=True,
    )
    p = out / "proxy/config.json"
    cfg = json.loads(p.read_text())
    for key in ["ca_file", "server_cert", "server_key", "proxy_signing_key"]:
        cfg[key] = str(out / "proxy" / Path(cfg[key]).name)
    for client in cfg["authorized_clients"]:
        client["signing_public_key"] = str(out / "proxy" / Path(client["signing_public_key"]).name)
    cfg["health_file"] = str(tmp_path / "health.json")
    p.write_text(json.dumps(cfg))
    return out, p, cfg


def policy(pair):
    out, p, cfg = pair
    c = load(p, allow_test=True)
    s = object.__new__(Server)
    s.lock = threading.RLock()
    s.state = "active"
    s.generation = 1
    s.replays = {}
    a = SimpleNamespace(
        edge_id=c.edge_id,
        proxy_id=c.proxy_id,
        endpoint_id=c.endpoint_id,
        configuration_version=c.configuration_version,
        edge_signing_key=str(out / "edge/edge-signing.key"),
    )
    req = _native_request(
        a,
        destination="127.0.0.1",
        destination_port=25,
        channel_binding=b"bound-channel",
    )
    key = next(iter(c.client_keys.values()))
    private = serialization.load_pem_private_key(
        (out / "edge/edge-signing.key").read_bytes(), password=None
    )
    session = {"closed": False, "generation": 1}
    return s, c, req, key, private, session


def resign(req, private, **updates):
    return _signed({**{k: v for k, v in req.items() if k != "signature"}, **updates}, private)


def test_production_never_accepts_fixture_mode_implicitly(pair):
    with pytest.raises(ValueError, match="test_mode"):
        load(pair[1])


@pytest.mark.parametrize(
    "field,value",
    [
        ("maximum_connections", True),
        ("header_timeout", float("nan")),
        ("idle_timeout", 0),
        ("maximum_new_connections_per_second", 0),
        ("maximum_session_bytes", 2**40),
    ],
)
def test_invalid_limits_fail_before_listen(pair, field, value):
    _, p, cfg = pair
    cfg[field] = value
    p.write_text(json.dumps(cfg))
    with pytest.raises(ValueError):
        load(p, allow_test=True)


def test_world_readable_private_key_rejected(pair):
    out, p, cfg = pair
    (out / "proxy/server.key").chmod(0o644)
    with pytest.raises(ValueError, match="permissions"):
        load(p, allow_test=True)


def test_exact_signed_admission_and_replay(pair):
    s, c, r, key, private, session = policy(pair)
    assert (
        s.admit(r, b"bound-channel", key, ipaddress.ip_address("127.0.0.1"), c, session)[0]
        == "127.0.0.1"
    )
    with pytest.raises(Rejected, match="replayed"):
        s.admit(r, b"bound-channel", key, ipaddress.ip_address("127.0.0.1"), c, session)


@pytest.mark.parametrize(
    "updates",
    [
        {"destination_port": True},
        {"destination_port": 443},
        {"issued_at": True},
        {"expires_at": 0},
        {"expires_at": int(time.time()) + 90},
        {"request_id": "recipient@example.com"},
        {"edge_id": "other-edge"},
        {"endpoint_id": "other-endpoint"},
        {"configuration_version": "999"},
        {"channel_binding": "wrong"},
    ],
)
def test_malformed_or_cross_scope_request_fails(pair, updates):
    s, c, r, key, private, session = policy(pair)
    with pytest.raises(Rejected):
        s.admit(
            resign(r, private, **updates),
            b"bound-channel",
            key,
            ipaddress.ip_address("127.0.0.1"),
            c,
            session,
        )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.100.100.200",
        "192.0.2.1",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
        "8.8.8.8",
        "9.9.9.9",
    ],
)
def test_public_destination_mode_blocks_private_special_self_and_peer(pair, address):
    s, c, r, key, private, session = policy(pair)
    c.deployment_mode = "production"
    c.source_address = ipaddress.ip_address("8.8.8.8")
    c.allowed_destination_cidrs = (ipaddress.ip_network("0.0.0.0/0"),)
    with pytest.raises(Rejected):
        s.admit(
            resign(r, private, destination_ip=address),
            b"bound-channel",
            key,
            ipaddress.ip_address("9.9.9.9"),
            c,
            session,
        )


def test_public_mx_and_explicit_deny_policy(pair):
    s, c, r, key, private, session = policy(pair)
    c.deployment_mode = "production"
    c.source_address = ipaddress.ip_address("8.8.8.8")
    c.allowed_destination_cidrs = (ipaddress.ip_network("0.0.0.0/0"),)
    r = resign(r, private, destination_ip="1.1.1.1")
    assert (
        s.admit(r, b"bound-channel", key, ipaddress.ip_address("9.9.9.9"), c, session)[0]
        == "1.1.1.1"
    )
    c.denied_destination_cidrs = (ipaddress.ip_network("1.1.1.0/24"),)
    with pytest.raises(Rejected, match="destination"):
        s.admit(r, b"bound-channel", key, ipaddress.ip_address("9.9.9.9"), c, session)


@pytest.mark.parametrize(
    "address",
    [
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:8.8.8.8",
        "2002:0808:0808::1",
        "ff02::1",
        "2001:db8::1",
    ],
)
def test_ipv6_special_and_transition_destinations_rejected(pair, address):
    s, c, r, key, private, session = policy(pair)
    c.deployment_mode = "production"
    c.source_address = ipaddress.ip_address("2606:4700:4700::1111")
    c.allowed_destination_cidrs = (ipaddress.ip_network("::/0"),)
    with pytest.raises(Rejected):
        s.admit(
            resign(r, private, destination_ip=address),
            b"bound-channel",
            key,
            ipaddress.ip_address("2001:4860:4860::8888"),
            c,
            session,
        )


def test_reload_generation_and_halt_invalidate_admission(pair):
    s, c, r, key, private, session = policy(pair)
    session["generation"] = 0
    with pytest.raises(Rejected, match="not_active"):
        s.admit(r, b"bound-channel", key, ipaddress.ip_address("127.0.0.1"), c, session)
    session["generation"] = 1
    s.state = "draining"
    with pytest.raises(Rejected, match="not_active"):
        s.admit(r, b"bound-channel", key, ipaddress.ip_address("127.0.0.1"), c, session)
