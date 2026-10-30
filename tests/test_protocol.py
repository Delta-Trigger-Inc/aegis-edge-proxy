from __future__ import annotations

import base64
import hashlib
import ipaddress
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proxy_runtime import (
    PROTOCOL_VERSION,
    NativeProxy,
    _receive_frame,
    _send_frame,
    _signed,
    _tunnel,
)






def test_native_frames_reject_duplicate_keys() -> None:
    sender, receiver = socket.socketpair()
    try:
        payload = b'{"request_id":"one","request_id":"two"}'
        sender.sendall(struct.pack("!I", len(payload)) + payload)
        with pytest.raises(ValueError, match="duplicate_key"):
            _receive_frame(receiver)
    finally:
        sender.close()
        receiver.close()


def test_native_frames_round_trip_fixed_schema_json() -> None:
    sender, receiver = socket.socketpair()
    try:
        expected = {"status": "accepted", "request_id": "request-001"}
        _send_frame(sender, expected)
        assert _receive_frame(receiver) == expected
    finally:
        sender.close()
        receiver.close()


def test_connector_tunnel_preserves_bidirectional_half_close() -> None:
    edge, connector_edge = socket.socketpair()
    connector_proxy, proxy = socket.socketpair()
    result: list[tuple[int, int]] = []
    thread = threading.Thread(
        target=lambda: result.append(_tunnel(connector_edge, connector_proxy))
    )
    thread.start()
    try:
        edge.sendall(b"smtp request")
        edge.shutdown(socket.SHUT_WR)
        assert proxy.recv(1024) == b"smtp request"
        assert proxy.recv(1024) == b""

        proxy.sendall(b"smtp response")
        proxy.shutdown(socket.SHUT_WR)
        assert edge.recv(1024) == b"smtp response"
        assert edge.recv(1024) == b""
        thread.join(timeout=2)
        assert thread.is_alive() is False
        assert result == [(12, 13)]
    finally:
        for connection in (edge, connector_edge, connector_proxy, proxy):
            connection.close()


def test_connector_tunnel_terminates_after_peer_reset() -> None:
    edge, connector_edge = socket.socketpair()
    connector_proxy, proxy = socket.socketpair()
    thread = threading.Thread(target=_tunnel, args=(connector_edge, connector_proxy))
    thread.start()
    edge.close()
    proxy.close()
    thread.join(timeout=2)
    connector_edge.close()
    connector_proxy.close()
    assert thread.is_alive() is False


def _native_proxy(private_key: Ed25519PrivateKey) -> NativeProxy:
    proxy = object.__new__(NativeProxy)
    proxy.args = SimpleNamespace(
        edge_id="edge-gate-c",
        proxy_id="proxy-gate-c",
        endpoint_id="endpoint-gate-c",
        configuration_version="gate-c-v1",
        maximum_connections=2,
    )
    proxy.edge_public_key = private_key.public_key()
    proxy.destination_networks = (ipaddress.ip_network("192.0.2.0/24"),)
    proxy.seen_requests = {}
    proxy.state = "active"
    proxy.lock = threading.Lock()
    proxy.active_count = 0
    return proxy


def _request(
    private_key: Ed25519PrivateKey,
    *,
    request_id: str = "request-001",
    channel_binding: bytes = b"tls-session-one",
    endpoint_id: str = "endpoint-gate-c",
    destination_ip: str = "192.0.2.20",
) -> dict[str, object]:
    now = int(time.time())
    binding = (
        base64.urlsafe_b64encode(hashlib.sha256(channel_binding).digest())
        .rstrip(b"=")
        .decode()
    )
    return _signed(
        {
            "version": PROTOCOL_VERSION,
            "request_id": request_id,
            "edge_id": "edge-gate-c",
            "proxy_id": "proxy-gate-c",
            "endpoint_id": endpoint_id,
            "configuration_version": "gate-c-v1",
            "destination_ip": destination_ip,
            "destination_port": 25,
            "issued_at": now,
            "expires_at": now + 20,
            "channel_binding": binding,
        },
        private_key,
    )


def test_native_request_is_authorized_replay_fenced_and_tls_channel_bound() -> None:
    private_key = Ed25519PrivateKey.generate()
    proxy = _native_proxy(private_key)
    channel_binding = b"tls-session-one"
    request = _request(private_key, channel_binding=channel_binding)

    assert proxy._admit(request, channel_binding=channel_binding) == (
        "192.0.2.20",
        25,
        "request-001",
    )
    with pytest.raises(ValueError, match="request_replayed"):
        proxy._admit(request, channel_binding=channel_binding)

    second = _request(private_key, request_id="request-002", channel_binding=channel_binding)
    with pytest.raises(ValueError, match="channel_binding_invalid"):
        proxy._admit(second, channel_binding=b"another-tls-session")


def test_native_request_fails_closed_on_endpoint_and_destination() -> None:
    private_key = Ed25519PrivateKey.generate()
    proxy = _native_proxy(private_key)

    with pytest.raises(ValueError, match="endpoint_not_authorized"):
        proxy._admit(
            _request(private_key, endpoint_id="another-endpoint"),
            channel_binding=b"tls-session-one",
        )
    with pytest.raises(ValueError, match="destination_not_allowed"):
        proxy._admit(
            _request(private_key, destination_ip="127.0.0.1"),
            channel_binding=b"tls-session-one",
        )


def test_native_request_reserves_bounded_capacity_and_honors_drain() -> None:
    private_key = Ed25519PrivateKey.generate()
    proxy = _native_proxy(private_key)
    proxy.active_count = proxy.args.maximum_connections

    with pytest.raises(ValueError, match="connection_limit_reached"):
        proxy._admit(
            _request(private_key),
            channel_binding=b"tls-session-one",
        )

    proxy.active_count = 0
    proxy.state = "draining"
    with pytest.raises(ValueError, match="proxy_draining"):
        proxy._admit(
            _request(private_key, request_id="request-draining"),
            channel_binding=b"tls-session-one",
        )
