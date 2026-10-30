"""Native protocol framing, signing and authenticated connection probe."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import socket
import ssl
import struct
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_FRAME_BYTES = 4096
PROTOCOL_VERSION = "aegis-egress-v1"


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519")
    return key


def _public_key(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("verification key must be Ed25519")
    return key


def _signed(values: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    return {**values, "signature": _encode(key.sign(_canonical(values)))}


def _verify_signed(value: dict[str, Any], key: Ed25519PublicKey) -> dict[str, Any]:
    signature = value.get("signature")
    if not isinstance(signature, str):
        raise ValueError("signature_missing")
    unsigned = {name: item for name, item in value.items() if name != "signature"}
    try:
        key.verify(_decode(signature), _canonical(unsigned))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("signature_invalid") from exc
    return unsigned


def _send_frame(connection: socket.socket, value: Mapping[str, Any]) -> None:
    payload = _canonical(value)
    if len(payload) > MAX_FRAME_BYTES:
        raise ValueError("frame_too_large")
    connection.sendall(struct.pack("!I", len(payload)) + payload)


def _receive_exact(connection: socket.socket, count: int, *, deadline=None) -> bytes:
    value = bytearray()
    while len(value) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("frame_deadline_exceeded")
            connection.settimeout(remaining)
        chunk = connection.recv(count - len(value))
        if not chunk:
            raise ConnectionError("unexpected_eof")
        value.extend(chunk)
    return bytes(value)


def _receive_frame(connection: socket.socket, *, deadline=None) -> dict[str, Any]:
    size = struct.unpack("!I", _receive_exact(connection, 4, deadline=deadline))[0]
    if size < 2 or size > MAX_FRAME_BYTES:
        raise ValueError("frame_size_invalid")

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("frame_duplicate_key")
            value[key] = item
        return value

    value = json.loads(
        _receive_exact(connection, size, deadline=deadline), object_pairs_hook=strict_object
    )
    if not isinstance(value, dict):
        raise ValueError("frame_not_object")
    return value


def _client_context(args: argparse.Namespace) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca_file)
    if not args.no_client_cert:
        context.load_cert_chain(args.client_cert, args.client_key)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    return context


def _native_request(
    args: argparse.Namespace,
    *,
    destination: str,
    destination_port: int,
    channel_binding: bytes,
    request_id: str | None = None,
) -> dict[str, Any]:
    issued_at = int(time.time())
    values = {
        "version": PROTOCOL_VERSION,
        "request_id": request_id or uuid.uuid4().hex,
        "edge_id": args.edge_id,
        "proxy_id": args.proxy_id,
        "endpoint_id": args.endpoint_id,
        "configuration_version": args.configuration_version,
        "destination_ip": str(ipaddress.ip_address(destination)),
        "destination_port": destination_port,
        "issued_at": issued_at,
        "expires_at": issued_at + 20,
        "channel_binding": _encode(hashlib.sha256(channel_binding).digest()),
    }
    return _signed(values, _private_key(args.edge_signing_key))


def _native_open(
    args: argparse.Namespace,
    *,
    destination: str,
    destination_port: int,
    request_id: str | None = None,
    track=None,
) -> tuple[ssl.SSLSocket, dict[str, Any]]:
    raw = socket.create_connection((args.proxy_host, args.proxy_port), timeout=args.connect_timeout)
    connection = None
    try:
        if track is not None:
            track(raw)
        connection = _client_context(args).wrap_socket(raw, server_hostname=args.proxy_server_name)
        if track is not None:
            track(connection)
        channel_binding = connection.get_channel_binding("tls-unique")
        if not channel_binding:
            raise ssl.SSLError("TLS channel binding is unavailable")
        connection.settimeout(args.header_timeout)
        request = _native_request(
            args,
            destination=destination,
            destination_port=destination_port,
            channel_binding=(
                b"deliberately-invalid-channel-binding"
                if args.channel_binding_mismatch
                else channel_binding
            ),
            request_id=request_id,
        )
        _send_frame(connection, request)
        response = _receive_frame(connection, deadline=time.monotonic() + args.header_timeout)
        values = _verify_signed(response, _public_key(args.proxy_signing_public_key))
        if values.get("request_id") != request["request_id"]:
            raise ValueError("response_request_mismatch")
        if (
            set(values) != {"version", "request_id", "proxy_id", "status", "reason", "observed_at"}
            or values["version"] != PROTOCOL_VERSION
            or values["proxy_id"] != args.proxy_id
            or values["status"] not in {"accepted", "rejected"}
            or not isinstance(values["reason"], str)
            or not 1 <= len(values["reason"]) <= 160
            or type(values["observed_at"]) is not int
            or abs(int(time.time()) - values["observed_at"]) > 30
            or (values["status"] == "accepted" and values["reason"] != "connection_admitted")
        ):
            raise ValueError("response_schema_invalid")
        connection.settimeout(None)
        return connection, values
    except Exception:
        (connection if connection is not None else raw).close()
        raise
