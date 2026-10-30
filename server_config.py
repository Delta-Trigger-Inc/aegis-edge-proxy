"""Strict, bounded private configuration for one Edge/endpoint/source-IP process."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import ssl
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

LIMIT = 262144
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}\Z")


def unique(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate_configuration_field")
        out[key] = value
    return out


def read_file(path, *, secret=False):
    p = Path(path)
    if not p.is_absolute() or p.is_symlink():
        raise ValueError("absolute_regular_file_required")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > LIMIT or s.st_nlink != 1:
            raise ValueError("invalid_private_file")
        if s.st_uid not in {0, os.geteuid()} or s.st_mode & 0o022 or (secret and s.st_mode & 0o007):
            raise ValueError("unsafe_private_file_permissions")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError("file_too_large")
        return data
    finally:
        os.close(fd)


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("invalid_integer_limit")
    return value


def load(path, *, allow_test=False):
    raw = read_file(path, secret=True)
    v = json.loads(raw, object_pairs_hook=unique)
    required = {
        "schema_version",
        "deployment_mode",
        "listen_host",
        "listen_port",
        "edge_id",
        "proxy_id",
        "endpoint_id",
        "configuration_version",
        "source_ip",
        "allowed_peer_cidrs",
        "allowed_destination_cidrs",
        "denied_destination_cidrs",
        "maximum_connections",
        "maximum_new_connections_per_second",
        "connect_timeout",
        "header_timeout",
        "idle_timeout",
        "session_timeout",
        "maximum_session_bytes",
        "drain_timeout",
        "ca_file",
        "server_cert",
        "server_key",
        "proxy_signing_key",
        "authorized_clients",
        "health_file",
    }
    if (
        not isinstance(v, dict)
        or set(v) != required
        or type(v["schema_version"]) is not int
        or v["schema_version"] != 1
    ):
        raise ValueError("configuration_schema_invalid")
    if v["deployment_mode"] not in {"production", "test"} or (
        v["deployment_mode"] == "test" and not allow_test
    ):
        raise ValueError("test_mode_not_enabled")
    for k in ("edge_id", "proxy_id", "endpoint_id", "configuration_version"):
        if not isinstance(v[k], str) or not ID.fullmatch(v[k]):
            raise ValueError("invalid_identity")
    source = ipaddress.ip_address(v["source_ip"])
    listen = ipaddress.ip_address(v["listen_host"])
    if (
        source.is_unspecified
        or source.is_multicast
        or source.version != listen.version
        or (v["deployment_mode"] == "production" and not source.is_global)
    ):
        raise ValueError("invalid_source_address")
    if listen not in (
        source,
        ipaddress.ip_address("0.0.0.0" if source.version == 4 else "::"),
    ):
        raise ValueError("listener_must_bind_source_or_wildcard")
    if (
        getattr(source, "ipv4_mapped", None)
        or getattr(source, "sixtofour", None)
        or getattr(source, "teredo", None)
    ):
        raise ValueError("transition_address_forbidden")
    integer(v["listen_port"], 1024, 65535)
    integer(v["maximum_connections"], 1, 256)
    integer(v["maximum_session_bytes"], 1024, 1024 * 1024 * 1024)
    integer(v["maximum_new_connections_per_second"], 1, 256)
    for k, bound in [
        ("connect_timeout", 30),
        ("header_timeout", 30),
        ("idle_timeout", 600),
        ("session_timeout", 3600),
        ("drain_timeout", 300),
    ]:
        if type(v[k]) not in (int, float) or not math.isfinite(v[k]) or not 0 < v[k] <= bound:
            raise ValueError("invalid_timeout")
    if v["idle_timeout"] > v["session_timeout"]:
        raise ValueError("idle_exceeds_session")
    for k in [
        "allowed_peer_cidrs",
        "allowed_destination_cidrs",
        "denied_destination_cidrs",
    ]:
        if (
            not isinstance(v[k], list)
            or len(v[k]) > 128
            or (k != "denied_destination_cidrs" and not v[k])
        ):
            raise ValueError("invalid_network_list")
        networks = tuple(ipaddress.ip_network(n, strict=True) for n in v[k])
        if any(n.version != source.version for n in networks):
            raise ValueError("network_family_mismatch")
        if k == "allowed_peer_cidrs" and any(
            n.prefixlen < (24 if n.version == 4 else 64) for n in networks
        ):
            raise ValueError("peer_allowlist_too_broad")
        v[k] = networks
    clients = v["authorized_clients"]
    if not isinstance(clients, list) or not 1 <= len(clients) <= 4:
        raise ValueError("invalid_client_allowlist")
    keys = {}
    for item in clients:
        if not isinstance(item, dict) or set(item) != {
            "certificate_sha256",
            "signing_public_key",
        }:
            raise ValueError("invalid_client_identity")
        digest = item["certificate_sha256"]
        if (
            not isinstance(digest, str)
            or not re.fullmatch("[a-f0-9]{64}", digest)
            or digest in keys
        ):
            raise ValueError("invalid_client_fingerprint")
        key = serialization.load_pem_public_key(read_file(item["signing_public_key"]))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("invalid_client_signing_key")
        keys[digest] = key
    for k in ["ca_file", "server_cert", "server_key", "proxy_signing_key"]:
        read_file(v[k], secret=k.endswith("key"))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_STRICT
    ctx.load_cert_chain(v["server_cert"], v["server_key"])
    ctx.load_verify_locations(v["ca_file"])
    # Disable TLS tickets/resumption: each connection must present its current leaf identity.
    ctx.num_tickets = 0
    ctx.options |= ssl.OP_NO_TICKET
    cert = x509.load_pem_x509_certificate(read_file(v["server_cert"]))
    now = datetime.now(UTC)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("server_certificate_expired_or_not_yet_valid")
    v.update(
        client_keys=keys,
        tls_context=ctx,
        certificate_expires_at=cert.not_valid_after_utc.isoformat(),
        digest=hashlib.sha256(raw).hexdigest(),
        source_address=source,
    )
    health = Path(v["health_file"])
    if not health.is_absolute() or health.name != "health.json":
        raise ValueError("invalid_health_path")
    return SimpleNamespace(**v)
