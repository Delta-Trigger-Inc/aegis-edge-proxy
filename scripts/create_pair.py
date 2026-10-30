"""Generate private production PKI on the trusted Edge/operator host, never on GitHub."""

import argparse
import datetime
import ipaddress
import json
import os
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--deployment-mode", choices=["production", "test"], default="production")
    p.add_argument("--edge-peer-cidr", required=True)
    for field in [
        "edge-id",
        "proxy-id",
        "endpoint-id",
        "source-ip",
        "server-name",
        "output",
        "allowed-destination-cidr",
    ]:
        p.add_argument("--" + field, required=True)
    a = p.parse_args()
    for value in [a.edge_id, a.proxy_id, a.endpoint_id]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,100}", value):
            p.error("Invalid ID")
    source = ipaddress.ip_address(a.source_ip)
    peer = ipaddress.ip_network(a.edge_peer_cidr, strict=True)
    if peer.version != source.version:
        p.error("Edge peer address family must match proxy source")
    net = ipaddress.ip_network(a.allowed_destination_cidr, strict=True)
    if net.version != source.version:
        p.error("Destination family must match source")
    if a.deployment_mode == "production" and not source.is_global:
        p.error("Production source must be globally routable")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", a.server_name):
        p.error("Invalid TLS DNS name")
    os.umask(0o077)
    out = Path(a.output)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ["ca", "edge", "proxy"]:
        (out / name).mkdir(mode=0o700)

    def write(name, data):
        (out / name).write_bytes(data.encode() if isinstance(data, str) else data)

    def private(k):
        return k.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def public(k):
        return k.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    now = datetime.datetime.now(datetime.UTC)
    ca = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, a.proxy_id + " CA")])
    cacert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca, hashes.SHA256())
    )
    write("ca/ca.key", private(ca))
    write("ca/ca.pem", cacert.public_bytes(serialization.Encoding.PEM))
    for side, cn, eku in [
        ("edge", a.edge_id, ExtendedKeyUsageOID.CLIENT_AUTH),
        ("proxy", a.server_name, ExtendedKeyUsageOID.SERVER_AUTH),
    ]:
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        )
        if side == "proxy":
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(a.server_name)]),
                critical=False,
            )
        cert = builder.sign(ca, hashes.SHA256())
        if side == "edge":
            client_fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        stem = "client" if side == "edge" else "server"
        write(side + "/" + stem + ".key", private(key))
        write(side + "/" + stem + ".pem", cert.public_bytes(serialization.Encoding.PEM))
        write(side + "/ca.pem", cacert.public_bytes(serialization.Encoding.PEM))
    edge = ed25519.Ed25519PrivateKey.generate()
    proxy = ed25519.Ed25519PrivateKey.generate()
    write("edge/edge-signing.key", private(edge))
    write("proxy/edge-signing-public.pem", public(edge))
    write("proxy/proxy-signing.key", private(proxy))
    write("edge/proxy-signing-public.pem", public(proxy))
    cfg = {
        "schema_version": 1,
        "deployment_mode": a.deployment_mode,
        "allowed_peer_cidrs": [str(peer)],
        "denied_destination_cidrs": [],
        "idle_timeout": 60,
        "session_timeout": 600,
        "maximum_session_bytes": 67108864,
        "maximum_new_connections_per_second": 16,
        "drain_timeout": 30,
        "listen_host": a.source_ip,
        "listen_port": 5443,
        "edge_id": a.edge_id,
        "proxy_id": a.proxy_id,
        "endpoint_id": a.endpoint_id,
        "configuration_version": "1",
        "source_ip": a.source_ip,
        "allowed_destination_cidrs": [str(net)],
        "maximum_connections": 16,
        "connect_timeout": 5,
        "header_timeout": 5,
        "ca_file": "/run/aegis-proxy/ca.pem",
        "server_cert": "/run/aegis-proxy/server.pem",
        "server_key": "/run/aegis-proxy/server.key",
        "proxy_signing_key": "/run/aegis-proxy/proxy-signing.key",
        "authorized_clients": [
            {
                "certificate_sha256": client_fingerprint,
                "signing_public_key": "/run/aegis-proxy/edge-signing-public.pem",
            }
        ],
        "health_file": "/run/aegis-health/health.json",
    }
    write("proxy/config.json", json.dumps(cfg, indent=2) + "\n")
    edgebase = "/run/aegis-egress/" + a.endpoint_id
    profile = {
        "version": 1,
        "backend": "aegis_proxy_v1",
        "proxy_id": a.proxy_id,
        "ca_file": edgebase + "/ca.pem",
        "client_cert": edgebase + "/client.pem",
        "client_key": edgebase + "/client.key",
        "edge_signing_key": edgebase + "/edge-signing.key",
        "proxy_signing_public_key": edgebase + "/proxy-signing-public.pem",
    }
    write("edge/security-profile.json", json.dumps(profile, indent=2) + "\n")
    write(
        "metadata.json",
        json.dumps(
            {
                "edge_id": a.edge_id,
                "proxy_id": a.proxy_id,
                "endpoint_id": a.endpoint_id,
                "source_ip": a.source_ip,
                "proxy_host": a.source_ip,
                "proxy_port": 5443,
                "tls_server_name": a.server_name,
                "endpoint_configuration_version": 1,
                "certificate_expires": (now + datetime.timedelta(days=30)).isoformat(),
                "sending_enabled": False,
            },
            indent=2,
        )
        + "\n",
    )
    print(
        "Created private pair bundle. Copy only proxy/ to its proxy host; "
        "retain edge/ and ca/ on the trusted operator host. Leaf certificates expire in 30 days."
    )


if __name__ == "__main__":
    main()
