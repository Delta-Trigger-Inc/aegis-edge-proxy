"""Stage TLS renewal: deploy transition-proxy, then edge, then proxy.

Retains the CA and signing identities. Reloads terminate current streams.
Never connects, deploys, overwrites its input, or renews an expired CA.
"""

import argparse
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def renew(source, output):
    os.umask(0o077)
    source = Path(source).resolve(strict=True)
    ca = x509.load_pem_x509_certificate((source / "ca/ca.pem").read_bytes())
    key = serialization.load_pem_private_key((source / "ca/ca.key").read_bytes(), password=None)
    now = datetime.now(UTC)
    until = now + timedelta(days=30)
    if ca.not_valid_before_utc > now or ca.not_valid_after_utc <= until + timedelta(days=1):
        raise ValueError("CA renewal requires a new pair and coordinated trust replacement")

    def public(k):
        return k.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    if public(ca.public_key()) != public(key.public_key()):
        raise ValueError("CA private key mismatch")
    config = json.loads((source / "proxy/config.json").read_text())
    old = x509.load_pem_x509_certificate((source / "edge/client.pem").read_bytes())
    old_digest = old.fingerprint(hashes.SHA256()).hex()
    if (
        len(config["authorized_clients"]) != 1
        or config["authorized_clients"][0]["certificate_sha256"] != old_digest
    ):
        raise ValueError("Complete the previous renewal before staging another")
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    files = {
        "ca": ["ca.key", "ca.pem"],
        "edge": [
            "ca.pem",
            "client.pem",
            "client.key",
            "edge-signing.key",
            "proxy-signing-public.pem",
            "security-profile.json",
        ],
        "proxy": [
            "ca.pem",
            "server.pem",
            "server.key",
            "proxy-signing.key",
            "edge-signing-public.pem",
            "config.json",
        ],
    }
    for side, names in files.items():
        (output / side).mkdir(mode=0o700)
        for name in names:
            (output / side / name).write_bytes((source / side / name).read_bytes())
    for side, stem in (("edge", "client"), ("proxy", "server")):
        prior = x509.load_pem_x509_certificate((source / side / (stem + ".pem")).read_bytes())
        new_key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(prior.subject)
            .issuer_name(ca.subject)
            .public_key(new_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(until)
        )
        for extension in prior.extensions:
            value = extension.value
            if isinstance(value, x509.SubjectKeyIdentifier):
                value = x509.SubjectKeyIdentifier.from_public_key(new_key.public_key())
            builder = builder.add_extension(value, critical=extension.critical)
        certificate = builder.sign(key, hashes.SHA256())
        (output / side / (stem + ".pem")).write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
        )
        (output / side / (stem + ".key")).write_bytes(
            new_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        if side == "edge":
            config["authorized_clients"][0]["certificate_sha256"] = certificate.fingerprint(
                hashes.SHA256()
            ).hex()
    (output / "proxy/config.json").write_text(json.dumps(config, indent=2) + "\n")
    transition = output / "transition-proxy"
    transition.mkdir(mode=0o700)
    for name in files["proxy"]:
        (transition / name).write_bytes((output / "proxy" / name).read_bytes())
    config["authorized_clients"].append(
        {
            "certificate_sha256": old_digest,
            "signing_public_key": config["authorized_clients"][0]["signing_public_key"],
        }
    )
    (transition / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    metadata = json.loads((source / "metadata.json").read_text())
    metadata["certificate_expires"] = until.isoformat()
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    renew(args.bundle, args.output)
    print("Renewal staged: deploy transition-proxy, then edge, then proxy; verify each step.")
