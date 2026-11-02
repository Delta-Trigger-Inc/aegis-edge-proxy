"""Stock Postfix catch-all forwarding; separate from the stateless outbound proxy."""

import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path


def hostname(value):
    if (
        not isinstance(value, str)
        or len(value) > 253
        or "." not in value
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in value.split(".")
        )
    ):
        raise ValueError("invalid hostname")
    return value


def configuration(value):
    if set(value) - {
        "domain",
        "hostname",
        "shared_inbox",
        "control_url",
        "control_token",
        "listen_address",
    } or not {"domain", "hostname", "shared_inbox"} <= set(value):
        raise ValueError("invalid configuration fields")
    domain, host = hostname(value["domain"]), hostname(value["hostname"])
    inbox = value["shared_inbox"]
    if (
        not isinstance(inbox, str)
        or len(inbox) > 254
        or not re.fullmatch(r"[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+", inbox)
    ):
        raise ValueError("invalid shared inbox")
    destination_domain = hostname(inbox.split("@")[1])
    listen = value.get("listen_address", "all")
    if listen != "all" and (
        not ipaddress.ip_address(listen).is_global or ipaddress.ip_address(listen).version != 4
    ):
        raise ValueError("public listener address required")
    if destination_domain == domain or host == destination_domain:
        raise ValueError("forwarding destination would loop")
    main = {
        "compatibility_level": "3.6",
        "myhostname": host,
        "myorigin": domain,
        "mydestination": "",
        "inet_interfaces": listen,
        "inet_protocols": "ipv4",
        "mynetworks": "127.0.0.1/32",
        "relay_domains": "",
        "relayhost": "",
        "virtual_alias_domains": domain,
        "virtual_alias_maps": "hash:/etc/postfix/aegis_aliases",
        "smtpd_relay_restrictions": "reject_unauth_destination",
        "smtpd_recipient_restrictions": "reject_non_fqdn_recipient,reject_unauth_destination",
        "smtpd_sasl_auth_enable": "no",
        "disable_vrfy_command": "yes",
        "smtpd_authorized_xclient_hosts": "",
        "smtpd_authorized_xforward_hosts": "",
        "smtpd_client_connection_count_limit": "10",
        "smtpd_client_connection_rate_limit": "30",
        "smtpd_client_message_rate_limit": "60",
        "smtpd_recipient_limit": "20",
        "default_process_limit": "30",
        "default_destination_concurrency_limit": "2",
        "message_size_limit": "15728640",
        "queue_minfree": "268435456",
        "maximal_queue_lifetime": "5d",
        "bounce_queue_lifetime": "1d",
        "minimal_backoff_time": "300s",
        "maximal_backoff_time": "3600s",
        "smtp_tls_security_level": "may",
        "smtpd_tls_security_level": "may",
        "smtpd_tls_cert_file": "/var/lib/postfix/inbound-cert.pem",
        "smtpd_tls_key_file": "/var/lib/postfix/inbound-key.pem",
        "smtp_tls_CAfile": "/etc/ssl/certs/ca-certificates.crt",
        "sender_canonical_maps": "tcp:127.0.0.1:10001",
        "sender_canonical_classes": "envelope_sender",
        "recipient_canonical_maps": "tcp:127.0.0.1:10002",
        "recipient_canonical_classes": "envelope_recipient",
        "alias_maps": "",
        "alias_database": "",
        "local_transport": "error:local delivery disabled",
        "maillog_file": "/dev/stdout",
        "smtputf8_enable": "no",
        "biff": "no",
    }
    # The shared address is the sole alias destination; arbitrary external RCPTs
    # are rejected before alias expansion. SRS preserves forwarding SPF identity.
    return main, f"@{domain} {inbox}\n"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        # Never forward the pairing credential to a redirected destination.
        raise ValueError("Routing redirects are not allowed")


def check_health():
    value = json.loads(Path("/run/aegis-inbound/config.json").read_text())
    address = value.get("listen_address", "all")
    with socket.create_connection(
        ("127.0.0.1" if address == "all" else address, 25), timeout=2
    ) as stream:
        if not stream.recv(1024).startswith(b"220 "):
            raise RuntimeError("inbound listener unavailable")
    with socket.create_connection(("127.0.0.1", 10001), timeout=2):
        pass


def run():
    value = json.loads(Path("/run/aegis-inbound/config.json").read_text())
    main, aliases = configuration(value)
    root = Path("/etc/postfix")
    (root / "main.cf").write_text("".join(f"{key} = {v}\n" for key, v in main.items()))
    (root / "aegis_aliases").write_text(aliases)
    subprocess.run(["postmap", str(root / "aegis_aliases")], check=True)
    key = Path("/var/lib/postfix/inbound-key.pem")
    if not key.exists():
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "365",
                "-subj",
                "/CN=" + value["hostname"],
                "-keyout",
                str(key),
                "-out",
                "/var/lib/postfix/inbound-cert.pem",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        key.chmod(0o600)
    secret = Path("/var/lib/postsrsd/secret")
    if not secret.exists():
        fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(secrets.token_hex(32))
    srs = subprocess.Popen(
        [
            "postsrsd",
            "-d",
            value["domain"],
            "-s",
            str(secret),
            "-l",
            "127.0.0.1",
            "-f",
            "10001",
            "-r",
            "10002",
            "-u",
            "nobody",
        ]
    )
    subprocess.run(["postfix", "check"], check=True)
    postfix = subprocess.Popen(["postfix", "start-fg"])
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    next_update, applied_revision = 0, 0
    try:
        while not stopping:
            if srs.poll() is not None or postfix.poll() is not None:
                raise RuntimeError("inbound service exited")
            if value.get("control_url") and time.monotonic() >= next_update:
                next_update = time.monotonic() + 60
                try:
                    url = urllib.parse.urlsplit(value["control_url"])
                    if (
                        url.scheme != "https"
                        or not url.hostname
                        or url.username
                        or url.password
                        or url.query
                        or url.fragment
                    ):
                        raise ValueError("HTTPS control URL required")
                    request = urllib.request.Request(
                        value["control_url"] + "?applied_revision=" + str(applied_revision),
                        headers={"Authorization": "Bearer " + value["control_token"]},
                    )
                    with urllib.request.build_opener(NoRedirect()).open(
                        request, timeout=8
                    ) as response:
                        new = json.loads(response.read(4096))
                    if new["domain"] != value["domain"]:
                        raise ValueError("domain changed")
                    updated = {**value, "shared_inbox": new["shared_inbox"]}
                    _, new_aliases = configuration(updated)
                    if new_aliases != aliases:
                        (root / "aegis_aliases").write_text(new_aliases)
                        subprocess.run(["postmap", str(root / "aegis_aliases")], check=True)
                        subprocess.run(["postfix", "reload"], check=True)
                        value, aliases = updated, new_aliases
                    applied_revision = int(new["revision"])
                except Exception:
                    print(
                        "Routing refresh unavailable; retained existing forwarding destination.",
                        flush=True,
                    )
            time.sleep(0.5)
    finally:
        subprocess.run(["postfix", "stop"], check=False)
        srs.terminate()
        srs.wait(timeout=10)
        postfix.wait(timeout=20)


if __name__ == "__main__":
    if sys.argv[1:] == ["health"]:
        check_health()
    elif sys.argv[1:] == ["run"]:
        run()
    else:
        raise SystemExit("use run or health")
