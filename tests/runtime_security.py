"""Exercise resource limits and administrative controls using actual TLS sockets.

Run as UID 10001 in the production image with --network none. No real mail.
"""

import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, "/app")
from proxy_runtime import _native_open

os.umask(0o077)
root = Path(tempfile.mkdtemp(prefix="proxy-security-"))
bundle = root / "pair"
subprocess.run(
    [
        sys.executable,
        "/app/create_pair.py",
        "--deployment-mode",
        "test",
        "--edge-peer-cidr",
        "127.0.0.1/32",
        "--edge-id",
        "test-edge",
        "--proxy-id",
        "test-proxy",
        "--endpoint-id",
        "test-endpoint",
        "--source-ip",
        "127.0.0.1",
        "--server-name",
        "proxy.test",
        "--allowed-destination-cidr",
        "127.0.0.1/32",
        "--output",
        str(bundle),
    ],
    check=True,
)
cfg = json.loads((bundle / "proxy/config.json").read_text())
for field in ("ca_file", "server_cert", "server_key", "proxy_signing_key"):
    cfg[field] = str(bundle / "proxy" / Path(cfg[field]).name)
for item in cfg["authorized_clients"]:
    item["signing_public_key"] = str(bundle / "proxy" / Path(item["signing_public_key"]).name)
cfg.update(
    health_file=str(root / "health.json"),
    maximum_connections=2,
    maximum_new_connections_per_second=32,
    header_timeout=1,
    idle_timeout=0.5,
    session_timeout=1.2,
    drain_timeout=0.3,
)
config = root / "config.json"
edge = bundle / "edge"
args = SimpleNamespace(
    proxy_host="127.0.0.1",
    proxy_port=5443,
    edge_id="test-edge",
    proxy_id="test-proxy",
    endpoint_id="test-endpoint",
    configuration_version="1",
    connect_timeout=2,
    header_timeout=2,
    ca_file=str(edge / "ca.pem"),
    client_cert=str(edge / "client.pem"),
    client_key=str(edge / "client.key"),
    edge_signing_key=str(edge / "edge-signing.key"),
    proxy_signing_public_key=str(edge / "proxy-signing-public.pem"),
    proxy_server_name="proxy.test",
    no_client_cert=False,
    channel_binding_mismatch=False,
)
receiver = socket.socket()
receiver.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
receiver.bind(("127.0.0.1", 25))
receiver.listen()
receiver.settimeout(0.2)
done = threading.Event()


def echo(connection):
    with connection:
        connection.settimeout(3)
        try:
            while data := connection.recv(65536):
                connection.sendall(data)
        except OSError:
            pass


def accept():
    while not done.is_set():
        try:
            c, _ = receiver.accept()
        except TimeoutError:
            continue
        except OSError:
            return
        threading.Thread(target=echo, args=(c,), daemon=True).start()


threading.Thread(target=accept, daemon=True).start()
process = log = None


def until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.03)
    raise AssertionError("condition deadline exceeded")


def health():
    return json.loads((root / "health.json").read_text())


def write_config():
    temporary = config.with_suffix(".new")
    temporary.write_text(json.dumps(cfg))
    temporary.replace(config)


def start():
    global process, log
    write_config()
    (root / "health.json").unlink(missing_ok=True)
    log = (root / "proxy.log").open("a")
    process = subprocess.Popen(
        [sys.executable, "/app/proxy.py", "--allow-test-mode", "--config", str(config)],
        stdout=log,
        stderr=log,
    )
    until(lambda: (root / "health.json").exists())


def stop():
    process.terminate()
    process.wait(timeout=3)
    log.close()


def connect():
    c, r = _native_open(args, destination="127.0.0.1", destination_port=25)
    assert r["status"] == "accepted", r
    c.settimeout(2)
    return c


def closed(c):
    try:
        return c.recv(1) == b""
    except (ConnectionError, OSError):
        return True


def reload():
    write_config()
    process.send_signal(signal.SIGHUP)
    digest = hashlib.sha256(config.read_bytes()).hexdigest()
    until(lambda: health()["configuration_digest"] == digest)


try:
    start()
    # Unauthenticated slow handshakes reserve the same bounded slots as real sessions.
    sockets = [socket.create_connection(("127.0.0.1", 5443)) for _ in range(2)]
    until(lambda: health()["active_connections"] == 2)
    excess = socket.create_connection(("127.0.0.1", 5443))
    excess.settimeout(1)
    assert closed(excess)
    excess.close()
    for s in sockets:
        s.settimeout(2)
        assert closed(s)
        s.close()
    until(lambda: health()["active_connections"] == 0)
    print(
        "PASS: bounded pre-authentication capacity and absolute handshake timeout",
        flush=True,
    )

    with connect() as c:
        c.sendall(b"idle")
        assert c.recv(4) == b"idle"
        assert closed(c)
    with connect() as c:
        began = time.monotonic()
        while time.monotonic() - began < 3:
            try:
                c.sendall(b"x")
                if not c.recv(1):
                    break
            except OSError:
                break
            time.sleep(0.1)
        assert time.monotonic() - began < 2
    print("PASS: idle and total-session limits", flush=True)

    cfg["maximum_session_bytes"] = 1024
    reload()
    with connect() as c:
        c.sendall(b"x" * 2048)
        assert closed(c)
    cfg["maximum_session_bytes"] = 67108864
    reload()
    print("PASS: per-session byte cap", flush=True)

    cfg.update(idle_timeout=5, session_timeout=10)
    reload()
    c = connect()
    c.sendall(b"before")
    assert c.recv(6) == b"before"
    original = cfg["authorized_clients"][0]["certificate_sha256"]
    cfg["authorized_clients"][0]["certificate_sha256"] = "a" * 64
    reload()
    assert closed(c)
    c.close()
    try:
        c = connect()
    except (OSError, ConnectionError):
        pass
    else:
        c.close()
        raise AssertionError("revoked certificate admitted")
    cfg["authorized_clients"][0]["certificate_sha256"] = original
    reload()
    with connect() as c:
        c.sendall(b"restored")
        assert c.recv(8) == b"restored"
    print(
        "PASS: revocation terminates live streams and refuses a CA-valid retired leaf",
        flush=True,
    )

    c = connect()
    process.send_signal(signal.SIGUSR1)
    until(lambda: health()["state"] == "draining")
    c.sendall(b"drain")
    assert c.recv(5) == b"drain"
    denied = socket.create_connection(("127.0.0.1", 5443))
    denied.settimeout(1)
    assert closed(denied)
    denied.close()
    process.send_signal(signal.SIGUSR2)
    assert closed(c)
    c.close()
    until(lambda: health()["state"] == "halted")
    stop()
    start()
    c = connect()
    config.write_text('{"invalid":true}')
    process.send_signal(signal.SIGHUP)
    until(lambda: health()["state"] == "halted")
    assert not health()["reload_ok"] and closed(c)
    c.close()
    stop()
    start()
    c = connect()
    began = time.monotonic()
    stop()
    assert time.monotonic() - began < 2 and closed(c)
    c.close()
    print(
        "PASS: drain, halt, invalid reload fail-closed, bounded shutdown and restart",
        flush=True,
    )
    rotated = root / "renewed"
    subprocess.run(
        [sys.executable, "/app/renew_pair.py", "--bundle", str(bundle), "--output", str(rotated)],
        check=True,
    )

    def install_rotation(side):
        global cfg
        cfg = json.loads((rotated / side / "config.json").read_text())
        for field in ("ca_file", "server_cert", "server_key", "proxy_signing_key"):
            cfg[field] = str(rotated / side / Path(cfg[field]).name)
        for item in cfg["authorized_clients"]:
            item["signing_public_key"] = str(rotated / side / Path(item["signing_public_key"]).name)
        cfg.update(health_file=str(root / "health.json"), drain_timeout=0.3)

    install_rotation("transition-proxy")
    start()
    with connect() as c:
        c.sendall(b"old")
        assert c.recv(3) == b"old"
    old_args = args
    args = SimpleNamespace(**vars(args))
    args.client_cert = str(rotated / "edge/client.pem")
    args.client_key = str(rotated / "edge/client.key")
    with connect() as c:
        c.sendall(b"new")
        assert c.recv(3) == b"new"
    install_rotation("proxy")
    reload()
    c = connect()
    c.close()
    new_args, args = args, old_args
    try:
        c = connect()
    except (OSError, ConnectionError):
        pass
    else:
        c.close()
        raise AssertionError("retired leaf still accepted after renewal")
    args = new_args
    stop()
    print("PASS: staged renewal admits both leaves, then revokes the retired leaf", flush=True)
finally:
    if process is not None and process.poll() is None:
        stop()
    done.set()
    receiver.close()
