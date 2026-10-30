"""Bounded, single-tenant egress server; SMTP and queue ownership stay on Edge."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import struct
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bounded_stream import relay
from proxy_runtime import PROTOCOL_VERSION, _canonical, _encode, _signed, _verify_signed
from server_config import load, read_file


class Rejected(Exception):
    pass


class Server:
    def __init__(self, path, *, allow_test=False):
        self.path = path
        self.allow_test = allow_test
        self.config = load(path, allow_test=allow_test)
        self.lock = threading.RLock()
        self.state = "active"
        self.stopping = False
        self.reload_requested = False
        self.sessions = {}
        self.replays = {}
        self.workers = set()
        self.rejected = 0
        self.completed = 0
        self.last_reload_ok = True
        self.started = time.monotonic()
        self.generation = 1
        self.open_tokens = float(self.config.maximum_new_connections_per_second)
        self.open_clock = time.monotonic()
        self.config.signing_key = self.signing_key(self.config)
        family = socket.AF_INET if self.config.source_address.version == 4 else socket.AF_INET6
        # Kernel ownership check; no IP_FREEBIND or capability that could bypass it.
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((self.config.source_ip, 0))
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        if family == socket.AF_INET6:
            self.listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((self.config.listen_host, self.config.listen_port))
        self.listener.listen(self.config.maximum_connections)
        self.listener.settimeout(0.5)
        self.write_health()

    @staticmethod
    def signing_key(cfg):
        k = serialization.load_pem_private_key(
            read_file(cfg.proxy_signing_key, secret=True), password=None
        )
        if not isinstance(k, Ed25519PrivateKey):
            raise ValueError("invalid_server_signing_key")
        return k

    def write_health(self):
        with self.lock:
            v = {
                "schema": "aegis.proxy.health.v1",
                "version": "1.0.0",
                "state": self.state,
                "pid": os.getpid(),
                "observed_at": time.time(),
                "uptime_seconds": int(time.monotonic() - self.started),
                "active_connections": len(self.sessions),
                "maximum_connections": self.config.maximum_connections,
                "configuration_digest": self.config.digest,
                "configuration_version": self.config.configuration_version,
                "reload_ok": self.last_reload_ok,
                "completed_connections": self.completed,
                "rejected_connections": self.rejected,
                "certificate_expires_at": self.config.certificate_expires_at,
            }
        p = Path(self.config.health_file)
        temp = p.with_name("health.tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(v, f)
        os.replace(temp, p)

    def close_sessions(self, predicate=lambda s: True):
        with self.lock:
            for session in tuple(self.sessions.values()):
                if predicate(session):
                    session["closed"] = True
                    for sock in tuple(session["sockets"]):
                        # shutdown on the underlying descriptor wakes reads; only
                        # the owning worker manipulates the SSL object itself.
                        try:
                            with socket.socket(fileno=os.dup(sock.fileno())) as raw:
                                raw.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

    def change_state(self, state):
        with self.lock:
            self.state = state
        if state == "halted":
            self.close_sessions()

    def reload(self):
        try:
            cfg = load(self.path, allow_test=self.allow_test)
            cfg.signing_key = self.signing_key(cfg)
            old = self.config
            fixed = (
                "listen_host",
                "listen_port",
                "source_ip",
                "edge_id",
                "proxy_id",
                "endpoint_id",
                "deployment_mode",
                "maximum_connections",
                "health_file",
            )
            if any(getattr(old, k) != getattr(cfg, k) for k in fixed):
                raise ValueError("restart_required_for_topology_change")
            with self.lock:
                self.config = cfg
                self.generation += 1
                self.last_reload_ok = True
            # Terminate all sessions on policy/trust reload. This avoids retaining
            # a tunnel under a revoked certificate or superseded destination rule.
            self.close_sessions()
            print(
                json.dumps({"event": "configuration_reloaded", "digest": cfg.digest}),
                flush=True,
            )
        except Exception:
            self.last_reload_ok = False
            # Invalid replacement configuration disables all new/existing traffic.
            self.change_state("halted")
            print('{"event":"configuration_reload_rejected"}', flush=True)

    def serve(self):
        def stop(*_):
            self.stopping = True
            self.change_state("draining")

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGUSR1, lambda *_: self.change_state("draining"))
        signal.signal(signal.SIGUSR2, lambda *_: self.change_state("halted"))
        signal.signal(signal.SIGHUP, lambda *_: setattr(self, "reload_requested", True))
        print('{"event":"proxy_ready","version":"1.0.0"}', flush=True)
        try:
            while not self.stopping:
                if self.reload_requested:
                    self.reload_requested = False
                    self.reload()
                self.write_health()
                try:
                    raw, peer = self.listener.accept()
                except TimeoutError:
                    continue
                peer_ip = ipaddress.ip_address(peer[0])
                cfg = self.config
                with self.lock:
                    now = time.monotonic()
                    rate = cfg.maximum_new_connections_per_second
                    self.open_tokens = min(
                        float(rate), self.open_tokens + (now - self.open_clock) * rate
                    )
                    self.open_clock = now
                    if (
                        self.state != "active"
                        or len(self.sessions) >= cfg.maximum_connections
                        or self.open_tokens < 1
                        or not any(peer_ip in n for n in cfg.allowed_peer_cidrs)
                    ):
                        self.rejected += 1
                        raw.close()
                        continue
                    self.open_tokens -= 1
                    token = object()
                    session = {
                        "sockets": [raw],
                        "closed": False,
                        "fingerprint": None,
                        "generation": self.generation,
                    }
                    self.sessions[token] = session
                    worker = threading.Thread(
                        target=self.handle,
                        args=(token, session, raw, peer_ip, cfg),
                        daemon=True,
                    )
                    self.workers.add(worker)
                    try:
                        worker.start()
                    except BaseException:
                        self.workers.discard(worker)
                        self.sessions.pop(token, None)
                        raw.close()
                        raise
        finally:
            self.listener.close()
            deadline = time.monotonic() + self.config.drain_timeout
            while self.sessions and time.monotonic() < deadline:
                self.write_health()
                time.sleep(0.1)
            self.change_state("halted")
            join_deadline = time.monotonic() + 1
            for w in tuple(self.workers):
                w.join(timeout=max(0, join_deadline - time.monotonic()))
            self.write_health()

    def frame(self, tls, deadline):
        def read(n):
            data = bytearray()
            while len(data) < n:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Rejected("header_timeout")
                tls.settimeout(remaining)
                b = tls.recv(n - len(data))
                if not b:
                    raise Rejected("unexpected_eof")
                data.extend(b)
            return bytes(data)

        size = struct.unpack("!I", read(4))[0]
        if not 1 <= size <= 4096:
            raise Rejected("frame_size_invalid")
        from server_config import unique

        value = json.loads(read(size), object_pairs_hook=unique)
        if not isinstance(value, dict):
            raise Rejected("request_schema_invalid")
        return value

    def admit(self, request, binding, key, peer, cfg, session):
        try:
            v = _verify_signed(request, key)
        except (ValueError, TypeError):
            raise Rejected("signature_invalid") from None
        required = {
            "version",
            "request_id",
            "edge_id",
            "proxy_id",
            "endpoint_id",
            "configuration_version",
            "destination_ip",
            "destination_port",
            "issued_at",
            "expires_at",
            "channel_binding",
        }
        if set(v) != required or v["version"] != PROTOCOL_VERSION:
            raise Rejected("request_schema_invalid")
        for k in ("edge_id", "proxy_id", "endpoint_id", "configuration_version"):
            if v[k] != getattr(cfg, k):
                raise Rejected("identity_not_authorized")
        request_id = v["request_id"]
        if not isinstance(request_id, str) or not re.fullmatch("[A-Za-z0-9_-]{8,64}", request_id):
            raise Rejected("request_id_invalid")
        if not binding or v["channel_binding"] != _encode(hashlib.sha256(binding).digest()):
            raise Rejected("channel_binding_invalid")
        now = int(time.time())
        issued, expires = v["issued_at"], v["expires_at"]
        if (
            type(issued) is not int
            or type(expires) is not int
            or not 1 <= expires - issued <= 30
            or issued > now + 5
            or expires <= now
        ):
            raise Rejected("request_expired")
        if type(v["destination_port"]) is not int or v["destination_port"] != 25:
            raise Rejected("destination_port_not_allowed")
        if not isinstance(v["destination_ip"], str):
            raise Rejected("destination_not_allowed")
        try:
            destination = ipaddress.ip_address(v["destination_ip"])
        except ValueError:
            raise Rejected("destination_not_allowed") from None
        if (
            destination.version != cfg.source_address.version
            or destination.is_multicast
            or destination.is_unspecified
            or getattr(destination, "ipv4_mapped", None)
            or getattr(destination, "sixtofour", None)
            or getattr(destination, "teredo", None)
        ):
            raise Rejected("destination_not_allowed")
        if cfg.deployment_mode == "production" and (
            not destination.is_global or destination in (peer, cfg.source_address)
        ):
            raise Rejected("destination_not_allowed")
        if not any(destination in n for n in cfg.allowed_destination_cidrs) or any(
            destination in n for n in cfg.denied_destination_cidrs
        ):
            raise Rejected("destination_not_allowed")
        with self.lock:
            if (
                self.state != "active"
                or session["closed"]
                or session["generation"] != self.generation
            ):
                raise Rejected("proxy_not_active")
            self.replays = {k: e for k, e in self.replays.items() if e >= now}
            if request_id in self.replays:
                raise Rejected("request_replayed")
            if len(self.replays) >= cfg.maximum_connections * 64:
                raise Rejected("request_capacity_reached")
            self.replays[request_id] = expires
        return str(destination), request_id

    def response(self, tls, cfg, request_id, status, reason):
        value = _signed(
            {
                "version": PROTOCOL_VERSION,
                "request_id": request_id,
                "proxy_id": cfg.proxy_id,
                "status": status,
                "reason": reason,
                "observed_at": int(time.time()),
            },
            cfg.signing_key,
        )
        payload = _canonical(value)
        tls.settimeout(cfg.header_timeout)
        tls.sendall(struct.pack("!I", len(payload)) + payload)

    def handle(self, token, session, raw, peer, cfg):
        tls = remote = None
        request_id = "unknown"
        terminal = "tls_rejected"
        counts = [0, 0]
        start = time.monotonic()
        try:
            # One absolute deadline covers TLS handshake plus complete framed header.
            deadline = start + cfg.header_timeout
            raw.settimeout(cfg.header_timeout)
            tls = cfg.tls_context.wrap_socket(raw, server_side=True)
            with self.lock:
                session["sockets"] = [tls]
            fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            key = cfg.client_keys.get(fingerprint)
            if key is None:
                raise Rejected("client_certificate_revoked")
            session["fingerprint"] = fingerprint
            request = self.frame(tls, deadline)
            if isinstance(request.get("request_id"), str) and re.fullmatch(
                "[A-Za-z0-9_-]{8,64}", request["request_id"]
            ):
                request_id = request["request_id"]
            try:
                dest, request_id = self.admit(
                    request,
                    tls.get_channel_binding("tls-unique"),
                    key,
                    peer,
                    cfg,
                    session,
                )
                family = socket.AF_INET if cfg.source_address.version == 4 else socket.AF_INET6
                remote = socket.socket(family, socket.SOCK_STREAM)
                with self.lock:
                    session["sockets"].append(remote)
                remote.settimeout(cfg.connect_timeout)
                remote.bind((cfg.source_ip, 0))
                remote.connect((dest, 25))
                if session["closed"]:
                    raise Rejected("proxy_not_active")
            except (Rejected, OSError) as e:
                reason = str(e) if isinstance(e, Rejected) else "destination_connect_failed"
                self.response(tls, cfg, request_id, "rejected", reason)
                terminal = reason
                return
            self.response(tls, cfg, request_id, "accepted", "connection_admitted")
            counts, terminal = relay(
                tls,
                remote,
                idle_timeout=cfg.idle_timeout,
                session_timeout=max(0.001, cfg.session_timeout - (time.monotonic() - start)),
                byte_limit=cfg.maximum_session_bytes,
                stopped=lambda: session["closed"],
            )
        except Rejected as e:
            terminal = str(e)
        except TimeoutError:
            terminal = "connection_timeout"
        except ssl.SSLError:
            terminal = "tls_rejected"
        except (ValueError, TypeError, OverflowError, RecursionError):
            terminal = "request_invalid"
        except OSError:
            terminal = "connection_closed"
        finally:
            for sock in (remote, tls, raw):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            with self.lock:
                self.sessions.pop(token, None)
                self.workers.discard(threading.current_thread())
                self.completed += 1
            evidence = {
                "schema": "aegis.egress_proxy.connection.v1",
                "request_id": request_id,
                "endpoint_id": cfg.endpoint_id,
                "configuration_version": cfg.configuration_version,
                "terminal": terminal,
                "bytes_from_edge": counts[0],
                "bytes_from_destination": counts[1],
                "duration_ms": int((time.monotonic() - start) * 1000),
            }
            print(
                json.dumps(
                    {"event": "proxy_evidence", **_signed(evidence, cfg.signing_key)},
                    sort_keys=True,
                ),
                flush=True,
            )
