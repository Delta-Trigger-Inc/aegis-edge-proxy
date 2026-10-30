"""Standalone native proxy reference preview; extracted without behavior changes."""
from __future__ import annotations
import argparse,base64,hashlib,ipaddress,json,signal,socket,ssl,struct,threading,time,uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey
MAX_FRAME_BYTES=4096
PROTOCOL_VERSION="aegis-egress-v1"


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

def _receive_exact(connection: socket.socket, count: int) -> bytes:
    value = bytearray()
    while len(value) < count:
        chunk = connection.recv(count - len(value))
        if not chunk:
            raise ConnectionError("unexpected_eof")
        value.extend(chunk)
    return bytes(value)

def _receive_frame(connection: socket.socket) -> dict[str, Any]:
    size = struct.unpack("!I", _receive_exact(connection, 4))[0]
    if size < 2 or size > MAX_FRAME_BYTES:
        raise ValueError("frame_size_invalid")

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("frame_duplicate_key")
            value[key] = item
        return value

    value = json.loads(_receive_exact(connection, size), object_pairs_hook=strict_object)
    if not isinstance(value, dict):
        raise ValueError("frame_not_object")
    return value

def _copy(source: socket.socket, destination: socket.socket, counts: list[int], index: int) -> None:
    try:
        while True:
            payload = source.recv(65536)
            if not payload:
                break
            destination.sendall(payload)
            counts[index] += len(payload)
    except (ConnectionError, OSError, ssl.SSLError):
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def _tunnel(left: socket.socket, right: socket.socket) -> tuple[int, int]:
    counts = [0, 0]
    threads = (
        threading.Thread(target=_copy, args=(left, right, counts, 0), daemon=True),
        threading.Thread(target=_copy, args=(right, left, counts, 1), daemon=True),
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return counts[0], counts[1]

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
        response = _receive_frame(connection)
        values = _verify_signed(response, _public_key(args.proxy_signing_public_key))
        if values.get("request_id") != request["request_id"]:
            raise ValueError("response_request_mismatch")
        connection.settimeout(None)
        return connection, values
    except Exception:
        (connection if connection is not None else raw).close()
        raise

class NativeProxy:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.signing_key = _private_key(args.proxy_signing_key)
        self.edge_public_key = _public_key(args.edge_signing_public_key)
        self.destination_networks = tuple(
            ipaddress.ip_network(value) for value in args.allowed_destination_cidr
        )
        self.seen_requests: dict[str, int] = {}
        self.state = "active"
        self.lock = threading.Lock()
        self.active: set[socket.socket] = set()
        self.active_count = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((args.listen_host, args.listen_port))
        self.listener.listen(args.maximum_connections)
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(args.server_cert, args.server_key)
        self.context.load_verify_locations(args.ca_file)
        self.context.verify_mode = ssl.CERT_REQUIRED
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self._health()

    def _set_state(self, state: str) -> None:
        with self.lock:
            self.state = state
            active = tuple(self.active) if state == "halted" else ()
        for connection in active:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self._health()
        _event("proxy_state", state=state)

    def close(self, *_unused: object) -> None:
        self._set_state("halted")
        self.listener.close()

    def serve(self) -> None:
        signal.signal(signal.SIGTERM, self.close)
        signal.signal(signal.SIGINT, self.close)
        signal.signal(signal.SIGUSR1, lambda *_: self._set_state("draining"))
        signal.signal(signal.SIGUSR2, lambda *_: self._set_state("halted"))
        signal.signal(signal.SIGHUP, lambda *_: self._set_state("active"))
        _event("proxy_ready", state=self.state)
        while True:
            try:
                connection, _address = self.listener.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _response(self, request_id: str, status: str, reason: str) -> dict[str, Any]:
        return _signed(
            {
                "version": PROTOCOL_VERSION,
                "request_id": request_id,
                "proxy_id": self.args.proxy_id,
                "status": status,
                "reason": reason,
                "observed_at": int(time.time()),
            },
            self.signing_key,
        )

    def _admit(
        self,
        request: dict[str, Any],
        *,
        channel_binding: bytes,
    ) -> tuple[str, int, str]:
        values = _verify_signed(request, self.edge_public_key)
        now = int(time.time())
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
        if set(values) != required or values["version"] != PROTOCOL_VERSION:
            raise ValueError("request_schema_invalid")
        if values["edge_id"] != self.args.edge_id or values["proxy_id"] != self.args.proxy_id:
            raise ValueError("identity_not_authorized")
        if values["endpoint_id"] != self.args.endpoint_id:
            raise ValueError("endpoint_not_authorized")
        if values["configuration_version"] != self.args.configuration_version:
            raise ValueError("configuration_version_invalid")
        expected_channel = _encode(hashlib.sha256(channel_binding).digest())
        if values["channel_binding"] != expected_channel:
            raise ValueError("channel_binding_invalid")
        if not isinstance(values["issued_at"], int) or not isinstance(values["expires_at"], int):
            raise ValueError("request_time_invalid")
        if values["issued_at"] > now + 5 or values["expires_at"] < now:
            raise ValueError("request_expired")
        if values["expires_at"] - values["issued_at"] > 30:
            raise ValueError("request_window_invalid")
        request_id = str(values["request_id"])
        if len(request_id) < 8 or len(request_id) > 64:
            raise ValueError("request_id_invalid")
        destination_ip = ipaddress.ip_address(str(values["destination_ip"]))
        if not any(destination_ip in network for network in self.destination_networks):
            raise ValueError("destination_not_allowed")
        destination_port = values["destination_port"]
        if destination_port != 25:
            raise ValueError("destination_port_not_allowed")
        with self.lock:
            self.seen_requests = {
                key: expiry for key, expiry in self.seen_requests.items() if expiry >= now
            }
            if self.state != "active":
                raise ValueError("proxy_" + self.state)
            if request_id in self.seen_requests:
                raise ValueError("request_replayed")
            if len(self.seen_requests) >= self.args.maximum_connections * 64:
                raise ValueError("replay_cache_full")
            if self.active_count >= self.args.maximum_connections:
                raise ValueError("connection_limit_reached")
            self.seen_requests[request_id] = int(values["expires_at"])
            self.active_count += 1
        return str(destination_ip), destination_port, request_id

    def _dial(self, destination: str, port: int) -> socket.socket:
        family = socket.AF_INET6 if ":" in destination else socket.AF_INET
        connection = socket.socket(family, socket.SOCK_STREAM)
        connection.settimeout(self.args.connect_timeout)
        source = (
            (self.args.source_ip, 0, 0, 0)
            if family == socket.AF_INET6
            else (self.args.source_ip, 0)
        )
        connection.bind(source)
        connection.connect((destination, port))
        connection.settimeout(None)
        return connection

    def _health(self) -> None:
        if not self.args.health_file:
            return
        with self.lock:
            value = {
                "schema": "aegis.egress_proxy.health.v1",
                "state": self.state,
                "active_connections": self.active_count,
                "maximum_connections": self.args.maximum_connections,
                "configuration_version": self.args.configuration_version,
            }
        Path(self.args.health_file).write_text(json.dumps(value, sort_keys=True) + "\n")

    def _handle(self, raw: socket.socket) -> None:
        inbound: ssl.SSLSocket | None = None
        outbound: socket.socket | None = None
        request_id = "unknown"
        endpoint_id = self.args.endpoint_id
        destination_digest = ""
        terminal = "tls_rejected"
        started = time.monotonic()
        byte_counts = (0, 0)
        reserved = False
        try:
            raw.settimeout(self.args.header_timeout)
            inbound = self.context.wrap_socket(raw, server_side=True)
            channel_binding = inbound.get_channel_binding("tls-unique")
            if not channel_binding:
                raise ssl.SSLError("TLS channel binding is unavailable")
            request = _receive_frame(inbound)
            if isinstance(request.get("request_id"), str):
                request_id = request["request_id"]
            try:
                destination, port, request_id = self._admit(
                    request,
                    channel_binding=channel_binding,
                )
                reserved = True
                destination_digest = hashlib.sha256(f"{destination}:{port}".encode()).hexdigest()
                outbound = self._dial(destination, port)
            except (ValueError, OSError) as exc:
                reason = _fixed_error(exc)
                _send_frame(inbound, self._response(request_id, "rejected", reason))
                terminal = reason
                return
            with self.lock:
                self.active.update((inbound, outbound))
            self._health()
            _send_frame(inbound, self._response(request_id, "accepted", "connection_admitted"))
            inbound.settimeout(None)
            byte_counts = _tunnel(inbound, outbound)
            terminal = "stream_closed"
        except (ConnectionError, OSError, ValueError, ssl.SSLError) as exc:
            terminal = _fixed_error(exc)
        finally:
            for connection in (inbound, outbound, raw):
                if connection is not None:
                    with self.lock:
                        self.active.discard(connection)
                    try:
                        connection.close()
                    except OSError:
                        pass
            if reserved:
                with self.lock:
                    self.active_count -= 1
            self._health()
            evidence = {
                "schema": "aegis.egress_proxy.connection.v1",
                "request_id": request_id,
                "endpoint_id": endpoint_id,
                "configuration_version": self.args.configuration_version,
                "destination_digest": destination_digest,
                "terminal": terminal,
                "bytes_from_edge": byte_counts[0],
                "bytes_from_destination": byte_counts[1],
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
            _event("proxy_evidence", **_signed(evidence, self.signing_key))

def _fixed_error(error: BaseException) -> str:
    text = str(error)
    allowed = {
        "configuration_version_invalid",
        "channel_binding_invalid",
        "connection_limit_reached",
        "destination_not_allowed",
        "destination_port_not_allowed",
        "endpoint_not_authorized",
        "frame_not_object",
        "frame_duplicate_key",
        "frame_size_invalid",
        "frame_too_large",
        "identity_not_authorized",
        "proxy_draining",
        "proxy_halted",
        "request_expired",
        "request_id_invalid",
        "request_replayed",
        "replay_cache_full",
        "request_schema_invalid",
        "request_time_invalid",
        "request_window_invalid",
        "signature_missing",
        "signature_invalid",
        "unexpected_eof",
    }
    if text in allowed:
        return text
    if isinstance(error, ssl.SSLError):
        return "tls_rejected"
    if isinstance(error, TimeoutError | socket.timeout):
        return "connection_timeout"
    if isinstance(error, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(error, OSError):
        return "connection_failed"
    return "request_invalid"

def _event(event: str, **values: Any) -> None:
    print(json.dumps({"event": event, **values}, sort_keys=True), flush=True)
