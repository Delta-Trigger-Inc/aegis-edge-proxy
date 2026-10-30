from __future__ import annotations

import socket
import struct

import pytest

from proxy_runtime import (
    _receive_frame,
    _send_frame,
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
