"""One worker owns TLS I/O; both directions have bounded buffering and deadlines."""

import select
import socket
import ssl
import time

BUFFER = 65536


def relay(tls, remote, *, idle_timeout, session_timeout, byte_limit, stopped):
    tls.setblocking(False)
    remote.setblocking(False)
    start = last = time.monotonic()
    to_remote = bytearray()
    to_tls = bytearray()
    counts = [0, 0]
    read_tls = read_remote = True
    remote_shutdown = False
    tls_recv_wants_write = tls_send_wants_read = False
    while True:
        now = time.monotonic()
        if stopped():
            return counts, "administrative_close"
        if now - start >= session_timeout:
            return counts, "session_timeout"
        if now - last >= idle_timeout:
            return counts, "idle_timeout"
        if not read_tls and not to_remote and not remote_shutdown:
            try:
                remote.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            remote_shutdown = True
        # The destination's final EOF terminates a drained TLS stream. Never invoke
        # SSLSocket.shutdown(): it discards Python's SSL object and corrupts reads.
        if not read_remote and not to_tls and not to_remote:
            return counts, "stream_closed"
        readers = []
        writers = []
        if (read_tls and len(to_remote) < BUFFER) or (to_tls and tls_send_wants_read):
            readers.append(tls)
        if read_remote and len(to_tls) < BUFFER:
            readers.append(remote)
        if (to_tls and not tls_send_wants_read) or tls_recv_wants_write:
            writers.append(tls)
        if to_remote:
            writers.append(remote)
        wait = min(0.5, idle_timeout - (now - last), session_timeout - (now - start))
        if read_tls and len(to_remote) < BUFFER and tls.pending():
            wait = 0
        ready_r, ready_w, _ = select.select(readers, writers, [], max(0, wait))
        if (
            read_tls
            and len(to_remote) < BUFFER
            and (tls in ready_r or (tls_recv_wants_write and tls in ready_w) or tls.pending())
        ):
            try:
                b = tls.recv(min(BUFFER - len(to_remote), byte_limit - sum(counts) + 1))
                tls_recv_wants_write = False
                if b:
                    if sum(counts) + len(b) > byte_limit:
                        return counts, "byte_limit"
                    to_remote.extend(b)
                    counts[0] += len(b)
                    last = time.monotonic()
                else:
                    read_tls = False
            except ssl.SSLWantReadError:
                tls_recv_wants_write = False
            except ssl.SSLWantWriteError:
                tls_recv_wants_write = True
        if read_remote and len(to_tls) < BUFFER and remote in ready_r:
            try:
                b = remote.recv(min(BUFFER - len(to_tls), byte_limit - sum(counts) + 1))
                if b:
                    if sum(counts) + len(b) > byte_limit:
                        return counts, "byte_limit"
                    to_tls.extend(b)
                    counts[1] += len(b)
                    last = time.monotonic()
                else:
                    read_remote = False
            except BlockingIOError:
                pass
        if to_remote and remote in ready_w:
            try:
                n = remote.send(to_remote)
                del to_remote[:n]
                if n:
                    last = time.monotonic()
            except BlockingIOError:
                pass
        if to_tls and (tls in ready_w or (tls_send_wants_read and tls in ready_r)):
            try:
                n = tls.send(to_tls)
                del to_tls[:n]
                tls_send_wants_read = False
                if n:
                    last = time.monotonic()
            except ssl.SSLWantReadError:
                tls_send_wants_read = True
            except ssl.SSLWantWriteError:
                tls_send_wants_read = False
