"""Isolated container verification for the inbound Postfix catch-all receiver.

Runs with no external network traffic: a local mock DNS+SMTP sink on a private
Docker bridge proves Postfix smtp(8) resolves MX/A records from /etc/resolv.conf
without /var/spool/postfix/etc/resolv.conf, rejects foreign relays, SRS-rewrites
envelope senders, and forwards assigned-domain mail to the configured inbox.
"""

import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

MOCK_SINK = """
import json, socket, struct, sys, threading
from pathlib import Path

mx_ip = sys.argv[1]
out_path = Path("/tmp/captured.json")
dns_queries = []
smtp_events = []

def enc(name):
    parts = [p.encode() for p in name.rstrip(".").split(".")]
    return b"".join(bytes([len(p)]) + p for p in parts) + b"\\x00"

def dec(pkt, off):
    labels = []
    while True:
        n = pkt[off]; off += 1
        if n == 0:
            break
        labels.append(pkt[off:off + n].decode()); off += n
    return ".".join(labels).lower(), off

def dns_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        pkt, addr = sock.recvfrom(4096)
        qname, off = dec(pkt, 12)
        qtype, _ = struct.unpack("!HH", pkt[off:off + 4])
        dns_queries.append([qname, qtype])
        question = pkt[12:off + 4]
        ans = []
        if qname == "dest.test" and qtype == 15:
            rdata = struct.pack("!H", 10) + enc("mx1.dest.test")
            ans.append(b"\\xc0\\x0c" + struct.pack("!HHIH", 15, 1, 60, len(rdata)) + rdata)
        elif qname == "mx1.dest.test" and qtype == 1:
            rdata = socket.inet_aton(mx_ip)
            ans.append(b"\\xc0\\x0c" + struct.pack("!HHIH", 1, 1, 60, len(rdata)) + rdata)
        hdr = pkt[:2] + struct.pack("!HHHHH", 0x8180, 1, len(ans), 0, 0)
        sock.sendto(hdr + question + b"".join(ans), addr)
        out_path.write_text(json.dumps({"dns_queries": dns_queries, "smtp_events": smtp_events}))

def smtp_loop():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 25))
    srv.listen(5)
    while True:
        conn, _ = srv.accept()
        with conn:
            conn.sendall(b"220 mx1.dest.test ESMTP\\r\\n")
            stream = conn.makefile("rwb", buffering=0)
            ev = {"mail_from": None, "rcpt_to": [], "data": ""}
            in_data = False
            buf = []
            for raw in stream:
                line = raw.decode("utf-8", "replace")
                if in_data:
                    if line in (".\\r\\n", ".\\n"):
                        in_data = False
                        ev["data"] = "".join(buf)
                        smtp_events.append(ev)
                        out_path.write_text(
                            json.dumps({"dns_queries": dns_queries, "smtp_events": smtp_events})
                        )
                        conn.sendall(b"250 OK\\r\\n")
                    else:
                        buf.append(line)
                    continue
                upper = line.upper()
                if upper.startswith(("EHLO", "HELO")):
                    conn.sendall(b"250 mx1.dest.test\\r\\n")
                elif upper.startswith("MAIL FROM:"):
                    ev["mail_from"] = line.strip()
                    conn.sendall(b"250 OK\\r\\n")
                elif upper.startswith("RCPT TO:"):
                    ev["rcpt_to"].append(line.strip())
                    conn.sendall(b"250 OK\\r\\n")
                elif upper.startswith("DATA"):
                    in_data = True
                    conn.sendall(b"354 Go ahead\\r\\n")
                elif upper.startswith("QUIT"):
                    conn.sendall(b"221 Bye\\r\\n")
                    break
                else:
                    conn.sendall(b"250 OK\\r\\n")

threading.Thread(target=dns_loop, daemon=True).start()
smtp_loop()
"""


def smtp_cmd(sock: socket.socket, cmd: str) -> str:
    sock.sendall((cmd + "\r\n").encode())
    return sock.recv(4096).decode()


def main() -> None:
    image = sys.argv[1] if len(sys.argv) > 1 else "aegis-inbound:test"
    stamp = int(time.time())
    net_name = f"aegis-inbound-ci-{stamp}"
    sink_name = f"{net_name}-sink"
    recv_name = f"{net_name}-recv"
    vol_name = f"{net_name}-spool"

    with tempfile.TemporaryDirectory(prefix="aegis-inbound-ci-") as tmp:
        tmp_dir = Path(tmp)
        cfg_path = tmp_dir / "config.json"
        cfg_path.write_text(
            json.dumps(
                {
                    "domain": "inbound.test",
                    "hostname": "mx.inbound.test",
                    "shared_inbox": "dtfbl@dest.test",
                    "listen_address": "all",
                }
            )
        )
        sink_script = tmp_dir / "mock_sink.py"
        sink_script.write_text(MOCK_SINK)

        try:
            subprocess.run(["docker", "network", "create", "--internal", net_name], check=True)
            subprocess.run(["docker", "volume", "create", vol_name], check=True)
            subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    sink_name,
                    "--network",
                    net_name,
                    "-v",
                    f"{sink_script}:/mock.py:ro",
                    "--entrypoint",
                    "python3",
                    image,
                    "-c",
                    (
                        "import socket, subprocess; "
                        "ip = socket.gethostbyname(socket.gethostname()); "
                        "subprocess.run(['python3', '/mock.py', ip], check=True)"
                    ),
                ],
                check=True,
            )
            sink_ip = subprocess.check_output(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    sink_name,
                ],
                text=True,
            ).strip()
            time.sleep(1)

            subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    recv_name,
                    "--network",
                    net_name,
                    "--dns",
                    sink_ip,
                    "--security-opt",
                    "no-new-privileges:true",
                    "-v",
                    f"{cfg_path}:/run/aegis-inbound/config.json:ro",
                    "-v",
                    f"{vol_name}:/var/spool/postfix",
                    image,
                ],
                check=True,
            )

            for _ in range(40):
                rc = subprocess.run(
                    [
                        "docker",
                        "exec",
                        recv_name,
                        "python3",
                        "/usr/local/lib/aegis-inbound/runtime.py",
                        "health",
                    ],
                    capture_output=True,
                ).returncode
                if rc == 0:
                    break
                time.sleep(0.5)
            else:
                logs = subprocess.check_output(["docker", "logs", recv_name], text=True)
                raise RuntimeError(f"inbound receiver failed health check:\n{logs}")

            chroot_out = subprocess.check_output(
                ["docker", "exec", recv_name, "postconf", "-F", "*/*/chroot"], text=True
            )
            assert "smtp/unix/chroot = n" in chroot_out, chroot_out
            assert "= y" not in chroot_out, chroot_out
            spool_resolv = subprocess.run(
                ["docker", "exec", recv_name, "test", "-e", "/var/spool/postfix/etc/resolv.conf"]
            ).returncode
            assert spool_resolv != 0, "expected /var/spool/postfix/etc/resolv.conf to be absent"

            # Inject SMTP from inside the internal network via the sink container so
            # --internal works identically on every runner without host-bridge routing.
            client_code = (
                "import socket, sys; "
                "host = sys.argv[1]; "
                "s = socket.create_connection((host, 25), timeout=5); "
                "assert s.recv(4096).startswith(b'220 '); "
                "send = lambda c: (s.sendall((c + '\\r\\n').encode()), s.recv(4096).decode())[1]; "
                "assert send('EHLO tester.example').startswith('250'); "
                "assert send('MAIL FROM:<sender@external.test>').startswith('250'); "
                "assert send('RCPT TO:<nobody@foreign.test>').startswith(('454', '554')); "
                "assert send('RCPT TO:<probe@inbound.test>').startswith('250'); "
                "assert send('DATA').startswith('354'); "
                "s.sendall(b'From: sender@external.test\\r\\nTo: probe@inbound.test\\r\\n"
                "Subject: CI chroot DNS check\\r\\n\\r\\nhello\\r\\n.\\r\\n'); "
                "assert s.recv(4096).decode().startswith('250'); "
                "send('QUIT')"
            )
            recv_ip = subprocess.check_output(
                [
                    "docker",
                    "inspect",
                    "-f",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    recv_name,
                ],
                text=True,
            ).strip()
            subprocess.run(
                ["docker", "exec", sink_name, "python3", "-c", client_code, recv_ip],
                check=True,
            )

            captured = None
            for _ in range(40):
                res = subprocess.run(
                    ["docker", "exec", sink_name, "cat", "/tmp/captured.json"],
                    capture_output=True,
                    text=True,
                )
                if res.returncode == 0:
                    data = json.loads(res.stdout)
                    if data.get("smtp_events"):
                        captured = data
                        break
                time.sleep(0.5)
            if not captured:
                logs = subprocess.check_output(["docker", "logs", recv_name], text=True)
                raise RuntimeError(f"message was not forwarded to mock MX:\n{logs}")

            assert ["dest.test", 15] in captured["dns_queries"], captured["dns_queries"]
            assert ["mx1.dest.test", 1] in captured["dns_queries"], captured["dns_queries"]
            event = captured["smtp_events"][0]
            assert "SRS0=" in event["mail_from"] and "@inbound.test>" in event["mail_from"], event
            assert any("dtfbl@dest.test" in rcpt for rcpt in event["rcpt_to"]), event
            print("inbound container DNS/MX/SRS verification passed")
        finally:
            for container in (recv_name, sink_name):
                subprocess.run(["docker", "rm", "-f", container], capture_output=True)
            subprocess.run(["docker", "volume", "rm", "-f", vol_name], capture_output=True)
            subprocess.run(["docker", "network", "rm", net_name], capture_output=True)


if __name__ == "__main__":
    main()
