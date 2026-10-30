"""Connection-only authenticated probe: no SMTP commands or recipient data."""

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from proxy_runtime import _native_open

p = argparse.ArgumentParser()
p.add_argument("--bundle", required=True)
p.add_argument("--destination", required=True)
a = p.parse_args()
root = Path(a.bundle)
m = json.loads((root / "metadata.json").read_text())
edge = root / "edge"
args = SimpleNamespace(
    proxy_host=m["proxy_host"],
    proxy_port=m["proxy_port"],
    edge_id=m["edge_id"],
    proxy_id=m["proxy_id"],
    endpoint_id=m["endpoint_id"],
    configuration_version=str(m["endpoint_configuration_version"]),
    connect_timeout=5,
    header_timeout=5,
    ca_file=str(edge / "ca.pem"),
    client_cert=str(edge / "client.pem"),
    client_key=str(edge / "client.key"),
    edge_signing_key=str(edge / "edge-signing.key"),
    proxy_signing_public_key=str(edge / "proxy-signing-public.pem"),
    proxy_server_name=m["tls_server_name"],
    no_client_cert=False,
    channel_binding_mismatch=False,
)
connection, response = _native_open(args, destination=a.destination, destination_port=25)
connection.close()
print(json.dumps(response))
raise SystemExit(0 if response.get("status") == "accepted" else 1)
