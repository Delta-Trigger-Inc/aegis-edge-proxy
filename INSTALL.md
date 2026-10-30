# Production installation

Use a maintained Linux host (Ubuntu 24.04 LTS or later is recommended), synchronized
clock, an assigned public source IP, outbound TCP 25, and Docker Engine with Compose
v2+. Follow [Docker's supported OS/install instructions](https://docs.docker.com/engine/install/ubuntu/).
Do not install this on the Cloud host. Multiple sending IPs use separate projects,
bundles and listeners. Never add an unassigned IP or enable freebind.

## 1. Download and pin the image

Download the source archive, SHA256SUMS, RELEASE.json, and the image archive for
`uname -m` (x86_64 → amd64; aarch64 → arm64) from the
[1.0.0 release](https://github.com/Delta-Trigger-Inc/aegis-edge-proxy/releases/tag/v1.0.0).
The release contains no private configuration. On Linux, in that download directory:

```sh
sha256sum --ignore-missing -c SHA256SUMS
docker load --input aegis-edge-proxy-1.0.0-linux-amd64.tar.gz
tar -xzf aegis-edge-proxy-1.0.0.tar.gz
cd aegis-edge-proxy-1.0.0
```

Use the corresponding arm64 filename when appropriate. Compare the loaded image's
ID, architecture, user and revision with RELEASE.json, then set `AEGIS_PROXY_IMAGE`
to that exact `sha256:...` image ID. Compose uses `pull_policy: never`.

```sh
docker image inspect aegis-edge-proxy:1.0.0-amd64
export AEGIS_PROXY_IMAGE=sha256:REPLACE_WITH_VERIFIED_IMAGE_ID
```

Alternatively build the checked source with `docker build --build-arg
SOURCE_REVISION=RELEASE_COMMIT -t aegis-edge-proxy:1.0.0 .` and pin its actual local
image ID. A locally rebuilt image need not have the prebuilt archive's image ID.

## 2. Generate private credentials on the trusted Edge/operator host

Load the release image there too. Set these variables to your actual enrolled
agent, unique endpoint/proxy IDs, Edge public outbound IP, assigned proxy IP and
TLS name. The TLS name may match the sender EHLO but serves a separate purpose.

```sh
umask 077
mkdir -p "$HOME/aegis-proxy-private"
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --entrypoint /usr/bin/python3 -v "$HOME/aegis-proxy-private:/private" \
  "$AEGIS_PROXY_IMAGE" /app/create_pair.py \
  --edge-id "$EDGE_AGENT_ID" --proxy-id "$PROXY_ID" --endpoint-id "$ENDPOINT_ID" \
  --source-ip "$SOURCE_IP" --edge-peer-cidr "$EDGE_PUBLIC_IP/32" \
  --server-name "$TLS_NAME" --allowed-destination-cidr 0.0.0.0/0 \
  --output "/private/$ENDPOINT_ID"
```

The production policy still rejects non-global/self destinations even with
0.0.0.0/0. Use narrower public destination CIDRs if required. IPv6-only deployments
need matching IPv6 source, peer and destination CIDRs; the released Edge/Postfix
companion topology is IPv4, so IPv6 is not part of its integration certification.

Keep the entire original bundle on the trusted operator host for renewal. Transfer
only `proxy/` to `/opt/aegis-proxy/ENDPOINT/proxy` on the assigned proxy host over
an authenticated connection. Never put bundles in GitHub or image layers. CA and
Edge private keys must not be installed on the proxy. The helper refuses overwrite.

## 3. Host restrictions and credential custody

Verify the source IP in `ip -4 addr`, port 5443 availability in `ss -lnt`, outbound
TCP 25 and NTP. In provider and host firewalls, allow inbound TCP 5443 only from
the Edge public IP and deny all other sources. Preserve SSH access. An allow rule
alone is not a deny policy; audit broad existing rules before changing anything.
The Compose service uses Linux [host networking](https://docs.docker.com/engine/network/drivers/host/)
so it can bind the actual source IP. No Docker port publication is used. Host INPUT
rules therefore protect its listener. It does not listen for inbound SMTP on 25.

```sh
sudo chown -R root:10001 /opt/aegis-proxy/ENDPOINT/proxy
sudo find /opt/aegis-proxy/ENDPOINT/proxy -type d -exec chmod 750 {} +
sudo find /opt/aegis-proxy/ENDPOINT/proxy -type f -exec chmod 640 {} +
export AEGIS_PROXY_BUNDLE=/opt/aegis-proxy/ENDPOINT/proxy
```

Store the two environment values in a root-readable deployment file or supply
them consistently on every command. Do not place secret PEM contents in environment
variables. The service runs as UID/GID 10001 with no capabilities.

## 4. Validate and start

```sh
docker compose -p ENDPOINT config --quiet
docker compose -p ENDPOINT run --rm --no-deps proxy --check
docker compose -p ENDPOINT up -d
docker compose -p ENDPOINT exec -T proxy /usr/bin/python3 /app/proxy.py --health
docker compose -p ENDPOINT logs --tail 30 proxy
```

The runtime contains no shell or `cat`. To inspect health:

```sh
docker compose -p ENDPOINT exec -T proxy /usr/bin/python3 -c \
  'from pathlib import Path; print(Path("/run/aegis-health/health.json").read_text())'
```

From Edge (the firewall-authorized source), test an approved receiver's resolved
public MX IP without sending a message:

```sh
docker run --rm --network host --user "$(id -u):$(id -g)" \
  --entrypoint /usr/bin/python3 -v "$HOME/aegis-proxy-private:/private:ro" \
  "$AEGIS_PROXY_IMAGE" /app/probe.py --bundle "/private/$ENDPOINT_ID" \
  --destination "$APPROVED_MX_IP"
```

Expect a signed accepted response. Verify the intended source IP independently
at a controlled receiver. Check that unauthorized peers cannot access 5443.

## 5. Register the Edge transport and commission the sender

Use the installed Edge endpoint staging API, NativeConfiguration service and
native-delivery exporter. Do not hand-edit the encrypted database or create a
parallel SMTP submission listener. The endpoint ID, agent ID, proxy ID, source IP,
port 5443, configuration version and TLS server name must match the bundle exactly.
The `edge/security-profile.json` file is an exporter input, not a complete registry.
Register backend `aegis_proxy_v1`, the profile's digest, and the private route binding.

Copy `edge/` to the Postfix companion's indicated `/run/aegis-egress/ENDPOINT`
location, readable only by connector UID/GID 10002. Mount it read-only. Install
matching Edge and Postfix builds with the hardened connector, the per-attempt
policy service, and the protected local DSN receiving companion. Preserve the
existing Edge data/master key and persistent Postfix queue during upgrades.

Configure `egress.DOMAIN` A → assigned source IP and provider PTR → the same name;
use that name for EHLO. Merge the source IP into the return-path domain's existing
single SPF record. Reuse an existing suitable DKIM key through Edge's verified
local import, or generate a new Edge key and publish its actual TXT value. A proxy
migration alone does not require replacing DKIM DNS. Verify aligned From/SPF/DKIM,
DMARC, return-path receiving, and public unsubscribe behavior before sending.
Preserve existing mailbox MX unless explicitly migrating it. See
[Gmail's sender requirements](https://support.google.com/mail/answer/81126?hl=en).

Finally create an explicitly authorized test audience, approve its ordinary Cloud
campaign, and verify delivery and receiving evidence through the actual chain.
A connection-only probe or this software release cannot certify all those settings.
