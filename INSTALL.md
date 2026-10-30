# Controlled-test installation

Requirements: Linux Docker Engine and Docker Compose v2+, a locally assigned
source IPv4 address, NTP synchronization, and an operator-controlled test receiver
accepting TCP 25. Do not install on the Cloud host. Multiple source IPs on one host
use separate projects and separate bundles; each listener binds its own source IP.
Do not add an IP that the provider has not assigned to that host.

## 1. Build the downloaded release

Install Docker using https://docs.docker.com/engine/install/ for the host OS.
From the extracted release directory:

```sh
docker build --pull -t aegis-edge-proxy:0.1.0-preview.1 .
docker run --rm aegis-edge-proxy:0.1.0-preview.1 --help
```

This package uses Linux host networking so the outbound socket can bind the actual
assigned source IP. There are no Compose port publications. See
https://docs.docker.com/engine/network/drivers/host/ . The runtime is UID/GID 10001,
read-only, has no Linux capabilities and has bounded memory, tasks and rotated logs.

## 2. Create a private pair on the trusted Edge/operator host

Build the same image on the trusted host. Choose explicit unique IDs and use the
actual enrolled Edge agent ID, not a tenant name. Replace the example addresses;
192.0.2.10 and 198.51.100.20 below are documentation addresses, not working targets.

```sh
umask 077
mkdir -p "$HOME/aegis-proxy-private"
docker run --rm --user "$(id -u):$(id -g)" --entrypoint python \
  -v "$HOME/aegis-proxy-private:/private" \
  aegis-edge-proxy:0.1.0-preview.1 /app/create_pair.py \
  --edge-id YOUR_ENROLLED_AGENT_ID --proxy-id proxy-example \
  --endpoint-id endpoint-example --source-ip 192.0.2.10 \
  --server-name mail.example.com --allowed-destination-cidr 198.51.100.20/32 \
  --output /private/endpoint-example
```

The helper refuses to overwrite an existing output directory and creates private
files with mode 600. Keep `ca/`, `edge/` and `metadata.json` on the trusted host.
Transfer **only `proxy/`** over authenticated SSH to its corresponding source-IP
host, e.g. to `/opt/aegis-proxy/endpoint-example/proxy`. Never put a private bundle
in GitHub, a public download, an image layer or chat. The CA is private to this
pair and is unrelated to Cloud enrollment or public ACME certificates.

## 3. Restrict the host and prepare custody

Check `ip -4 addr`, `ss -lnt`, provider firewall and host firewall. The source IP
must already be on an interface, port 5443 on that IP must be free, and the provider
must allow outbound TCP 25 to the approved test receiver. Do not enable freebind.

In the provider firewall allow inbound TCP 5443 only from the actual Edge outbound
IP /32 and deny that port from other sources. Keep your existing administrative SSH
rule. Apply the equivalent host rule. On a host where UFW is already enabled with
an incoming-deny policy, an example allow rule is:

```sh
sudo ufw allow from EDGE_IP to SOURCE_IP port 5443 proto tcp
sudo ufw status verbose
```

An allow rule alone does not create a deny policy. Audit existing broad rules; do
not reset a firewall or enable UFW blindly over SSH. The service does not listen
for inbound SMTP on port 25. Existing mail services are separate; stop/remove them
only after confirming host ownership and the desired cutover.

Set custody after copying the private `proxy/` directory:

```sh
sudo chown -R root:10001 /opt/aegis-proxy/endpoint-example/proxy
sudo find /opt/aegis-proxy/endpoint-example/proxy -type d -exec chmod 750 {} +
sudo find /opt/aegis-proxy/endpoint-example/proxy -type f -exec chmod 640 {} +
export AEGIS_PROXY_BUNDLE=/opt/aegis-proxy/endpoint-example/proxy
```

## 4. Validate and start

From the release directory, keep the same project and bundle path on each command:

```sh
docker compose -p endpoint-example config --quiet
docker compose -p endpoint-example run --rm --no-deps proxy --config /run/aegis-proxy/config.json --check
docker compose -p endpoint-example up -d --no-build
docker compose -p endpoint-example logs --tail 30 proxy
docker compose -p endpoint-example exec proxy cat /run/aegis-health/health.json
```

`proxy_ready`/the health file show process state, not an authenticated route check.
From the trusted Edge/operator host run a connection-only probe. The chosen source
network must be allowed by the proxy firewall:

```sh
docker run --rm --network host --user "$(id -u):$(id -g)" --entrypoint python \
  -v "$HOME/aegis-proxy-private:/private:ro" \
  aegis-edge-proxy:0.1.0-preview.1 /app/probe.py \
  --bundle /private/endpoint-example --destination 198.51.100.20
```

Expect a signed `accepted` / `connection_admitted` response. Independently inspect
the controlled receiver: the observed source must equal the intended sending IP.
The probe sends no SMTP commands or message. A Mac behind a different public IP
will be blocked if only the real Edge is allowed; run the probe from Edge.

Drain refuses new admissions while current tunnels finish:
`docker compose -p endpoint-example kill -s SIGUSR1 proxy`.
Halt closes existing tunnels:
`docker compose -p endpoint-example kill -s SIGUSR2 proxy`.
Resume with SIGHUP; stop with `docker compose -p endpoint-example down`.

## 5. Connect the Edge side and commission mail separately

The supplied `edge/security-profile.json` has the native `aegis_proxy_v1` credential
file fields. Mount `edge/` under its indicated private `/run/aegis-egress/ENDPOINT`
path in the Edge Postfix companion; keep keys readable only by its connector UID
10002. Register matching endpoint/proxy IDs, source IP, port 5443, configuration
version 1 and TLS server name. The profile includes its distinct proxy_id; preserve both IDs exactly.
The profile is an input to AEGIS's registry/export workflow, not a complete registry
or a file that can simply be dropped into the Edge data directory. The native
Postfix and policy companions, private topology, routing bindings and readback must
be installed through that workflow before campaign sending can function.

EHLO, DKIM signing, return paths and retry queues belong to Edge/Postfix, not this
proxy. Create `mail.DOMAIN` A -> source IP and provider PTR source IP -> that same
hostname. Verify both directions and use that hostname for the Edge sender EHLO.
SPF must authorize the actual return-path domain's source IP; merge with an existing
SPF record, never add a second one. Generate a new DKIM key in Edge and publish its
actual public key; do not use a placeholder TXT value. Preserve existing MX/SPF/
DMARC until their existing mail uses are checked. A test connection does not verify
SPF, DKIM, DMARC, bounce receiving or unsubscribe processing. See sender requirements:
https://support.google.com/a/answer/81126?hl=en .

Keep sending disabled until production hardening, the complete Edge route, DNS,
receiving, unsubscribe and an authorized test delivery are verified. This preview
alone does not complete those steps.
