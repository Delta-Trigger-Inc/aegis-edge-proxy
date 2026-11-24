# Inbound domain forwarding

This optional Postfix service is separate from the existing outbound Edge proxy.
It accepts all local parts at one assigned domain and forwards to the shared
inbox configured on Edge. It rejects relay to other domains. PostSRSd preserves
SPF compatibility for forwarded envelope senders; null senders remain null.

Build locally for the target architecture:

```sh
docker build --platform linux/amd64 -f inbound/Dockerfile -t aegis-inbound:candidate .
```

Save the image, verify its checksum after transfer, load it, and pin the local
image ID in `AEGIS_INBOUND_IMAGE`. Generate a root-only pairing file from the
Edge endpoint setup API. It contains `domain`, `hostname`, `listen_address`,
`shared_inbox`, `control_url`, and `control_token`. Set `AEGIS_INBOUND_CONFIG` to
its absolute path and start `inbound/compose.yaml` with a unique project name.
Persist all three volumes. Do not discard queues during upgrades or rollbacks.

The public listener uses only `listen_address:25`, so an existing loopback MTA
can remain. If an existing MTA owns the public listener, inventory and back up
its configuration and queue before a cutover. Never stop a nonempty queue.

Keep port 25 reachable from the Internet, while the existing outbound proxy's
5443 firewall restrictions remain unchanged. The shared-inbox domain must not
be this forwarding domain. Top Spot's shared inbox domain keeps its own MX.

Receivers poll their authenticated Edge control URL every minute. Address changes
apply to newly accepted mail; already queued mail retains its resolved recipient.
An unavailable control service leaves existing forwarding in place. The mailbox
test in Edge proves receipt, not merely an SMTP `250` response.

The included self-signed certificate supports ordinary opportunistic STARTTLS.
It does not establish an MTA-STS or DANE policy. Use a managed public certificate
before advertising either policy. The forwarding service logs SMTP addresses;
logs are bounded by Compose and must be treated as private operational data.
