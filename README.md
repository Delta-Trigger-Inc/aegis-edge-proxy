# AEGIS Edge Proxy 1.0.0

Authenticated, source-bound SMTP egress for AEGIS Edge/Postfix. Download source and
prebuilt Linux images from the [public release](https://github.com/Delta-Trigger-Inc/aegis-edge-proxy/releases/tag/v1.0.0).
See [installation](INSTALL.md), [operations](OPERATIONS.md) and [test evidence](TEST-RESULTS.json).

The proxy carries an opaque TCP stream to a literal destination IP on port 25.
Postfix on Edge owns MX lookup, EHLO, SMTP, STARTTLS, DKIM, queueing and retries.
The proxy never accepts a recipient list or queues mail. It has no direct-delivery
fallback. One process binds one assigned sending IP and one enrolled Edge endpoint.

Production controls include TLS 1.3 mutual authentication, exact client-certificate
pins paired with Ed25519 admission keys, channel-bound signed requests and replies,
strict identity/version checks, bounded replay state, source/peer/destination rules,
and rejection of private, local, transition and non-global destinations. A private
fixture mode requires an explicit CLI flag and is not used for deployment.

Unauthenticated and authenticated sessions share the same concurrency bound.
Handshake/header, connect, idle and total deadlines, byte caps, admission rate
limits, bounded buffers, a non-root distroless runtime, read-only mounts, capability
removal and rotated logs constrain resource use. Reload revokes active streams;
invalid configuration fails closed. Operators can drain or halt admissions.
Certificate renewal supports an overlap followed by explicit old-leaf revocation.

Default limits: 16 connections, 16 new connections/second, 5-second handshake and
connect deadlines, 60-second idle timeout, 600-second session lifetime, 64 MiB total
wire bytes per session, and 30-second shutdown drain. These are limits, not a
throughput or deliverability guarantee. SMTP should complete its response before
closing; this is not a general-purpose bidirectional TCP half-close service.

AEGIS Edge requires the hardened native connector and its normal Postfix, policy
and receiving companions. A running proxy does not grant campaign authority or
verify sending DNS, unsubscribe processing, bounce handling or inbox placement.
Each deployment still needs its own commissioning test.

No customer domains, credentials, private keys, recipient lists or Edge databases
are included in this repository or its release assets.
