# Controlled live commissioning — 2026-10-31 UTC

A single-recipient Gmail campaign was exercised through the normal signed-in
Cloud workflow with proxy 1.0.0 and the hardened Edge/Postfix integration. The
customer administrator used an audited, expiring support session; no customer
password or permanent customer membership was substituted.

The ordinary workflow verified the route, a one-contact eligible audience snapshot,
approved content readback, and current signed delivery readiness. The scheduled
batch used one SMTP attempt through the authenticated TLS 1.3 proxy. The retired
proxy configuration version was independently confirmed to be rejected.

Gmail rejected the message after DATA with SMTP `550 5.7.1`, explicitly citing the
sending domain's very low reputation. This was not a successful Gmail delivery.
The original message retained in the local delivery-status notification had a DKIM
signature that verified against the sender's existing published DNS key.

Postfix routed the local bounce to the receiving companion and emptied its queue.
Cloud's signed aggregate result showed one manifest recipient, one SMTP attempt,
one bounce, zero accepted messages, zero retries, and zero queued messages. All
batches were issued and the revision's sending was closed. No automatic resend
was performed.

This validates the live transport, existing-key DKIM migration, permanent-failure
handling, retained local DSN collection and Cloud result reporting for this test.
It does not certify sender reputation, public inbox placement, every proxy host,
or external public bounce/MX routing. Production senders still require their own
DNS, authentication, receiving/unsubscribe checks and approved delivery tests.
The temporary test proxy's older OS must be replaced for production as planned.

## Multiple domains within one campaign

Cloud `68564b226f7826e6890c9af8bbdc2c456d9fb610` and Edge
`6268eb1ddb1e8904d3fac238339b53004d27d12a` add explicit per-endpoint sender
assignments to the existing capacity-weighted campaign planner. The review UI at
Cloud `83dfdb0` displays every approved endpoint/sender pairing. Proxy 1.0.0's
wire protocol and immutable downloadable artifacts are unchanged.

Isolated tests exercise one campaign with two registered egress IPs and two
sending/DKIM domains, verify both real signatures, preserve recipient uniqueness
and replay identity, and reject changed sender bindings at admission and later
attempts. Signed readiness checks every assigned identity. These new tests use
controlled Postfix ingress; they do not claim a live multi-host inbox-delivery
result. Only the single test proxy above has been commissioned live.

Configure each proxy's own source IP/EHLO and each Edge sender's DKIM and return
path first. In Cloud choose a named endpoint pool, select multiple endpoints and
sending domains, assign a verified sender to every endpoint, and review/apply the
signed route plan before ordinary campaign approval. Deployment order is Cloud
reader first, Edge producer second. Shared rate limits remain shared across the
pool, and a failed message is not silently retried under another sender domain.
