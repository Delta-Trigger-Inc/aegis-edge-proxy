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
