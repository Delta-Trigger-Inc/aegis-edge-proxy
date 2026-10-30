# Operations and incident response

Monitor Docker health plus the health JSON's state, reload_ok, certificate expiry,
active/rejected counts and configuration digest. Health is process readiness, not
mail delivery. Alert on unhealthy/halted state, persistent saturation, and TLS
certificate expiry within seven days. Leaves last 30 days; renew before day 23.
Keep NTP synchronized. Logs contain signed connection identifiers, byte counts and
fixed terminal reasons, not SMTP contents or recipients. Retain logs according to
your operational policy outside the bounded local rotation when needed.

## Drain, halt, reload and resume

- `docker compose -p ENDPOINT kill -s SIGUSR1 proxy`: refuse new sessions; let existing sessions finish.
- `docker compose -p ENDPOINT kill -s SIGUSR2 proxy`: refuse new sessions and terminate current sessions.
- `docker compose -p ENDPOINT kill -s SIGHUP proxy`: validate/reload trust and policy; terminate current sessions. Invalid reload halts the service.
- `docker compose -p ENDPOINT restart proxy`: explicit resume after validating configuration. A reload alone does not resume a drained/halted service.
- SIGTERM drains for the configured deadline, then closes remaining sessions. Postfix retains/retries deferred messages under its normal policy.

Replace config and credential files atomically inside the mounted directory, with
root:10001 ownership and mode 640. Do not replace the bind-mounted directory inode
without recreating the container. Run `--check` against the staged bundle first.
Topology/identity/listener changes require restart. No administrative HTTP port exists.

## TLS renewal

On the trusted host holding the original complete bundle:

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  --entrypoint /usr/bin/python3 -v "$HOME/aegis-proxy-private:/private" \
  "$AEGIS_PROXY_IMAGE" /app/renew_pair.py \
  --bundle "/private/$ENDPOINT_ID" --output "/private/$ENDPOINT_ID-renewed"
```

1. Stage the generated `transition-proxy/` files on the proxy, check, then reload. It trusts both old and new client leaf pins. The server's new leaf uses the same CA and TLS name.
2. Replace the Edge connector's client certificate/key with `edge/` from the renewed bundle, preserving UID 10002 and read-only mounts. Restart the connector/companion using its supported deployment procedure; preserve its queue. Test an authenticated connection.
3. Install the renewed final `proxy/` config and reload. This removes the old pin and terminates any remaining old streams. Verify a new connection works and the retired credential fails.
4. Retain the renewed complete bundle as the input for next renewal. Safely retire the old leaf private keys after verification.

Do not leave overlap enabled. The helper refuses a new renewal from an unfinished
overlap and refuses renewal when the CA has less than 31 days remaining. CA or
Ed25519-key replacement requires a newly generated pair and a coordinated update
of both sides' trust/profile registration. Drain first. Compromise requires immediate
halt/revocation, replacement credentials, and explicit restart after validation.

## Upgrade, rollback and failure

Download/checksum the new image; inspect its exact identity. Retain the prior image
and private config. Drain, change the pinned image ID, then recreate only this
proxy. Verify health, authenticated admission and an owned delivery test. Roll back
by restoring the prior image/config and restarting. Never downgrade to the old
unauthenticated proxy protocol as an automatic fallback.

Proxy outage leaves the queue on Edge/Postfix; it does not authorize direct MX
access. Do not flush or delete queues to fix connectivity. Invalid TLS/pins, stale
requests, signature errors, private destinations and configuration mismatch must
remain denied. Repair the underlying configuration, check health, then let Postfix
retry under a current signed control lease and the existing per-attempt policy.

The host needs regular OS/Docker updates and an appropriate firewall. A temporary
legacy test host is not a production host merely because this container is healthy.
