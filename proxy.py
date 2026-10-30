"""Production native egress proxy launcher."""

import argparse
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

from server import Server
from server_config import load


def main():
    p = argparse.ArgumentParser(description="AEGIS Edge Proxy 1.0.0")
    p.add_argument("--config", default="/run/aegis-proxy/config.json")
    p.add_argument("--check", action="store_true")
    p.add_argument("--health", action="store_true")
    p.add_argument(
        "--allow-test-mode",
        action="store_true",
        help="explicit isolated-fixture configuration only",
    )
    a = p.parse_args()
    if a.health:
        v = json.loads(Path("/run/aegis-health/health.json").read_text())
        age = time.time() - v["observed_at"]
        os.kill(v["pid"], 0)
        expiry = datetime.fromisoformat(v["certificate_expires_at"])
        if not (
            0 <= age < 5
            and v["state"] in {"active", "draining"}
            and v["reload_ok"]
            and expiry > datetime.now(UTC)
        ):
            raise SystemExit(1)
        return
    if a.check:
        cfg = load(a.config, allow_test=a.allow_test_mode)
        Server.signing_key(cfg)
        print("Configuration, TLS identity and private credentials valid.")
        return
    if os.geteuid() == 0:
        raise SystemExit("Run as a non-root user")
    Server(a.config, allow_test=a.allow_test_mode).serve()


if __name__ == "__main__":
    main()
