from types import SimpleNamespace

import pytest

from inbound.runtime import NoRedirect, configuration, disable_postfix_chroot


def test_receiver_accepts_only_its_domain_and_uses_srs():
    config, aliases = configuration(
        dict(
            domain="example.com",
            hostname="mx.example.com",
            shared_inbox="team@destination.com",
            listen_address="8.8.8.8",
        )
    )
    assert aliases == "@example.com team@destination.com\n"
    assert config["smtpd_relay_restrictions"] == "reject_unauth_destination"
    assert config["relay_domains"] == config["mydestination"] == ""
    assert config["sender_canonical_classes"] == "envelope_sender"
    assert config["inet_interfaces"] == "8.8.8.8"


@pytest.mark.parametrize(
    "inbox", ["mail@example.com", "mail@mx.example.com", "mail@other.com\n@evil.com x@z.com"]
)
def test_no_forwarding_loops_or_alias_injection(inbox):
    with pytest.raises(ValueError):
        configuration(dict(domain="example.com", hostname="mx.example.com", shared_inbox=inbox))


def test_no_token_forwarding_redirect():
    with pytest.raises(ValueError, match="redirect"):
        NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://other.example/")


def test_disable_postfix_chroot_updates_and_verifies_master_cf():
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd == ["postconf", "-F", "*/*/chroot"]:
            return SimpleNamespace(stdout="smtp/inet/chroot = n\nsmtp/unix/chroot = n\n")
        return SimpleNamespace(stdout="")

    disable_postfix_chroot(run_cmd=fake_run)
    assert calls == [
        ["postconf", "-F", "*/*/chroot=n"],
        ["postconf", "-F", "*/*/chroot"],
    ]


@pytest.mark.parametrize(
    "stdout,expected",
    [
        ("smtp/inet/chroot = n\n", "missing smtp/unix"),
        ("smtp/inet/chroot = n\nsmtp/unix/chroot = y\n", "chroot still enabled"),
    ],
)
def test_disable_postfix_chroot_rejects_unverified_master_cf(stdout, expected):
    def fake_run(cmd, **kwargs):
        return SimpleNamespace(stdout=stdout if cmd == ["postconf", "-F", "*/*/chroot"] else "")

    with pytest.raises(RuntimeError, match=expected):
        disable_postfix_chroot(run_cmd=fake_run)
