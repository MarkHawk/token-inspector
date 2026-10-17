import io
import json

import pytest

from conftest import NOW_ISO
from token_inspector.cli import main
from token_inspector.redact import mask

# Every personal value the generator puts into a sample.
PERSONAL = ["jo.bloggs", "Bloggs", "jbloggs", "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "admin@example.com"]


def run(samples, name, *extra):
    out = io.StringIO()
    main(["--now", NOW_ISO, str(samples.path(name)), *samples.args(name), *extra], stdout=out, stderr=io.StringIO())
    return out.getvalue()


def test_mask():
    assert mask("jo.bloggs@example.com") == "j***@example.com"
    assert mask("Jo Bloggs") == "J***"
    assert mask("x") == "***"


def test_unredacted_output_contains_the_personal_values(samples):
    """Guards the next test: it must be checking values that really appear."""
    out = run(samples, "saml-xsw.xml") + run(samples, "jwt-valid.txt")
    for value in PERSONAL:
        assert value in out


@pytest.mark.parametrize("fmt", [[], ["--json"]], ids=["text", "json"])
def test_redact_masks_every_sample(samples, fmt):
    for name in samples.names():
        out = run(samples, name, "--redact", *fmt)
        for value in PERSONAL:
            assert value not in out, (name, value)


def test_redact_keeps_the_email_domain_and_masks_finding_text(samples):
    out = run(samples, "saml-xsw.xml", "--redact")
    assert "NameID          a***@example.com" in out
    assert "NameID 'a***@example.com'" in " ".join(out.split())
    assert "Redacted:" in out


def test_redact_does_not_change_results(samples):
    plain = json.loads(run(samples, "saml-rotated-cert.xml", "--json"))
    masked = json.loads(run(samples, "saml-rotated-cert.xml", "--json", "--redact"))
    assert [f["status"] for f in plain["findings"]] == [f["status"] for f in masked["findings"]]
    assert masked["redacted"] is True and plain["redacted"] is False


def test_redact_leaves_non_personal_values_alone(samples):
    out = run(samples, "saml-valid.xml", "--redact")
    assert "https://idp.example.com/realms/example" in out
    assert "app-user, app-admin" in out  # role is not personal
    assert "Token Inspector Test CA" in out  # certificate details are not personal
