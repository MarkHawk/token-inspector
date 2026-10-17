"""Trust material sitting next to the input is used when no trust flag is
given, and the report says so. Explicit flags always win."""

import io
import json
import shutil

import pytest

from conftest import NOW_ISO
from token_inspector.cli import EXIT_FAIL, EXIT_OK, main

SAML_NOTE = "Using idp-metadata.xml found next to the input"
JWKS_NOTE = "Using jwks.json found next to the input"


def run(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    code = main(["--now", NOW_ISO, *argv], stdin=stdin, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def checks(out):
    return {f["check_id"]: f for f in json.loads(out)["findings"]}


@pytest.fixture
def folder(samples, tmp_path):
    """A clean folder holding one SAML response, one JWT and their trust files."""
    for name in ("saml-valid.xml", "jwt-valid.txt", "idp-metadata.xml", "jwks.json", "idp-rotated.pem"):
        shutil.copy(samples.path(name), tmp_path / name)
    return tmp_path


def test_saml_uses_metadata_next_to_input(folder):
    code, out, _ = run(str(folder / "saml-valid.xml"))
    assert code == EXIT_OK
    assert f"Note:       {SAML_NOTE}" in out
    _, out, _ = run(str(folder / "saml-valid.xml"), "--json")
    assert json.loads(out)["notes"] == [SAML_NOTE]
    assert checks(out)["saml.cert.metadata_match"]["summary"] == \
        "The signing certificate is the one in metadata idp-metadata.xml."


def test_jwt_uses_jwks_next_to_input(folder):
    code, out, _ = run(str(folder / "jwt-valid.txt"), "--json")
    doc = json.loads(out)
    assert doc["notes"] == [JWKS_NOTE]
    assert checks(out)["jwt.signature"]["status"] == "PASS"
    assert "JWKS jwks.json" in checks(out)["jwt.signature"]["summary"]


def test_only_the_file_for_the_token_kind_is_mentioned(folder):
    _, out, _ = run(str(folder / "saml-valid.xml"))
    assert JWKS_NOTE not in out


@pytest.mark.parametrize("flag", ["--metadata", "--cert", "--jwks"])
def test_explicit_trust_flags_win(folder, samples, flag):
    value = {"--metadata": samples.path("idp-metadata-expired.xml"),
             "--cert": folder / "idp-rotated.pem",
             "--jwks": folder / "jwks.json"}[flag]
    _, out, _ = run(str(folder / "saml-valid.xml"), flag, str(value))
    assert SAML_NOTE not in out


def test_explicit_cert_is_what_gets_checked(folder):
    """With --cert, the neighbouring metadata is ignored, so the wrong cert fails."""
    code, out, _ = run(str(folder / "saml-valid.xml"), "--cert", str(folder / "idp-rotated.pem"), "--json")
    assert code == EXIT_FAIL
    assert "certificate idp-rotated.pem" in checks(out)["saml.signature.assertion"]["summary"]


def test_no_discover_flag(folder):
    _, out, _ = run(str(folder / "saml-valid.xml"), "--no-discover", "--json")
    assert json.loads(out)["notes"] == []
    assert checks(out)["saml.cert.metadata_match"]["status"] == "SKIP"


def test_nothing_discovered_without_neighbours(samples, tmp_path):
    shutil.copy(samples.path("saml-valid.xml"), tmp_path / "saml-valid.xml")
    _, out, _ = run(str(tmp_path / "saml-valid.xml"), "--json")
    assert json.loads(out)["notes"] == []


def test_stdin_and_pasted_tokens_do_not_discover(folder, monkeypatch):
    monkeypatch.chdir(folder)  # a jwks.json in the working folder must not be picked up
    token = (folder / "jwt-valid.txt").read_text()
    for argv, stdin in ((["--token", token], None), (["-"], io.StringIO(token))):
        _, out, _ = run(*argv, "--json", stdin=stdin)
        assert json.loads(out)["notes"] == []
        assert checks(out)["jwt.signature"]["status"] == "SKIP"
