import io

from conftest import NOW_ISO
from token_inspector.cli import EXIT_ERROR, EXIT_FAIL, EXIT_OK, main


def run(*argv, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    code = main(["--now", NOW_ISO, *argv], stdin=stdin, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def sample_run(samples, name, *extra):
    return run(str(samples.path(name)), *samples.args(name), *extra)


def test_valid_saml_exits_zero(samples):
    code, out, _ = sample_run(samples, "saml-valid.b64")
    assert code == EXIT_OK
    assert "base64 (HTTP-POST binding)" in out and "Result: no failures" in out


def test_failing_saml_exits_one_and_names_runbook(samples):
    code, out, _ = sample_run(samples, "saml-expired-cert.xml")
    assert code == EXIT_FAIL
    assert "FAIL  Signing certificate dates" in out
    assert "Runbook: identity-lab 01-expired-signing-cert" in out


def test_trust_source_is_shown_without_local_path(samples):
    _, out, _ = sample_run(samples, "saml-valid.xml")
    assert "metadata idp-metadata.xml" in out and str(samples.dir) not in out


def test_bad_input_exits_two(samples):
    code, out, err = run("--token", "hello")
    assert code == EXIT_ERROR and out == "" and "not a SAML response" in err


def test_missing_key_file_exits_two(samples):
    code, _, err = run(str(samples.path("saml-valid.xml")), "--metadata", "/nonexistent/md.xml")
    assert code == EXIT_ERROR and "cannot read" in err


def test_bad_now_exits_two(samples):
    code, _, err = run(str(samples.path("saml-valid.xml")), "--now", "yesterday")
    assert code == EXIT_ERROR and "ISO 8601" in err
