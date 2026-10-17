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
    assert "base64 (HTTP-POST binding)" in out
    assert "Verdict: no problems found (0 FAIL, 0 WARN, 13 PASS, 1 SKIP)" in out


def test_failing_saml_exits_one_and_names_runbook(samples):
    code, out, _ = sample_run(samples, "saml-expired-cert.xml")
    assert code == EXIT_FAIL
    assert "FAIL  Signing certificate dates" in out
    runbook_lines = [line.strip() for line in out.splitlines() if "Runbook:" in line]
    assert runbook_lines == ["Runbook: identity-lab 01-expired-signing-cert"]
    assert "Verdict: 1 problem to fix (1 FAIL, 0 WARN, 12 PASS, 1 SKIP)" in out


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


def test_verdict_wording():
    from token_inspector.findings import Finding, Report, Status
    from token_inspector.render import verdict_line

    def verdict(*statuses):
        r = Report("saml", "", "", "", None, 60, findings=[Finding("x", s, "t", "s") for s in statuses])
        return verdict_line(r)

    P, W, F, S = Status.PASS, Status.WARN, Status.FAIL, Status.SKIP
    assert verdict(P, S) == "Verdict: no problems found (0 FAIL, 0 WARN, 1 PASS, 1 SKIP)"
    assert verdict(P, W, W) == "Verdict: no failures, 2 warnings to review (0 FAIL, 2 WARN, 1 PASS, 0 SKIP)"
    assert verdict(P, W) == "Verdict: no failures, 1 warning to review (0 FAIL, 1 WARN, 1 PASS, 0 SKIP)"
    assert verdict(F, P) == "Verdict: 1 problem to fix (1 FAIL, 0 WARN, 1 PASS, 0 SKIP)"
    assert verdict(F, F, W) == "Verdict: 2 problems to fix, 1 warning to review (2 FAIL, 1 WARN, 0 PASS, 0 SKIP)"


class FakeStdin(io.StringIO):
    def isatty(self):
        return False


def test_valid_jwt_from_stdin(samples):
    token = samples.read("jwt-valid.txt").decode()
    code, out, _ = run("-", *samples.args("jwt-valid.txt"), stdin=FakeStdin(token))
    assert code == EXIT_OK
    assert "Input:      ID token (JWT), compact JWS, pasted value" in out
    assert "Verdict: no problems found" in out


def test_jwt_from_har(samples):
    code, out, _ = sample_run(samples, "jwt-valid.har")
    assert code == EXIT_OK and "HAR file" in out and "Found in:   HAR entry 1" in out


def test_expired_jwt_exits_one(samples):
    code, out, _ = sample_run(samples, "jwt-expired.txt")
    assert code == EXIT_FAIL and "FAIL  Expiry (exp)" in out


def test_encrypted_jwt_is_a_warning_not_an_error(samples):
    code, out, _ = sample_run(samples, "jwt-encrypted.txt")
    assert code == EXIT_OK and "Encrypted JWT (JWE)" in out and "WARN  Encrypted token" in out


def test_truncated_jwt_exits_two(samples):
    head = samples.read("jwt-valid.txt").decode().split(".")[0]
    code, _, err = run("--token", head + ".bm90IGpzb24.c2ln")
    assert code == EXIT_ERROR and "not valid JSON" in err


def test_token_type_override(samples):
    _, out, _ = sample_run(samples, "jwt-access-token.txt", "--token-type", "id")
    assert "ID token (set with --token-type)" in out
