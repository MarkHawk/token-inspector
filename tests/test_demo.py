"""`token-inspector demo` runs the bundled samples offline with fixed results."""

import io
import json

import pytest

from conftest import ROOT
from token_inspector import demo
from token_inspector.cli import EXIT_ERROR, EXIT_FAIL, EXIT_OK, main

BUNDLE = ROOT / "src" / "token_inspector" / "demo_samples"
LAB = ROOT / "samples" / "lab" / "expired-signing-cert"


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(["demo", *argv], stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def verdicts(out):
    """{sample name: (status, text)} from the summary lines."""
    rows = {}
    for line in out.splitlines():
        parts = line.split()
        if line.startswith("  ") and parts and parts[0] in ("valid", "expired", "rotation", "xsw"):
            status = next(p for p in parts if p in ("PASS", "WARN", "FAIL"))
            rows[parts[0]] = (status, line.split(f"  {status}  ", 1)[1])
    return rows


def test_summary_has_one_line_per_sample():
    code, out, err = run()
    assert code == EXIT_OK and err == ""
    assert verdicts(out) == {
        "valid": ("PASS", "no problems found"),
        "expired": ("FAIL", "likely cause: the token is simply old"),
        "rotation": ("FAIL", "likely cause: key rotation, trusted cert expired"),
        "xsw": ("FAIL", "likely cause: signature wrapping (XSW)"),
    }


def test_summary_falls_back_to_the_first_problem_without_a_cause():
    from token_inspector.findings import Finding, Report, Status

    report = Report("saml", "", "", "", None, 60, findings=[
        Finding("a", Status.FAIL, "Issuer", "s"), Finding("b", Status.FAIL, "Audience", "s")])
    assert demo.one_line(report) == ("FAIL", "2 problems: Issuer +1 more")


def test_summary_says_how_to_see_a_full_report():
    _, out, _ = run()
    assert "token-inspector demo <name>" in out and "token-inspector demo xsw" in out


def test_summary_lines_fit_the_report_width():
    _, out, _ = run()
    assert max(len(line) for line in out.splitlines()) <= 100


@pytest.mark.parametrize("name,code", [("valid", EXIT_OK), ("expired", EXIT_FAIL),
                                       ("rotation", EXIT_FAIL), ("xsw", EXIT_FAIL)])
def test_full_report_for_each_sample(name, code):
    got, out, _ = run(name)
    assert got == code
    assert out.startswith(f"Demo sample {name}: ")
    assert "\nSame as: token-inspector " in out and "--now " in out
    assert str(BUNDLE) not in out  # shows file names, not install paths
    assert "\nVerdict: " in out


def test_xsw_report_names_the_attack():
    _, out, _ = run("xsw", "--json")
    findings = {f["check_id"]: f for f in json.loads(out)["findings"]}
    assert findings["saml.signature.coverage"]["status"] == "FAIL"
    assert "XSW" in findings["saml.signature.coverage"]["summary"]


def test_rotation_report_shows_the_expired_trusted_cert():
    _, out, _ = run("rotation", "--json")
    findings = {f["check_id"]: f for f in json.loads(out)["findings"]}
    assert findings["saml.cert.trusted_validity"]["status"] == "FAIL"
    assert findings["saml.cert.validity"]["status"] == "PASS"


def test_redact_is_passed_through():
    _, out, _ = run("rotation", "--redact")
    assert "Redacted:" in out and "alice@idlab.example" not in out


def test_unknown_sample_exits_two():
    code, out, err = run("nope")
    assert code == EXIT_ERROR and out == "" and "choose from valid, expired, rotation, xsw" in err


def test_json_without_a_name_is_an_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["demo", "--json"])
    assert exc.value.code == 2 and "need a sample name" in capsys.readouterr().err


def test_a_file_called_demo_is_still_reachable(tmp_path, monkeypatch):
    (tmp_path / "demo").write_text((BUNDLE / "expired" / "jwt-expired.txt").read_text())
    monkeypatch.chdir(tmp_path)
    out = io.StringIO()
    main(["./demo"], stdout=out, stderr=io.StringIO())
    assert "Verdict:" in out.getvalue()


def test_bundle_has_four_samples_with_their_files():
    samples = demo.load_samples(BUNDLE)
    assert [s["name"] for s in samples] == ["valid", "expired", "rotation", "xsw"]
    for s in samples:
        assert (BUNDLE / s["name"] / s["file"]).is_file()
        assert "--now" in s["args"]  # fixed time, so verdicts never drift
        for a in s["args"]:
            if a.startswith("{dir}/"):
                assert (BUNDLE / s["name"] / a.removeprefix("{dir}/")).is_file(), a


def test_bundle_holds_no_private_keys():
    for path in BUNDLE.rglob("*"):
        if path.is_file():
            assert "PRIVATE KEY" not in path.read_text(errors="replace"), path


def test_rotation_sample_is_the_committed_lab_capture():
    for name in ("saml-response.xml", "sp-pinned-cert.pem"):
        assert (BUNDLE / "rotation" / name).read_bytes() == (LAB / name).read_bytes(), name


def test_samples_are_packaged():
    import tomllib

    data = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"]["package-data"]
    assert "demo_samples/*/*" in data["token_inspector"]


def test_bundle_titles_match_the_build_script():
    """demo.json is built by scripts/build_demo_samples.py, so the two must agree."""
    from conftest import load_script

    build = load_script("build_demo_samples")
    titles = {s["name"]: s["title"] for s in demo.load_samples(BUNDLE)}
    for name, title, *_ in build.SYNTHETIC:
        assert titles[name] == title
    assert f'"title": "{titles["rotation"]}"' in (ROOT / "scripts" / "build_demo_samples.py").read_text()
