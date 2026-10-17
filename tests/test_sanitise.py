"""The sanitiser and checker. Private values are assembled at run time so
this file itself contains none of the patterns it tests."""

import base64
import io

import pytest

from conftest import NOW_ISO, load_script
from token_inspector.cli import main

sanitise = load_script("sanitise")

PRIVATE_IPS = [".".join(p) for p in (("10", "1", "2", "3"), ("172", "20", "0", "5"), ("192", "168", "1", "20"))]
PUBLIC_IPS = [".".join(p) for p in (("172", "32", "0", "1"), ("8", "8", "8", "8"), ("192", "0", "2", "10"))]
HOME = "/home/" + "someone"
KEY_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"


@pytest.mark.parametrize("ip", PRIVATE_IPS)
def test_private_addresses_are_found_and_replaced(ip):
    text = f"https://{ip}:8180/realms/x"
    assert sanitise.find_problems(text) == ["private IPv4 address"]
    clean, changed = sanitise.sanitise_text(text)
    assert changed and ip not in clean and sanitise.find_problems(clean) == []


@pytest.mark.parametrize("ip", PUBLIC_IPS)
def test_public_and_documentation_addresses_are_left_alone(ip):
    assert sanitise.find_problems(f"host {ip} here") == []


def test_home_directories():
    assert sanitise.find_problems(f"{HOME}/lab/certs") == ["home directory path"]
    assert sanitise.find_problems("/home/pi/lab") == []
    assert sanitise.find_problems("/home/" + "pikachu/lab") == ["home directory path"]
    clean, _ = sanitise.sanitise_text(f"path {HOME}/lab")
    assert clean == "path ~/lab" and sanitise.find_problems(clean) == []


def test_private_keys_are_refused():
    text = f"{KEY_HEADER}\nMIIE...\n"
    assert sanitise.find_problems(text) == ["private key"]
    with pytest.raises(sanitise.UnsafeContent):
        sanitise.sanitise_text(text)
    assert sanitise.find_problems("-----BEGIN CERTIFICATE-----") == []


def test_personal_patterns_file(tmp_path):
    f = tmp_path / ".personal-patterns"
    f.write_text("# comment\n\nExample Person\nRobin\nre:(?i)lab-[0-9]+\\.internal\n")
    personal = sanitise.load_personal_patterns(f)
    assert sanitise.find_problems("by Example Person", personal) == ["personal pattern from .personal-patterns"]
    assert sanitise.find_problems("signed by Robin.", personal) != []
    # Whole words, case-sensitive: ordinary words containing the name are fine.
    assert sanitise.find_problems("robins and Robinson", personal) == []
    clean, _ = sanitise.sanitise_text("host LAB-42.internal", personal)
    assert clean == "host redacted"


def test_absent_personal_file_means_no_patterns(tmp_path):
    assert sanitise.load_personal_patterns(tmp_path / "missing") == []


def test_host_map():
    clean, changed = sanitise.sanitise_text("https://lab.host.test:8180/x", host_map={"lab.host.test": "idlab.example.com"})
    assert changed and clean == "https://idlab.example.com:8180/x"


# ---------------------------------------------------------------- tokens


def _cli(path, *args):
    out = io.StringIO()
    main(["--now", NOW_ISO, "--json", str(path), *args], stdout=out, stderr=io.StringIO())
    import json

    return {f["check_id"]: f["status"] for f in json.loads(out.getvalue())["findings"]}


def test_clean_saml_is_byte_identical_and_still_verifies(samples, tmp_path):
    xml = samples.read("saml-valid.xml")
    clean, changed = sanitise.sanitise_saml(xml)
    assert not changed and clean == xml


def test_sanitising_saml_breaks_its_signature_as_recorded(samples, tmp_path):
    xml = samples.read("saml-valid.xml").replace(b"Bloggs", PRIVATE_IPS[2].encode())
    clean, changed = sanitise.sanitise_saml(xml)
    assert changed and PRIVATE_IPS[2].encode() not in clean
    out = tmp_path / "s.xml"
    out.write_bytes(clean)
    assert _cli(out, *samples.args("saml-valid.xml"))["saml.signature.assertion"] == "FAIL"


def test_jwt_sanitising(samples, tmp_path):
    token = samples.read("jwt-valid.txt").decode().strip()
    same, changed = sanitise.sanitise_jwt(token)
    assert not changed and same == token

    head, payload, sig = token.split(".")
    raw = base64.urlsafe_b64decode(payload + "==").decode().replace("example-rp", PRIVATE_IPS[0])
    dirty = ".".join([head, base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode(), sig])
    clean, changed = sanitise.sanitise_jwt(dirty)
    assert changed and sanitise.check_paths([], []) == []
    out = tmp_path / "t.txt"
    out.write_text(clean)
    assert sanitise.check_paths([out], []) == []
    assert _cli(out, *samples.args("jwt-valid.txt"))["jwt.signature"] == "FAIL"


def test_checker_sees_inside_base64_and_jwts(tmp_path):
    hidden = base64.b64encode(f"<Response Destination='https://{PRIVATE_IPS[1]}/acs'/>".encode()).decode()
    (tmp_path / "a.b64").write_text(hidden)
    payload = base64.urlsafe_b64encode(f'{{"iss":"https://{PRIVATE_IPS[1]}/r"}}'.encode()).rstrip(b"=").decode()
    (tmp_path / "b.txt").write_text(f"eyJhbGciOiJSUzI1NiJ9.{payload}.c2lnbmF0dXJl")
    (tmp_path / "ok.txt").write_text("nothing to see")
    problems = sanitise.check_paths([tmp_path], [])
    assert sorted(p.rsplit("/", 1)[-1] for p, _ in problems) == ["a.b64", "b.txt"]


def test_check_command_exit_codes(tmp_path, capsys):
    (tmp_path / "clean.txt").write_text("fine")
    assert sanitise.main(["--check", str(tmp_path)]) == 0
    (tmp_path / "dirty.txt").write_text(f"see {HOME}/x")
    assert sanitise.main(["--check", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "home directory path" in err and HOME not in err  # names the kind, never the value
