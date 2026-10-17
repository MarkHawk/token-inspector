import base64
import io
import json
import urllib.parse
import zlib

import pytest

from token_inspector import inputs
from token_inspector.inputs import InputError, classify, detect, read_input

XML = b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1"/>'
POST = base64.b64encode(XML).decode()
REDIRECT = base64.b64encode(zlib.compress(XML)[2:-4]).decode()


def _b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


JWT = f"{_b64url({'alg': 'RS256', 'kid': 'k1'})}.{_b64url({'sub': 'u1'})}.c2ln"
JWE = f"{_b64url({'alg': 'RSA-OAEP', 'enc': 'A256GCM'})}.ZW5j.aXY.Y3Q.dGFn"


def only(data):
    tokens = detect(data)
    assert len(tokens) == 1
    return tokens[0]


def test_raw_xml():
    t = only(XML)
    assert (t.kind, t.encoding, t.payload) == ("saml", inputs.ENC_RAW_XML, XML)


def test_post_binding():
    t = only(POST)
    assert (t.kind, t.encoding, t.payload) == ("saml", inputs.ENC_POST, XML)


def test_post_binding_with_line_breaks_and_url_encoding():
    wrapped = "\n".join(POST[i : i + 20] for i in range(0, len(POST), 20))
    assert only(urllib.parse.quote(wrapped)).payload == XML


def test_redirect_binding():
    t = only(REDIRECT)
    assert (t.kind, t.encoding, t.payload) == ("saml", inputs.ENC_REDIRECT, XML)


def test_redirect_binding_in_url():
    url = "https://sp.example.com/acs?SAMLResponse=" + urllib.parse.quote(REDIRECT) + "&RelayState=x"
    t = only(url)
    assert (t.encoding, t.container) == (inputs.ENC_REDIRECT, "URL")


def test_post_form_body():
    t = only("SAMLResponse=" + urllib.parse.quote(POST) + "&RelayState=%2F")
    assert (t.encoding, t.container) == (inputs.ENC_POST, "form body")


def test_auto_submit_html_page():
    page = f'<html><body><form method="post"><input type="hidden" name="SAMLResponse" value="{POST}"/></form></body></html>'
    t = only(page)
    assert (t.encoding, t.container) == (inputs.ENC_POST, "HTML page")


def test_jwt():
    t = only(JWT)
    assert (t.kind, t.payload) == ("jwt", JWT)


def test_jwe_is_recognised():
    assert only(JWE).kind == "jwe"


def test_jwt_in_url_fragment():
    t = only(f"https://rp.example.com/cb#state=s&id_token={JWT}")
    assert (t.kind, t.container) == ("jwt", "URL")


def test_har_file():
    har = {
        "log": {
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://idp.example.com/sso?SAMLRequest=abc", "headers": []},
                    "response": {"content": {"text": "<html>login</html>"}},
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://sp.example.com/saml/acs",
                        "postData": {
                            "text": "SAMLResponse=" + urllib.parse.quote(POST),
                            "params": [{"name": "SAMLResponse", "value": urllib.parse.quote(POST)}],
                        },
                    },
                    "response": {},
                },
            ]
        }
    }
    t = only(json.dumps(har))
    assert (t.kind, t.container) == ("saml", "HAR file")
    assert "HAR entry 2 (POST https://sp.example.com/saml/acs)" in t.location


def test_har_with_token_response_and_bearer_header():
    access = f"{_b64url({'alg': 'RS256', 'typ': 'at+jwt'})}.{_b64url({'sub': 'u1', 'scope': 'openid'})}.c2ln"
    har = {
        "log": {
            "entries": [
                {
                    "request": {"method": "POST", "url": "https://idp.example.com/token"},
                    "response": {"content": {"text": json.dumps({"id_token": JWT, "access_token": access})}},
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/me",
                        "headers": [{"name": "Authorization", "value": f"Bearer {access}"}],
                    },
                    "response": {},
                },
            ]
        }
    }
    tokens = detect(json.dumps(har))
    assert [t.payload for t in tokens] == [JWT, access]


def test_har_without_tokens_explains_what_to_capture():
    with pytest.raises(InputError, match="Preserve log"):
        detect(json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": "https://x.example.com/"}}]}}))


def test_saml_tracer_export():
    export = {
        "requests": [
            {"method": "POST", "url": "https://sp.example.com/saml/acs", "post": [["RelayState", "/"], ["SAMLResponse", POST]]}
        ],
        "timestamp": 0,
    }
    t = only(json.dumps(export))
    assert (t.container, t.payload) == ("SAML-tracer export", XML)


def test_saml_request_only_gives_a_helpful_error():
    with pytest.raises(InputError, match="AuthnRequest"):
        detect("https://idp.example.com/sso?SAMLRequest=" + urllib.parse.quote(REDIRECT))


@pytest.mark.parametrize("junk", ["hello world", "bm90IHhtbA==", "a.b.c"])
def test_garbage_is_rejected(junk):
    with pytest.raises(InputError):
        detect(junk)


def test_classify_error_names_location():
    with pytest.raises(InputError, match="^input:"):
        classify("not a token")


def test_read_input_sources(tmp_path):
    f = tmp_path / "t.txt"
    f.write_bytes(XML)
    assert read_input(path=str(f)) == XML
    assert read_input(token="abc") == b"abc"

    class FakeStdin(io.StringIO):
        def isatty(self):
            return False

    assert read_input(stdin=FakeStdin("xyz")) == b"xyz"


def test_read_input_errors(tmp_path):
    with pytest.raises(InputError, match="cannot read"):
        read_input(path=str(tmp_path / "missing"))
    with pytest.raises(InputError, match="empty"):
        read_input(token="   ")
