#!/usr/bin/env python3
"""Capture real SAML and OIDC samples from a running identity-lab.

Read only: this signs in as a lab user exactly as a browser would and keeps
what comes back. It never changes the lab, never runs its break or fix
scripts and never reads its .env. It never writes raw captures to disk:
everything is sanitised in memory first, and nothing is written if a
private key or a pattern that sanitising cannot remove turns up.

SAML: GET the SP's /login, follow the redirect to Keycloak, submit the login
form and take the SAMLResponse from Keycloak's auto-submit page. The
response is not posted on to the SP.

OIDC (only with --oidc): run the authorisation code flow with PKCE as the
lab's oidc-rp client, stop at the redirect back to the RP and redeem the code
at the token endpoint. That client is confidential, so its secret is needed:
set OIDC_CLIENT_SECRET or type it at the prompt. It is never stored.

Normally run through scripts/capture_from_lab.sh.
"""

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import html
import json
import os
import pathlib
import re
import secrets
import sys
import urllib.parse
import zlib

import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import sanitise  # noqa: E402  (sibling script)

TIMEOUT = 15


class CaptureError(RuntimeError):
    pass


# ---------------------------------------------------------------- page parsing (pure, unit tested)


def login_form_action(page):
    """The Keycloak login form's action URL, or None if this is not the login page."""
    m = re.search(r'<form[^>]*id="kc-form-login"[^>]*>', page)
    if not m:
        return None
    action = re.search(r'action="([^"]+)"', m.group(0))
    return html.unescape(action.group(1)) if action else None


def keycloak_error(page):
    """The message on a Keycloak error or failed-login page, if any."""
    for pattern in (r'id="input-error"[^>]*>\s*(.*?)\s*<', r'class="[^"]*kc-feedback-text[^"]*"[^>]*>\s*(.*?)\s*<',
                    r'id="kc-error-message"[^>]*>.*?<p[^>]*>\s*(.*?)\s*<'):
        m = re.search(pattern, page, re.DOTALL)
        if m and m.group(1).strip():
            return html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()
    return None


def saml_response_from_page(page):
    m = re.search(r'name="SAMLResponse"[^>]*value="([^"]+)"', page) or re.search(
        r'value="([^"]+)"[^>]*name="SAMLResponse"', page
    )
    return html.unescape(m.group(1)) if m else None


def authn_request_id(redirect_url):
    """The ID of the SP's AuthnRequest, from an HTTP-Redirect binding URL."""
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(redirect_url).query)
    if "SAMLRequest" not in query:
        return None
    xml = zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), -15)
    m = re.search(rb'\sID="([^"]+)"', xml)
    return m.group(1).decode() if m else None


def pkce_pair():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def code_from_redirect(location, state):
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)
    if "error" in query:
        raise CaptureError(f"IdP returned {query['error'][0]}: {query.get('error_description', [''])[0]}")
    if query.get("state", [None])[0] != state:
        raise CaptureError("state in the redirect does not match the request")
    if "code" not in query:
        raise CaptureError("redirect has no authorisation code")
    return query["code"][0]


# ---------------------------------------------------------------- HTTP flows


def _get(session, url, **kw):
    try:
        r = session.get(url, timeout=TIMEOUT, **kw)
    except requests.RequestException as exc:
        raise CaptureError(f"cannot reach {url}: {exc.__class__.__name__}") from None
    return r


def _submit_login(session, page, user, password):
    action = login_form_action(page)
    if action is None:
        raise CaptureError("expected the Keycloak login form but got a different page")
    try:
        return session.post(action, data={"username": user, "password": password, "credentialId": ""},
                            timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException as exc:
        raise CaptureError(f"cannot submit the login form: {exc.__class__.__name__}") from None


def capture_public(session, cfg):
    base = f"https://{cfg.host}:{cfg.kc_port}/realms/{cfg.realm}"
    discovery = _get(session, f"{base}/.well-known/openid-configuration")
    if discovery.status_code != 200:
        raise CaptureError(f"Keycloak discovery returned HTTP {discovery.status_code}; is the lab running?")
    disc = discovery.json()
    metadata = _get(session, f"{base}/protocol/saml/descriptor")
    jwks = _get(session, disc["jwks_uri"])
    if metadata.status_code != 200 or jwks.status_code != 200:
        raise CaptureError("could not download the IdP metadata or JWKS")
    return disc, metadata.content, jwks.text


def capture_saml(session, cfg, user, password):
    sp = f"https://{cfg.host}:{cfg.sp_port}"
    r = _get(session, f"{sp}/login", allow_redirects=False)
    if r.status_code not in (302, 303) or "Location" not in r.headers:
        raise CaptureError(f"SP /login returned HTTP {r.status_code}, not a redirect to the IdP")
    request_id = authn_request_id(r.headers["Location"])
    page = _get(session, r.headers["Location"]).text
    resp = _submit_login(session, page, user, password)
    value = saml_response_from_page(resp.text)
    if value is None:
        reason = keycloak_error(resp.text) or f"HTTP {resp.status_code}"
        raise CaptureError(f"no SAMLResponse after login ({reason})")
    return base64.b64decode(value), request_id


def capture_oidc(session, cfg, disc, user, password, client_secret):
    redirect_uri = f"https://{cfg.host}:{cfg.rp_port}/auth/callback"
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    verifier, challenge = pkce_pair()
    params = {
        "client_id": cfg.client_id, "response_type": "code", "scope": "openid email profile",
        "redirect_uri": redirect_uri, "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    r = _get(session, disc["authorization_endpoint"] + "?" + urllib.parse.urlencode(params), allow_redirects=False)
    if r.status_code == 200:  # login form (no SSO session yet)
        r = _submit_login(session, r.text, user, password)
    location = r.headers.get("Location", "")
    if not location.startswith(redirect_uri):
        reason = keycloak_error(r.text) if r.text else None
        raise CaptureError(f"no redirect back to the RP ({reason or f'HTTP {r.status_code}'})")
    code = code_from_redirect(location, state)
    try:
        token = session.post(disc["token_endpoint"], timeout=TIMEOUT, auth=(cfg.client_id, client_secret), data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "code_verifier": verifier,
        })
    except requests.RequestException as exc:
        raise CaptureError(f"cannot reach the token endpoint: {exc.__class__.__name__}") from None
    if token.status_code != 200:
        raise CaptureError(f"token endpoint returned HTTP {token.status_code} ({token.json().get('error', '?')})")
    body = token.json()
    return body["id_token"], body.get("access_token"), nonce


# ---------------------------------------------------------------- sanitise and write (unit tested)


def write_capture(out, captured_at, label, public, saml=None, oidc=None, personal=(), host_map=None):
    """Sanitise everything in memory, then write it. Returns a summary dict.

    public: (issuer, metadata_xml_bytes, jwks_text)
    saml:   (response_xml_bytes, request_id, sp_entity_id, acs_url) or None
    oidc:   (id_token, access_token, nonce, client_id) or None
    """
    issuer, metadata_xml, jwks_text = public
    files, summary = {}, {"label": label, "captured_at": captured_at, "files": {}}
    now_args = ["--now", captured_at]

    def text(value):
        return sanitise.sanitise_text(value, personal, host_map)[0]

    files["idp-metadata.xml"] = sanitise.sanitise_saml(metadata_xml, personal, host_map)[0]
    files["jwks.json"] = text(jwks_text).encode()
    if saml:
        xml, request_id, sp_entity, acs = saml
        clean, changed = sanitise.sanitise_saml(xml, personal, host_map)
        files["saml-response.xml"] = clean
        args = ["--metadata", "{dir}/idp-metadata.xml", "--expect-issuer", issuer, "--expect-audience", sp_entity,
                "--expect-destination", acs] + (["--expect-in-response-to", request_id] if request_id else [])
        files["saml-response.xml.meta.json"] = _meta(label, "SAML response captured from identity-lab",
                                                     args + now_args, changed, text)
        summary["files"]["saml-response.xml"] = changed
    if oidc:
        id_token, access_token, nonce, client_id = oidc
        clean, changed = sanitise.sanitise_jwt(id_token, personal, host_map)
        files["jwt-id-token.txt"] = (clean + "\n").encode()
        args = ["--jwks", "{dir}/jwks.json", "--expect-issuer", issuer, "--client-id", client_id, "--nonce", nonce]
        files["jwt-id-token.txt.meta.json"] = _meta(label, "ID token captured from identity-lab", args + now_args,
                                                    changed, text)
        summary["files"]["jwt-id-token.txt"] = changed
        if access_token:
            clean, changed = sanitise.sanitise_jwt(access_token, personal, host_map)
            files["jwt-access-token.txt"] = (clean + "\n").encode()
            args = ["--jwks", "{dir}/jwks.json", "--expect-issuer", issuer, "--token-type", "access"]
            files["jwt-access-token.txt.meta.json"] = _meta(label, "Access token captured from identity-lab",
                                                            args + now_args, changed, text)
            summary["files"]["jwt-access-token.txt"] = changed

    # Final gate: nothing is written unless every file is clean.
    for name, data in files.items():
        for view in sanitise.decoded_views(data.decode("utf-8", errors="replace")):
            problems = sanitise.find_problems(view, personal)
            if problems:
                raise CaptureError(f"{name} still contains a {problems[0]} after sanitising; nothing written")
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        (out / name).write_bytes(data)
    return summary


def _meta(label, description, args, changed, text):
    meta = {
        "description": description,
        "label": label,
        "args": [text(a) for a in args],
        "signature_invalidated_by_sanitising": changed,
    }
    return (json.dumps(meta, indent=2) + "\n").encode()


# ---------------------------------------------------------------- main


class Config:
    def __init__(self, args):
        self.host, self.realm, self.client_id = args.lab_host, args.realm, args.client_id
        self.kc_port, self.sp_port, self.rp_port = args.kc_port, args.sp_port, args.rp_port


def main(argv=None):
    p = argparse.ArgumentParser(description="Capture sanitised samples from a running identity-lab (read only).")
    p.add_argument("--lab-host", required=True, help="the lab's LAB_HOST, for example localhost")
    p.add_argument("--ca", required=True, help="the lab CA certificate (certs/ca.crt in the lab)")
    p.add_argument("--label", default="baseline", help="name for this capture, e.g. clock-skew (default baseline)")
    p.add_argument("--out", default="samples/lab", help="parent directory (default samples/lab)")
    p.add_argument("--user", default="alice")
    p.add_argument("--realm", default="idlab")
    p.add_argument("--client-id", default="oidc-rp")
    p.add_argument("--kc-port", type=int, default=8180)
    p.add_argument("--sp-port", type=int, default=8181)
    p.add_argument("--rp-port", type=int, default=8182)
    p.add_argument("--oidc", action="store_true", help="also capture ID and access tokens (needs the client secret)")
    p.add_argument("--map-host", action="store_true",
                   help="replace the lab host name with idlab.example.com (breaks signatures)")
    args = p.parse_args(argv)

    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}", args.label):
        print("lab_capture: --label must be lower-case letters, digits and hyphens", file=sys.stderr)
        return 2
    out = pathlib.Path(args.out) / args.label
    if out.exists():
        print(f"lab_capture: {out} already exists; choose another --label or delete it", file=sys.stderr)
        return 2
    password = os.environ.get("LAB_PASSWORD") or getpass.getpass(f"Password for lab user {args.user}: ")
    client_secret = None
    if args.oidc:
        client_secret = os.environ.get("OIDC_CLIENT_SECRET") or getpass.getpass("oidc-rp client secret: ")

    cfg = Config(args)
    session = requests.Session()
    session.verify = args.ca
    captured_at = dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    host_map = {args.lab_host: "idlab.example.com"} if args.map_host and args.lab_host != "localhost" else None
    try:
        disc, metadata_xml, jwks_text = capture_public(session, cfg)
        xml, request_id = capture_saml(session, cfg, args.user, password)
        sp = f"https://{cfg.host}:{cfg.sp_port}"
        saml = (xml, request_id, f"{sp}/saml/metadata", f"{sp}/saml/acs")
        oidc = None
        if args.oidc:
            id_token, access_token, nonce = capture_oidc(session, cfg, disc, args.user, password, client_secret)
            oidc = (id_token, access_token, nonce, cfg.client_id)
        summary = write_capture(out, captured_at, args.label, (disc["issuer"], metadata_xml, jwks_text), saml, oidc,
                                sanitise.load_personal_patterns(), host_map)
    except (CaptureError, sanitise.UnsafeContent) as exc:
        print(f"lab_capture: {exc}", file=sys.stderr)
        return 1

    print(f"lab_capture: wrote {out} (captured {captured_at})")
    for name, changed in summary["files"].items():
        note = "sanitising changed it, so its signature no longer verifies" if changed else "unchanged, signature intact"
        print(f"  {name}: {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
