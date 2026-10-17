#!/usr/bin/env python3
"""Build the samples that `token-inspector demo` runs.

They ship inside the package (src/token_inspector/demo_samples/) so the demo
works from any install. Each sample gets its own folder holding the token, the
public trust material it is checked against, and nothing else: no private key
is copied. Every sample is evaluated as at a fixed time recorded in demo.json,
so the demo gives the same verdicts whenever it is run.

    python scripts/build_demo_samples.py

Three samples are synthetic (built by generate_samples.py at DEMO_NOW); the
fourth is the committed identity-lab capture taken mid certificate rotation.
"""

import json
import pathlib
import shutil
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_samples  # noqa: E402

OUT = ROOT / "src" / "token_inspector" / "demo_samples"
LAB = ROOT / "samples" / "lab" / "expired-signing-cert"
DEMO_NOW = "2026-03-02T12:00:00Z"

# name, title, generated sample (its recorded args are reused), trust file
SYNTHETIC = [
    ("valid", "Signed SAML response, in date", "saml-valid.xml", "idp-metadata.xml"),
    ("expired", "OIDC ID token, expired 3 h ago", "jwt-expired.txt", "jwks.json"),
    ("xsw", "Forged SAML response", "saml-xsw.xml", "idp-metadata.xml"),
]


def lab_args():
    """The lab capture's recorded args, checked against the cert the SP had pinned."""
    meta = json.loads((LAB / "saml-response.xml.meta.json").read_text())
    args, skip = [], False
    for a in meta["args"]:
        if skip:
            skip = False
        elif a == "--metadata":
            skip = True
        else:
            args.append(a)
    return ["--cert", "{dir}/sp-pinned-cert.pem", *args]


def build():
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    samples = []
    with tempfile.TemporaryDirectory() as tmp:
        now = generate_samples.dt.datetime.fromisoformat(DEMO_NOW.replace("Z", "+00:00"))
        generate_samples.generate(tmp, now)
        tmp = pathlib.Path(tmp)
        for name, title, file, trust in SYNTHETIC:
            folder = OUT / name
            folder.mkdir()
            shutil.copy(tmp / file, folder / file)
            shutil.copy(tmp / trust, folder / trust)
            meta = json.loads((tmp / (file + ".meta.json")).read_text())
            samples.append({"name": name, "title": title, "file": file,
                            "args": [*meta["args"], "--now", DEMO_NOW]})
    folder = OUT / "rotation"
    folder.mkdir()
    for file in ("saml-response.xml", "sp-pinned-cert.pem"):
        shutil.copy(LAB / file, folder / file)
    samples.insert(2, {"name": "rotation", "title": "Lab capture, mid key rotation",
                       "file": "saml-response.xml", "args": lab_args()})
    (OUT / "demo.json").write_text(json.dumps({"samples": samples}, indent=2) + "\n")
    return samples


def main():
    samples = build()
    print(f"wrote {len(samples)} demo samples to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
