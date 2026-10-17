"""Run committed identity-lab captures (samples/lab/<label>/) through the CLI.

Each capture records the time it was taken, so it is evaluated as at that
moment. Skipped when there are no captures, as in a fresh clone."""

import io
import json
import pathlib

import pytest

from conftest import ROOT
from token_inspector.cli import EXIT_ERROR, main

CAPTURES = sorted(pathlib.Path(ROOT / "samples" / "lab").glob("*/*.meta.json"))


@pytest.mark.skipif(not CAPTURES, reason="no lab captures committed yet")
@pytest.mark.parametrize("meta_path", CAPTURES, ids=[f"{p.parent.name}/{p.name[:-10]}" for p in CAPTURES])
def test_lab_capture(meta_path):
    meta = json.loads(meta_path.read_text())
    sample = meta_path.with_name(meta_path.name[: -len(".meta.json")])
    args = [a.replace("{dir}", str(meta_path.parent)) for a in meta["args"]]
    out = io.StringIO()
    code = main([str(sample), *args, "--json"], stdout=out, stderr=io.StringIO())
    assert code != EXIT_ERROR
    findings = {f["check_id"]: f["status"] for f in json.loads(out.getvalue())["findings"]}
    signature = findings.get("saml.signature.assertion") or findings.get("jwt.signature")
    if meta["signature_invalidated_by_sanitising"]:
        assert signature == "FAIL"
    elif meta["label"] == "baseline":
        assert code == 0, findings  # a healthy lab produces a clean report
