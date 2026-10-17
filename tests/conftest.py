import datetime as dt
import importlib.util
import json
import pathlib
import socket

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Every test runs as if it were this moment, so results never depend on the
# wall clock. The generator builds certificates and tokens relative to it.
NOW = dt.datetime(2026, 3, 2, 12, 0, 0, tzinfo=dt.UTC)
NOW_ISO = "2026-03-02T12:00:00Z"


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_samples", ROOT / "scripts" / "generate_samples.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load_generator()


class Samples:
    def __init__(self, path):
        self.dir = path

    def path(self, name):
        return self.dir / name

    def read(self, name):
        return (self.dir / name).read_bytes()

    def meta(self, name):
        return json.loads((self.dir / (name + ".meta.json")).read_text())

    def args(self, name):
        """The CLI arguments recorded for a sample, with paths filled in."""
        return [a.replace("{dir}", str(self.dir)) for a in self.meta(name)["args"]]

    def names(self, prefix=""):
        return sorted(p.name[: -len(".meta.json")] for p in self.dir.glob(f"{prefix}*.meta.json"))


@pytest.fixture(scope="session")
def samples(tmp_path_factory):
    out = tmp_path_factory.mktemp("samples")
    generator.generate(out, NOW)
    return Samples(out)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """The tool is offline by default: any socket connection fails the test."""

    def refuse(*args, **kwargs):
        raise AssertionError("token-inspector attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
