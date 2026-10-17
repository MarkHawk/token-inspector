import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """The tool is offline by default: any socket connection fails the test."""

    def refuse(*args, **kwargs):
        raise AssertionError("token-inspector attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
