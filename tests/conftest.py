"""Shared fixtures and guards for the FIDO test suite."""

import copy
import socket

import pytest

from fido import fido as fido_mod


@pytest.fixture(autouse=True)
def restore_module_defaults():
    """Restore fido.defaults after every test.

    main() writes xml_pronomSignature, containersignature_file and
    format_files into the module level dict and nothing put them back, so a
    test exercising -pronom_only permanently disabled extension matching for
    every test that ran afterwards.
    """
    saved = copy.deepcopy(fido_mod.defaults)
    yield
    fido_mod.defaults.clear()
    fido_mod.defaults.update(saved)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail any test that tries to reach the network.

    Several tests reach code that would contact the PRONOM service if a
    monkeypatch were forgotten, and hitting a public archive from a test run
    is never intended.
    """
    def refuse(*args, **kwargs):
        raise AssertionError("this test tried to open a network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
