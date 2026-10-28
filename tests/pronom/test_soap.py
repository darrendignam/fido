"""Offline contract tests for PRONOM SOAP helpers."""

import unittest.mock
import urllib.error

import pytest

import fido.pronom


class FakeResponse:
    """Small response shim used to mock urllib responses."""

    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeRequest:
    """Simple urllib Request shim with header support."""

    def __init__(self, url, data=None):
        self.url = url
        self.data = data
        self.headers = {}

    def add_header(self, key, value):
        self.headers[key] = value


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_pronom_version_from_mocked_soap_response(mock_request):
    """Parse signature version from a mocked SOAP payload."""
    xml = b"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">
  <soap:Body>
  <getSignatureFileVersionV1Response xmlns=\"http://pronom.nationalarchives.gov.uk\">
    <getSignatureFileVersionV1Result>
    <Version><Version>116</Version></Version>
    </getSignatureFileVersionV1Result>
  </getSignatureFileVersionV1Response>
  </soap:Body>
</soap:Envelope>
"""

    mock_request.Request.side_effect = lambda url, data=None: FakeRequest(
        url, data=data
    )
    mock_request.urlopen.return_value = FakeResponse(xml)

    assert fido.pronom.soap.get_pronom_sig_version() == 116


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_get_droid_signatures_counts_file_formats(mock_request):
    """Count FileFormat elements from a mocked DROID signature XML file."""
    sig_xml = b"""<?xml version=\"1.0\" encoding=\"utf-8\"?>
<SignatureFile xmlns=\"http://www.nationalarchives.gov.uk/pronom/SignatureFile\">
  <FileFormatCollection>
  <FileFormat ID=\"1\" PUID=\"fmt/1\" />
  <FileFormat ID=\"2\" PUID=\"fmt/2\" />
  </FileFormatCollection>
</SignatureFile>
"""

    mock_request.urlopen.return_value = FakeResponse(sig_xml)

    xml, count = fido.pronom.soap.get_droid_signatures(116, min_formats=1)
    assert "SignatureFile" in xml
    assert count == 2


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_get_droid_signatures_handles_http_error(mock_request, capsys):
    """Return fallback values and log an error when download fails."""

    mock_request.urlopen.side_effect = urllib.error.HTTPError(
        url="http://example.test", code=500, msg="boom", hdrs=None, fp=None
    )

    xml, count = fido.pronom.soap.get_droid_signatures(116, min_formats=1)
    captured = capsys.readouterr()
    assert xml == []
    assert count is False
    assert "could not download signature file v116" in captured.err


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_get_sig_xml_for_puid_returns_raw_xml(mock_request):
    """Return unmodified PRONOM XML bytes for a PUID."""
    payload = b"<root><foo>bar</foo></root>"
    mock_request.urlopen.return_value = FakeResponse(payload)

    assert fido.pronom.soap.get_sig_xml_for_puid("fmt/18") == payload


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_get_soap_response_exits_on_connection_error(mock_request, capsys):
    """Exit with code 1 when the connection fails.

    The guard used to wrap Request(), which only parses a URL and raises
    ValueError, so this message was unreachable while a real connection
    failure escaped as a traceback from urlopen.
    """
    mock_request.urlopen.side_effect = urllib.error.URLError("offline")

    with pytest.raises(SystemExit) as exc:
        fido.pronom.soap._get_soap_response('"action"', b"<soap/>")

    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert "There was a problem contacting the PRONOM service" in captured.out
    assert "https://" in captured.out


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_get_droid_signatures_refuses_an_html_error_page(mock_request, capsys):
    """A maintenance page is well formed XML, so it used to install cleanly.

    get_droid_signatures returned it as a valid signature file, the caller
    discarded the format count, and a known good file was overwritten with a
    document holding no formats at all.
    """
    page = b"<html><body>Sorry, we are down for maintenance</body></html>"
    mock_request.urlopen.return_value.__enter__.return_value.read.return_value = page

    xml, count = fido.pronom.soap.get_droid_signatures(116)

    assert xml == []
    assert count is False
    assert "refusing it" in capsys.readouterr().err


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_get_droid_signatures_survives_a_network_failure(mock_request, capsys):
    """Only HTTPError was caught, so a DNS failure aborted the whole update."""
    mock_request.urlopen.side_effect = urllib.error.URLError("no route to host")

    xml, count = fido.pronom.soap.get_droid_signatures(116)

    assert xml == []
    assert count is False
    assert "could not download signature file" in capsys.readouterr().err


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_per_puid_fetch_uses_https_and_the_documented_path(mock_request):
    """The URL was never asserted, so pointing FIDO at the wrong host or
    scheme would have passed. This fetch supplies the data that becomes the
    regexes FIDO executes, so it must not travel in clear."""
    recorded = {}

    def record(url, *_args, **_kwargs):
        recorded["url"] = url
        return unittest.mock.MagicMock()

    mock_request.Request.side_effect = record
    mock_request.urlopen.return_value.__enter__.return_value.read.return_value = b"<x/>"

    fido.pronom.soap.get_sig_xml_for_puid("fmt/18")

    assert recorded["url"] == "https://www.nationalarchives.gov.uk/pronom/fmt/18.xml"


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_soap_request_carries_its_action_and_headers(mock_request):
    """The SOAPAction header and the service path were both unverified."""
    recorded = {"headers": {}}

    class FakeRequest:
        def __init__(self, url, data=None):
            recorded["url"] = url
            recorded["data"] = data

        def add_header(self, key, value):
            recorded["headers"][key] = value

    mock_request.Request.side_effect = FakeRequest
    mock_request.urlopen.return_value.__enter__.return_value.read.return_value = b"<soap/>"

    fido.pronom.soap._get_soap_response('"getVersion"', b"<envelope/>")

    assert recorded["url"].startswith("https://")
    assert recorded["url"].endswith("/pronom/service.asmx")
    assert recorded["headers"]["SOAPAction"] == '"getVersion"'
    assert recorded["headers"]["Content-length"] == str(len(b"<envelope/>"))


@unittest.mock.patch("fido.pronom.soap.urllib.request")
def test_every_soap_call_passes_a_timeout(mock_request):
    """urlopen defaults to no timeout, so a stalled server hung the updater."""
    recorded = []

    def record(_req, *_args, **kwargs):
        recorded.append(kwargs.get("timeout"))
        return unittest.mock.MagicMock()

    mock_request.urlopen.side_effect = record

    fido.pronom.soap.get_sig_xml_for_puid("fmt/18")

    assert recorded and all(timeout is not None for timeout in recorded)
