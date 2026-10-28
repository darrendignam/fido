"""End to end identification guards.

The rest of the suite tests units. These drive real Fido against the shipped
signature file with small built fixtures, assert the expected PUID *and the
absence of the wrong ones*, and bound how long identification may take. That
combination is what the known open bugs need: a misidentification regression
only shows up as a negative assertion, and a backtracking regression only as a
time budget.
"""

import io
import json
import time
import zipfile

import pytest

from fido.fido import Fido
from fido.pronom.versions import get_local_versions

# Identification of one small file is milliseconds; this is three orders of
# magnitude of headroom, so it only fires on a real regression
TIME_BUDGET_SECONDS = 20


@pytest.fixture(scope="module")
def fido():
    """A real Fido with the shipped signatures, built once for the module."""
    # defaults only carries these once main() has run, so read them from
    # versions.xml the way main() does
    versions = get_local_versions()
    return Fido(
        quiet=True,
        format_files=[versions.pronom_signature, versions.fido_extension_signature],
        containersignature_file=versions.pronom_container_signature,
    )


def identify(fido, path):
    """Return (puids, matchtypes) for @param path."""
    results = []

    def collect(_name, matches, _delta, matchtype=""):
        results.append(([fido.get_puid(match[0]) for match in matches], matchtype))

    original = fido.handle_matches
    fido.handle_matches = collect
    try:
        fido.identify_file(str(path))
    finally:
        fido.handle_matches = original
    return results[-1] if results else ([], None)


def build_odt(path, version):
    """Write a minimal but plausible ODF text document."""
    with zipfile.ZipFile(path, "w") as handle:
        handle.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        handle.writestr(
            "META-INF/manifest.xml",
            '<?xml version="1.0"?><manifest:manifest '
            'xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
            '<manifest:file-entry manifest:full-path="/" '
            'manifest:media-type="application/vnd.oasis.opendocument.text"/></manifest:manifest>',
        )
        handle.writestr(
            "content.xml",
            '<?xml version="1.0"?><office:document-content '
            'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
            'office:version="{}"></office:document-content>'.format(version),
        )
    return path


def test_an_odf_document_is_identified_as_one_version_only(fido, tmp_path):
    """The version test lives in content.xml, the second file of the signature.

    Only the first file and its first sequence were examined, so one document
    was reported as fmt/136, fmt/290, fmt/291 and fmt/1756 at once.
    """
    puids, _matchtype = identify(fido, build_odt(tmp_path / "doc.odt", "1.2"))

    assert "fmt/291" in puids
    assert "fmt/290" not in puids
    assert "fmt/136" not in puids
    assert len(puids) == 1


def test_an_incomplete_archive_is_not_claimed_as_an_odf_document(fido, tmp_path):
    """PRONOM requires content.xml, so a manifest alone must not be enough."""
    path = tmp_path / "fake.odt"
    with zipfile.ZipFile(path, "w") as handle:
        handle.writestr(
            "META-INF/manifest.xml",
            'manifest:media-type="application/vnd.oasis.opendocument.text"',
        )
        handle.writestr("readme.txt", "not really an odt")

    puids, _matchtype = identify(fido, path)

    assert "x-fmt/263" in puids, "expected it to be reported as plain ZIP"
    for odf in ("fmt/136", "fmt/290", "fmt/291", "fmt/1756"):
        assert odf not in puids


def test_an_ooxml_document_is_identified(fido, tmp_path):
    """Guards the container path that upstream #152 concerns."""
    path = tmp_path / "doc.docx"
    with zipfile.ZipFile(path, "w") as handle:
        handle.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types '
            'xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Override PartName="/word/document.xml" ContentType="application/vnd.'
            'openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        )
        handle.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document '
            'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body/></w:document>",
        )
        handle.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')

    puids, _matchtype = identify(fido, path)

    assert "fmt/412" in puids
    assert "fido-fmt" not in " ".join(puids)


def test_plain_json_does_not_match_the_tweet_signature(fido, tmp_path):
    """Upstream #230 reports JSON identified as tweets.

    The signature itself is sound: it requires "id_str" and "retweeted", which
    ordinary JSON does not carry. What users see is the extension fallback,
    because PRONOM lists json as Tweet JSON's extension, so the guard worth
    having is that the *signature* path does not match.
    """
    path = tmp_path / "data.json"
    path.write_text(json.dumps({"name": "value", "list": [1, 2, 3]}), encoding="utf-8")

    puids, matchtype = identify(fido, path)

    if "fmt/1311" in puids:
        assert matchtype == "extension", "Tweet JSON must never be a signature match here"


def test_identification_is_bounded_on_a_pathological_buffer(fido, tmp_path):
    """Upstream #233: a DPX frame full of 0xFF bytes made MP3 patterns
    backtrack for an unbounded time. fmt/134 chains bounded gaps rather than
    using .* so the atomic rewrite does not apply to it, and the per-file
    budget is what stops it."""
    path = tmp_path / "frames.dpx"
    path.write_bytes(b"SDPX" + b"\xff\xfb\x10" * 20000)

    started = time.monotonic()
    puids, _matchtype = identify(fido, path)
    elapsed = time.monotonic() - started

    assert elapsed < TIME_BUDGET_SECONDS, "identification took {:.1f}s".format(elapsed)
    assert puids, "the file should still be reported"


def test_a_gif_is_identified_quickly(fido, tmp_path):
    """A baseline, so the budget above is measured against something sane."""
    path = tmp_path / "sample.gif"
    path.write_bytes(b"GIF89a\x01\x00\x01\x00\x00\x00\x00;")

    started = time.monotonic()
    puids, matchtype = identify(fido, path)

    assert puids == ["fmt/4"]
    assert matchtype == "signature"
    assert time.monotonic() - started < 1.0


def test_identifying_a_stream_matches_identifying_a_file(fido, tmp_path):
    """Upstream #189 was a hang on stream identification, so both paths are
    driven for the same bytes."""
    magic = b"\x5a\x58\x54\x61\x70\x65\x21\x1a\x01"
    path = tmp_path / "sample.tzx"
    path.write_bytes(magic)
    from_file, _ = identify(fido, path)

    results = []
    fido.handle_matches = lambda _n, matches, _d, matchtype="": results.append(
        [fido.get_puid(match[0]) for match in matches]
    )
    try:
        fido.identify_stream(io.BytesIO(magic), str(path))
    finally:
        del fido.handle_matches

    assert "fmt/1000" in from_file
    assert results[-1] == from_file
