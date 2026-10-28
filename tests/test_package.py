import os
import zipfile
from io import BytesIO

import pytest

from fido.package import OlePackage, ZipPackage

TEST_DATA_BAD_PACKAGES = os.path.normpath(
    os.path.join(__file__, "..", "test_data/hard_packages")
)


def signature(puid, *files, signature_id="1"):
    """Build the signature structure extract_signatures produces.

    Each entry in @param files is (path, [sequence, ...]); every file and every
    sequence has to match for the signature to match.
    """
    return {
        puid: [
            {
                "id": signature_id,
                "files": [
                    {
                        "path": path,
                        "sequences": [{"sequence": sequence, "max_offset": None} for sequence in sequences],
                    }
                    for path, sequences in files
                ],
            }
        ]
    }


def build_zip(path, members):
    with zipfile.ZipFile(path, "w") as handle:
        for name, data in members.items():
            handle.writestr(name, data)
    return path


# These are deliberately damaged or unusual archives. A real signature map is
# passed so that an empty result proves the error handling fired, rather than
# proving that an empty signature map has nothing to iterate.
@pytest.mark.parametrize(
    "filename", ["bad.zip", "worse.zip", "unicode.zip", "foo.zip", "foo.tar"]
)
def test_damaged_archives_yield_no_match_and_do_not_raise(filename):
    signatures = signature("fmt/1", ("content/file.bin", [b"abc"]), ("limeri", [b"abc"]))

    package = ZipPackage(os.path.join(TEST_DATA_BAD_PACKAGES, filename), signatures)

    assert package.detect_formats() == []


def test_zip_detect_formats_positive_match(tmp_path):
    archive = build_zip(tmp_path / "sample.zip", {"content/file.bin": b"abcdef"})
    signatures = signature("fmt/1", ("content/file.bin", [b"abc"]))

    assert ZipPackage(str(archive), signatures).detect_formats() == ["fmt/1"]


def test_zip_detect_formats_missing_path(tmp_path):
    archive = build_zip(tmp_path / "sample.zip", {"other/file.bin": b"abcdef"})
    signatures = signature("fmt/1", ("content/file.bin", [b"abc"]))

    assert ZipPackage(str(archive), signatures).detect_formats() == []


def test_every_file_of_a_signature_must_be_present(tmp_path):
    """The discriminating file is often the second one.

    Signature 6000 for OpenDocument Text requires both META-INF/manifest.xml
    and content.xml, and only the first was examined, so an archive carrying
    the manifest alone matched every ODF version at once.
    """
    archive = build_zip(tmp_path / "partial.zip", {"META-INF/manifest.xml": b"opendocument.text"})
    signatures = signature(
        "fmt/136",
        ("META-INF/manifest.xml", [b"opendocument.text"]),
        ("content.xml", [b"office:document-content"]),
    )

    assert ZipPackage(str(archive), signatures).detect_formats() == []

    complete = build_zip(
        tmp_path / "complete.zip",
        {"META-INF/manifest.xml": b"opendocument.text", "content.xml": b"office:document-content"},
    )
    assert ZipPackage(str(complete), signatures).detect_formats() == ["fmt/136"]


def test_every_sequence_of_a_file_must_match(tmp_path):
    """A second subsequence is what distinguishes one version from another."""
    signatures = signature(
        "fmt/291",
        ("content.xml", [b"office:document-content", b"office:version='1.2'"]),
    )

    without_version = build_zip(tmp_path / "a.zip", {"content.xml": b"office:document-content"})
    assert ZipPackage(str(without_version), signatures).detect_formats() == []

    with_version = build_zip(
        tmp_path / "b.zip", {"content.xml": b"office:document-content office:version='1.2'"}
    )
    assert ZipPackage(str(with_version), signatures).detect_formats() == ["fmt/291"]


def test_alternative_signatures_for_one_puid_are_ored(tmp_path):
    archive = build_zip(tmp_path / "sample.zip", {"b.xml": b"second"})
    signatures = {
        "fmt/1": [
            {"id": "1", "files": [{"path": "a.xml", "sequences": [{"sequence": b"first", "max_offset": None}]}]},
            {"id": "2", "files": [{"path": "b.xml", "sequences": [{"sequence": b"second", "max_offset": None}]}]},
        ]
    }

    assert ZipPackage(str(archive), signatures).detect_formats() == ["fmt/1"]


def test_max_offset_bounds_where_a_sequence_may_start(tmp_path):
    archive = build_zip(tmp_path / "sample.zip", {"a.xml": b"\x00" * 200 + b"MATCH"})
    signatures = {
        "fmt/1": [
            {"id": "1", "files": [{"path": "a.xml", "sequences": [{"sequence": b"MATCH", "max_offset": 100}]}]}
        ]
    }

    assert ZipPackage(str(archive), signatures).detect_formats() == []

    signatures["fmt/1"][0]["files"][0]["sequences"][0]["max_offset"] = 300
    assert ZipPackage(str(archive), signatures).detect_formats() == ["fmt/1"]


def test_container_member_read_is_bounded(tmp_path):
    """A compressed member must not be read whole into memory.

    A 200KB archive holding a 200MB member drove peak RSS past 450MB, because
    the read had no size argument.
    """
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("mimetype", b"MATCH" + b"\x00" * (4 * 1024 * 1024))

    near = signature("fmt/X", ("mimetype", [b"MATCH"]))
    assert ZipPackage(archive, near, max_read=1024).detect_formats() == ["fmt/X"]

    # A sequence beyond the cap is unreachable, which proves the whole member
    # was not read
    far = signature("fmt/Y", ("mimetype", [b"\\x00{2000000}"]))
    assert ZipPackage(archive, far, max_read=1024).detect_formats() == []


def test_invalid_container_signature_is_skipped_not_raised(tmp_path, capsys):
    """fmt/125 in the shipped container file converts to an invalid pattern."""
    archive = build_zip(tmp_path / "sample.zip", {"mimetype": b"anything"})
    signatures = signature("fmt/BAD", ("mimetype", [b"\\x(0\\x0|\\x01\\x)0"]))

    assert ZipPackage(str(archive), signatures).detect_formats() == []
    assert "invalid container signature" in capsys.readouterr().err


class DummyOle:
    """Minimal stand-in for olefile.OleFileIO."""

    def __init__(self, streams):
        self.streams = streams

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def listdir(self):
        return [name.split("/") for name in self.streams]

    def openstream(self, path):
        return BytesIO(self.streams[path])


@pytest.mark.parametrize(
    ("streams", "wanted", "expected"),
    (
        # A prefix on a top-level stream is stripped, as before
        ({"\x01CompObj": b"MATCH"}, "CompObj", ["fmt/1"]),
        # A prefix on a nested component used to be missed entirely, and
        # Document/Page1 is a real shipped signature path
        ({"Document/\x01Page1": b"MATCH"}, "Document/Page1", ["fmt/1"]),
        # One extra leading character used to count as a match
        ({"XHeader": b"MATCH"}, "Header", []),
        ({"1Table": b"MATCH"}, "Table", []),
        # A name of the wrong depth must not match
        ({"Document/Page1/Extra": b"MATCH"}, "Document/Page1", []),
    ),
)
def test_ole_stream_paths_are_matched_per_component(monkeypatch, streams, wanted, expected):
    signatures = signature("fmt/1", (wanted, [b"MATCH"]))
    package = OlePackage("ole.bin", signatures)
    monkeypatch.setattr(package, "open_container", lambda: DummyOle(streams))

    assert package.detect_formats() == expected


def test_ole_detect_formats_handles_a_broken_container(capsys):
    """olefile raises OSError and ValueError for malformed input."""
    package = OlePackage(os.path.join(TEST_DATA_BAD_PACKAGES, "foo.zip"), signature("fmt/1", ("x", [b"y"])))

    assert package.detect_formats() == []
    assert "could not read container" in capsys.readouterr().err
