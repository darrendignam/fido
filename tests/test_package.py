import os
import zipfile
from io import BytesIO

import pytest

from fido.package import OlePackage, Package, ZipPackage

TEST_DATA_BAD_PACKAGES = os.path.normpath(
    os.path.join(__file__, "..", "test_data/hard_packages")
)


# None of these files should be identified as packages?
@pytest.mark.parametrize(
    "filename", ["bad.zip", "worse.zip", "unicode.zip", "foo.zip", "foo.tar"]
)
def test_bad_zip(filename):
    p = ZipPackage(os.path.join(TEST_DATA_BAD_PACKAGES, filename), {})
    r = p.detect_formats()
    assert isinstance(r, list) and len(r) == 0


def test_zip_detect_formats_positive_match(tmp_path):
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("content/file.bin", b"abcdef")

    signatures = {
        "content/file.bin": {
            "fmt/1": [{"signature": b"abc"}],
            "fmt/2": [{"signature": b"xyz"}],
        }
    }
    package = ZipPackage(str(zip_path), signatures)

    assert package.detect_formats() == ["fmt/1"]


def test_zip_detect_formats_missing_path(tmp_path):
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("other/file.bin", b"abcdef")

    signatures = {
        "content/file.bin": {
            "fmt/1": [{"signature": b"abc"}],
        }
    }
    package = ZipPackage(str(zip_path), signatures)

    assert package.detect_formats() == []


def test_package_process_matches_all_matching_signatures():
    package = Package()
    signatures = [{"signature": b"abc"}, {"signature": b"def"}, {"signature": b"xxx"}]

    matches = package._process_matches(b"abcdef", "fmt/1", signatures)

    assert matches == ["fmt/1", "fmt/1"]


def test_package_process_puid_map_aggregates_results():
    package = Package()
    puid_map = {
        "fmt/1": [{"signature": b"abc"}],
        "fmt/2": [{"signature": b"def"}],
    }

    matches = package._process_puid_map(b"abcdef", puid_map)

    assert matches == ["fmt/1", "fmt/2"]


def test_ole_detect_formats_positive(monkeypatch):
    class DummyOle:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def listdir(self):
            return [["Root", "Object"]]

        def openstream(self, _filepath):
            return BytesIO(b"abcdef")

    monkeypatch.setattr("fido.package.olefile.OleFileIO", lambda _ole: DummyOle())

    signatures = {"Root/Object": {"fmt/1": [{"signature": b"abc"}], "fmt/2": [{"signature": b"xyz"}]}}
    package = OlePackage("dummy.ole", signatures)

    assert package.detect_formats() == ["fmt/1"]


def test_ole_detect_formats_handles_ioerror(monkeypatch):
    monkeypatch.setattr("fido.package.olefile.OleFileIO", lambda _ole: (_ for _ in ()).throw(IOError("boom")))

    package = OlePackage("dummy.ole", {})

    assert package.detect_formats() == []


def test_container_member_read_is_bounded():
    """A compressed member must not be read whole into memory.

    A 200KB archive holding a 200MB member drove peak RSS past 450MB, because
    detect_formats called read() with no size.
    """
    payload = b"MATCH" + b"\x00" * (4 * 1024 * 1024)
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("mimetype", payload)

    signatures = {"mimetype": {"fmt/X": [{"signature": b"MATCH"}]}}
    package = ZipPackage(archive, signatures, max_read=1024)

    # The sequence is inside the first KB, so a bounded read still matches
    assert package.detect_formats() == ["fmt/X"]

    # ... and a sequence beyond the cap is not reachable, which is the proof
    # that the whole member was not read
    far_signatures = {"mimetype": {"fmt/Y": [{"signature": b"\\x00{2000000}"}]}}
    assert ZipPackage(archive, far_signatures, max_read=1024).detect_formats() == []


def test_invalid_container_signature_is_skipped_not_raised(capsys):
    """A container sequence that cannot compile must not abort the run.

    fmt/125 in the shipped container signature file converts to an invalid
    pattern, so one OLE2 file with a Header stream killed a whole batch.
    """
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("mimetype", b"anything")

    signatures = {"mimetype": {"fmt/BAD": [{"signature": b"\\x(0\\x0|\\x01\\x)0"}]}}

    assert ZipPackage(archive, signatures).detect_formats() == []
    assert "invalid container signature for fmt/BAD" in capsys.readouterr().err
