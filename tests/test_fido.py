#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import io
from xml.etree import ElementTree as XET
from time import sleep
from types import SimpleNamespace

import pytest

import fido.fido as fido_mod
from fido.fido import Fido
from fido.utils.timer import PerfTimer


def test_perf_timer():
    timer = PerfTimer()
    sleep(0.2)
    duration = timer.duration()
    assert duration > 0


id_test_data = [(b"\x5a\x58\x54\x61\x70\x65\x21\x1a\x01", "fmt/1000", "OK")]


@pytest.mark.parametrize(
    "magic, expected_puid, expected_result",
    id_test_data,
    # Add additional test cases here
)
def test_file_identification(tmp_path, capsys, magic: bytes, expected_puid: str, expected_result: str):
    """Reference for Fido-based format identification
    1. Create a byte-stream with a known magic number and serialize to tempfile.
    2. Call identify_file(...) to identify the file against Fido's known formats.
    """
    # Create a temporary file and write our skeleton file out to it.
    tmp_file = tmp_path / "tmp_file"
    tmp_file.write_bytes(magic)

    # Create a Fido instance and call identify_file. The identify_file function
    # will create and manage a file for itself.
    f = Fido()
    f.identify_file(str(tmp_file))

    # Capture the stdout returned by Fido and make assertions about its
    # validity.
    captured = capsys.readouterr()
    # TODO: there is a signature that generates an error
    # min repeat greater than max repeat at position 8
    # assert captured.err == ""
    reader = csv.reader(io.StringIO(captured.out), delimiter=",")
    assert reader is not None
    row = next(reader)
    assert row[0] == expected_result, "row hasn't returned a positive identification"
    assert row[2] == expected_puid, "row doesn't contain expected PUID value"
    assert int(row[5]) == len(magic), "row doesn't contain stream length"


@pytest.mark.parametrize(
    "magic, expected_puid, expected_result",
    id_test_data,
    # Add additional test cases here
)
def test_stream_identification(capsys, magic: bytes, expected_puid: str, expected_result: str):
    """Reference for Fido-based format identification
    1. Create a byte-stream with a known magic number.
    2. Call identify_stream(...) to identify the file against Fido's known formats.
    """
    # Create the stream object with the known magic-number.
    fstream = io.BytesIO(magic)

    # Create a Fido instance and call identify_stream. The identify_stream function
    # will work on the stream as-is. This could be an open file handle that the
    # caller is managing for itself.
    f = Fido()
    f.identify_stream(fstream, "filename to display", extension=False)

    # Capture the stdout returned by Fido and make assertions about its
    # validity.
    captured = capsys.readouterr()
    # TODO: as above, there is a signature that outputs an error
    # min repeat greater than max repeat at position 8
    # assert captured.err == ""
    reader = csv.reader(io.StringIO(captured.out), delimiter=",")
    assert reader is not None
    row = next(reader)
    assert row[0] == expected_result, "row hasn't returned a positive identification"
    assert row[2] == expected_puid, "row doesn't contain expected PUID value"
    assert int(row[5]) == len(magic), "row doesn't contain stream length"


def _format_element(puid, container=None, extension=None, has_priority_over=None):
    fmt = XET.Element("format")
    XET.SubElement(fmt, "puid").text = puid
    XET.SubElement(fmt, "name").text = puid
    if container is not None:
        XET.SubElement(fmt, "container").text = container
    if extension is not None:
        XET.SubElement(fmt, "extension").text = extension
    if has_priority_over is not None:
        XET.SubElement(fmt, "has_priority_over").text = has_priority_over
    return fmt


def _make_fido(monkeypatch):
    monkeypatch.setattr(Fido, "load_fido_xml", lambda self, _path: None)
    return Fido(format_files=[])


def test_container_type_detects_zip_ole_and_false(monkeypatch):
    fido = _make_fido(monkeypatch)

    zip_fmt = _format_element("fmt/999", container="zip")
    ole_fmt = _format_element("fmt/111")
    plain_fmt = _format_element("fmt/1")

    assert fido.container_type([(zip_fmt, "sig")]) == "zip"
    assert fido.container_type([(ole_fmt, "sig")]) == "ole"
    assert fido.container_type([(plain_fmt, "sig")]) is False


def test_identify_contents_dispatches_supported_types(monkeypatch):
    fido = _make_fido(monkeypatch)
    calls = {"zip": 0, "tar": 0}

    monkeypatch.setattr(fido, "walk_zip", lambda *_args, **_kwargs: calls.__setitem__("zip", calls["zip"] + 1))
    monkeypatch.setattr(fido, "walk_tar", lambda *_args, **_kwargs: calls.__setitem__("tar", calls["tar"] + 1))

    fido.identify_contents("a.zip", type="zip")
    fido.identify_contents("a.tar", type="tar")
    fido.identify_contents("a.bin", type="unknown")
    fido.identify_contents("a.bin", type=False)

    assert calls == {"zip": 1, "tar": 1}


def test_get_buffers_seekable_branches(monkeypatch):
    fido = _make_fido(monkeypatch)
    fido.bufsize = 8
    data = b"0123456789abcdefghij"

    bof_1, eof_1, _ = fido.get_buffers(io.BytesIO(data), length=12)
    assert bof_1 == data[:8]
    assert eof_1 == data[4:12]

    bof_2, eof_2, _ = fido.get_buffers(io.BytesIO(data), length=16)
    assert bof_2 == data[:8]
    assert eof_2 == data[8:16]

    bof_3, eof_3, _ = fido.get_buffers(io.BytesIO(data), length=20, seekable=True)
    assert bof_3 == data[:8]
    assert eof_3 == data[-8:]


def test_match_extensions_honors_priority_over(monkeypatch):
    fido = _make_fido(monkeypatch)
    superior = _format_element("fmt/1", extension="txt", has_priority_over="fmt/2")
    inferior = _format_element("fmt/2", extension="txt")
    fido.formats = [superior, inferior]
    fido.puid_has_priority_over_map = {
        "fmt/1": frozenset(["fmt/2"]),
        "fmt/2": frozenset(),
    }

    matches = fido.match_extensions("sample.txt")

    assert len(matches) == 1
    assert matches[0][0].find("puid").text == "fmt/1"
    assert matches[0][1] == "External"


def test_identify_file_reports_io_error(monkeypatch, capsys):
    fido = _make_fido(monkeypatch)
    monkeypatch.setattr("builtins.open", lambda *_a, **_k: (_ for _ in ()).throw(IOError("boom")))

    fido.identify_file("/does/not/exist")

    assert "FIDO: Error in identify_file" in capsys.readouterr().err


def test_identify_file_prefers_container_matches(monkeypatch, tmp_path):
    fido = _make_fido(monkeypatch)
    hits = {}
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc")
    zip_fmt = _format_element("fmt/999", container="zip")

    monkeypatch.setattr(fido, "match_formats", lambda *_a: [(zip_fmt, "sig")])
    monkeypatch.setattr(fido, "match_container", lambda *_a: [(zip_fmt, "container sig")])
    monkeypatch.setattr(fido_mod.ET, "parse", lambda _p: XET.ElementTree(XET.Element("root")))
    monkeypatch.setattr(
        fido,
        "handle_matches",
        lambda filename, matches, _duration, matchtype: hits.update(
            {"filename": filename, "matches": matches, "matchtype": matchtype}
        ),
    )

    fido.identify_file(str(sample))

    assert hits["matchtype"] == "container"
    assert hits["filename"] == str(sample)
    assert len(hits["matches"]) == 1


def test_identify_file_extension_fallback(monkeypatch, tmp_path):
    fido = _make_fido(monkeypatch)
    sample = tmp_path / "sample.txt"
    sample.write_bytes(b"abc")
    ext_fmt = _format_element("fmt/1", extension="txt")
    hits = {}

    monkeypatch.setattr(fido, "match_formats", lambda *_a: [])
    monkeypatch.setattr(fido, "match_extensions", lambda _name: [(ext_fmt, "External")])
    monkeypatch.setattr(
        fido,
        "handle_matches",
        lambda _filename, _matches, _duration, matchtype: hits.update({"matchtype": matchtype}),
    )

    fido.identify_file(str(sample), extension=True)

    assert hits["matchtype"] == "extension"


def test_identify_file_recurses_into_zip_when_enabled(monkeypatch, tmp_path):
    fido = _make_fido(monkeypatch)
    fido.zip = True
    sample = tmp_path / "sample.zip"
    sample.write_bytes(b"abc")
    zip_fmt = _format_element("fmt/999", container="zip")
    calls = {"recurse": 0}

    monkeypatch.setattr(fido, "match_formats", lambda *_a: [(zip_fmt, "sig")])
    monkeypatch.setattr(fido, "handle_matches", lambda *_a: None)
    monkeypatch.setattr(
        fido,
        "identify_contents",
        lambda _filename, type=None, extension=True: calls.__setitem__("recurse", calls["recurse"] + 1),
    )

    fido.identify_file(str(sample), extension=False)

    assert calls["recurse"] == 1


def test_identify_stream_non_windows_fallback_filename(monkeypatch):
    fido = _make_fido(monkeypatch)
    calls = {}
    monkeypatch.setattr(fido, "match_formats", lambda *_a: [])
    monkeypatch.setattr(
        fido,
        "match_extensions",
        lambda filename: calls.__setitem__("ext_filename", filename) or [],
    )
    monkeypatch.setattr(
        fido,
        "handle_matches",
        lambda filename, _matches, _duration, matchtype: calls.update(
            {"handled_filename": filename, "matchtype": matchtype}
        ),
    )
    fake_os = SimpleNamespace(
        name="posix",
        readlink=lambda _p: (_ for _ in ()).throw(OSError("no link")),
    )
    monkeypatch.setattr(fido_mod, "os", fake_os)

    fido.identify_stream(io.BytesIO(b"abc"), "provided.name", extension=True)

    assert calls["ext_filename"] == "provided.name"
    assert calls["handled_filename"] == "STDIN"
    assert calls["matchtype"] == "extension"


def test_identify_stream_windows_uses_provided_filename(monkeypatch):
    fido = _make_fido(monkeypatch)
    calls = {}
    monkeypatch.setattr(fido, "match_formats", lambda *_a: [])
    monkeypatch.setattr(
        fido,
        "match_extensions",
        lambda filename: calls.__setitem__("ext_filename", filename) or [],
    )
    monkeypatch.setattr(
        fido,
        "handle_matches",
        lambda filename, _matches, _duration, _matchtype: calls.update({"handled_filename": filename}),
    )
    fake_os = SimpleNamespace(name="nt")
    monkeypatch.setattr(fido_mod, "os", fake_os)

    fido.identify_stream(io.BytesIO(b"abc"), "provided.name", extension=True)

    assert calls["ext_filename"] == "provided.name"
    assert calls["handled_filename"] == "provided.name"


def test_walk_zip_handles_bad_zip(monkeypatch, capsys):
    fido = _make_fido(monkeypatch)
    monkeypatch.setattr(fido_mod.zipfile, "ZipFile", lambda *_a, **_k: (_ for _ in ()).throw(fido_mod.zipfile.BadZipfile()))

    fido.walk_zip("bad.zip")

    assert "FIDO: ZipError bad.zip" in capsys.readouterr().err


def test_walk_tar_handles_tar_error(monkeypatch, capsys):
    fido = _make_fido(monkeypatch)
    monkeypatch.setattr(fido_mod.tarfile, "TarFile", lambda *_a, **_k: (_ for _ in ()).throw(fido_mod.tarfile.TarError()))

    fido.walk_tar("bad.tar", None)

    assert "FIDO: Error: TarError bad.tar" in capsys.readouterr().err


def _main_args(**overrides):
    args = {
        "confdir": "/tmp",
        "pronom_only": False,
        "v": False,
        "sigs": None,
        "matchprintf": None,
        "nomatchprintf": None,
        "q": True,
        "bufsize": None,
        "container_bufsize": None,
        "zip": False,
        "nocontainer": False,
        "loadformats": None,
        "useformats": None,
        "nouseformats": None,
        "input": None,
        "files": ["-"],
        "recurse": False,
        "noextension": False,
        "filename": None,
    }
    args.update(overrides)
    return SimpleNamespace(**args)


def test_main_version_flag_exits(monkeypatch, capsys):
    monkeypatch.setattr(fido_mod, "parse_cli_args", lambda *_a: _main_args(v=True))
    monkeypatch.setattr(
        fido_mod,
        "get_local_versions",
        lambda _c: SimpleNamespace(
            pronom_signature="formats-v116.xml",
            pronom_container_signature="container-signature.xml",
            fido_extension_signature="format_extensions.xml",
        ),
    )

    with pytest.raises(SystemExit) as exc:
        fido_mod.main(["-v"])

    assert exc.value.code == 0
    assert "FIDO v" in capsys.readouterr().out


def test_main_sigs_calls_action(monkeypatch):
    calls = {}
    monkeypatch.setattr(fido_mod, "parse_cli_args", lambda *_a: _main_args(sigs="LiSt"))
    monkeypatch.setattr(
        fido_mod,
        "get_local_versions",
        lambda _c: SimpleNamespace(
            pronom_signature="formats-v116.xml",
            pronom_container_signature="container-signature.xml",
            fido_extension_signature="format_extensions.xml",
        ),
    )
    # Records the directory too: it was not passed, so every -sigs action read
    # the packaged versions.xml regardless of -confdir
    monkeypatch.setattr(
        fido_mod, "sig_file_actions", lambda value, config_dir=None: calls.__setitem__("sigs", (value, config_dir))
    )

    with pytest.raises(SystemExit) as exc:
        fido_mod.main(["-sig", "list"])

    assert exc.value.code == 0
    action, config_dir = calls["sigs"]
    assert action == "list"
    assert config_dir is not None, "-confdir must reach sig_file_actions"


def test_main_stdin_zip_raises_runtime(monkeypatch):
    class DummyFido:
        def __init__(self, **kwargs):
            self.zip = kwargs["zip"]
            self.current_file = ""

        def print_summary(self, _secs):
            return None

    monkeypatch.setattr(fido_mod, "parse_cli_args", lambda *_a: _main_args(zip=True, files=["-"]))
    monkeypatch.setattr(
        fido_mod,
        "get_local_versions",
        lambda _c: SimpleNamespace(
            pronom_signature="formats-v116.xml",
            pronom_container_signature="container-signature.xml",
            fido_extension_signature="format_extensions.xml",
        ),
    )
    monkeypatch.setattr(fido_mod, "Fido", DummyFido)

    with pytest.raises(RuntimeError):
        fido_mod.main([])


def test_print_matches_no_match_outputs_ko(monkeypatch, capsys):
    fido = _make_fido(monkeypatch)
    fido.current_filesize = 12
    fido.current_count = 1

    fido.print_matches("/tmp/file.bin", [], 0.01)

    assert "KO" in capsys.readouterr().out


def test_print_matches_with_match_outputs_ok(monkeypatch, capsys):
    fido = _make_fido(monkeypatch)
    fmt = _format_element("fmt/1", extension="txt")
    XET.SubElement(fmt, "mime").text = "text/plain"
    XET.SubElement(fmt, "version").text = "1.0"
    XET.SubElement(fmt, "alias").text = "Alias"
    fido.current_filesize = 12
    fido.current_count = 1

    fido.print_matches("/tmp/file.txt", [(fmt, "sig")], 0.01, "signature")

    output = capsys.readouterr().out
    assert "OK" in output
    assert "fmt/1" in output


def test_match_formats_covers_positions_and_exception_path(monkeypatch, capsys):
    fido = _make_fido(monkeypatch)

    def add_signature(fmt, name, pos, regex):
        sig = XET.SubElement(fmt, "signature")
        XET.SubElement(sig, "name").text = name
        pat = XET.SubElement(sig, "pattern")
        XET.SubElement(pat, "position").text = pos
        XET.SubElement(pat, "regex").text = regex

    bof_fmt = _format_element("fmt/1")
    eof_fmt = _format_element("fmt/2")
    var_fmt = _format_element("fmt/3")
    ifb_fmt = _format_element("fmt/4")
    bad_fmt = _format_element("fmt/5")

    # The BOF buffer deliberately carries its sequence away from offset zero,
    # so a matcher that searched instead of anchoring would be caught
    add_signature(bof_fmt, "bof", "BOF", "abc")
    add_signature(eof_fmt, "eof", "EOF", "xyz")
    add_signature(var_fmt, "var", "VAR", "abc")
    add_signature(ifb_fmt, "ifb", "IFB", "abc")
    add_signature(bad_fmt, "bad", "BOF", "[unclosed")

    fido.formats = [bof_fmt, eof_fmt, var_fmt, ifb_fmt, bad_fmt]
    fido.puid_has_priority_over_map = {
        "fmt/1": frozenset(),
        "fmt/2": frozenset(),
        "fmt/3": frozenset(),
        "fmt/4": frozenset(),
        "fmt/5": frozenset(),
    }

    matches = fido.match_formats(b"abc", b"xyz")
    matched_puids = {m[0].find("puid").text for m in matches}

    assert matched_puids == {"fmt/1", "fmt/2", "fmt/3", "fmt/4"}
    # The unusable pattern has to be reported against its PUID
    assert "fmt/5" in capsys.readouterr().err


def test_match_formats_anchors_bof_signatures_at_the_start(monkeypatch):
    """A BOF signature must not match its sequence at a later offset.

    Replacing re.match with re.search here would turn thousands of PRONOM
    signatures into substring searches.
    """
    fido = _make_fido(monkeypatch)
    fmt = _format_element("fmt/1")
    sig = XET.SubElement(fmt, "signature")
    XET.SubElement(sig, "name").text = "bof"
    pat = XET.SubElement(sig, "pattern")
    XET.SubElement(pat, "position").text = "BOF"
    XET.SubElement(pat, "regex").text = "abc"
    fido.formats = [fmt]
    fido.puid_has_priority_over_map = {"fmt/1": frozenset()}

    assert fido.match_formats(b"abc", b"") != []
    assert fido.match_formats(b"zzabc", b"") == []


def test_match_formats_does_not_swallow_programming_errors(monkeypatch):
    """Only an unusable regex is tolerated; a real bug must surface.

    The handler used to catch Exception, so any defect in matching silently
    removed a format from consideration and FIDO reported a wrong answer.
    """
    fido = _make_fido(monkeypatch)
    fmt = _format_element("fmt/1")
    sig = XET.SubElement(fmt, "signature")
    XET.SubElement(sig, "name").text = "bof"
    pat = XET.SubElement(sig, "pattern")
    XET.SubElement(pat, "position").text = "BOF"
    XET.SubElement(pat, "regex").text = "abc"
    fido.formats = [fmt]
    fido.puid_has_priority_over_map = {"fmt/1": frozenset()}
    monkeypatch.setattr(fido, "get_signatures", lambda _fmt: (_ for _ in ()).throw(TypeError("boom")))

    with pytest.raises(TypeError):
        fido.match_formats(b"abc", b"")


def test_match_formats_result_is_independent_of_format_order(monkeypatch):
    """Identification must not depend on the order of self.formats.

    Priority was applied while collecting as well as afterwards, so a format
    dropped during collection was missing from the set the second pass needed.
    """
    def build():
        generic = _format_element("gen/1")
        middle = _format_element("mid/1")
        specific = _format_element("spc/1")
        for fmt, name in ((generic, "gen"), (middle, "mid"), (specific, "spc")):
            sig = XET.SubElement(fmt, "signature")
            XET.SubElement(sig, "name").text = name
            pat = XET.SubElement(sig, "pattern")
            XET.SubElement(pat, "position").text = "BOF"
            XET.SubElement(pat, "regex").text = "abc"
        return generic, middle, specific

    priority = {
        "gen/1": frozenset(),
        "mid/1": frozenset(["gen/1"]),
        "spc/1": frozenset(["mid/1", "gen/1"]),
    }

    results = []
    for order in ((0, 2, 1), (0, 1, 2), (2, 1, 0)):
        fido = _make_fido(monkeypatch)
        built = build()
        fido.formats = [built[index] for index in order]
        fido.puid_has_priority_over_map = priority
        matches = fido.match_formats(b"abc", b"")
        results.append({m[0].find("puid").text for m in matches})

    assert results[0] == results[1] == results[2], results
    assert results[0] == {"spc/1"}


def test_get_buffers_non_seekable_long_stream(monkeypatch):
    fido = _make_fido(monkeypatch)
    fido.bufsize = 8
    data = b"0123456789abcdefghijABCDEFGHIJ"

    bof, eof, _ = fido.get_buffers(io.BytesIO(data), length=len(data), seekable=False)

    assert bof == data[:8]
    assert eof == data[-8:]


def test_buffered_read_overlap_and_non_overlap(monkeypatch, tmp_path):
    fido = _make_fido(monkeypatch)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"0123456789abcdefghij")
    fido.current_file = str(sample)
    fido.current_filesize = sample.stat().st_size
    fido.bufsize = 8
    fido.container_bufsize = 4

    no_overlap = fido.buffered_read(0, overlap=False)
    with_overlap = fido.buffered_read(2, overlap=True)

    assert no_overlap == b"01234567"
    assert with_overlap == b"23456789"


def test_walk_zip_recurses_for_nested_container(monkeypatch, tmp_path):
    fido = _make_fido(monkeypatch)
    sample = tmp_path / "sample.zip"
    import zipfile

    with zipfile.ZipFile(sample, "w") as zf:
        zf.writestr("inner.bin", b"abc")

    zip_fmt = _format_element("fmt/999", container="zip")
    calls = {"recurse": 0}
    monkeypatch.setattr(fido, "match_formats", lambda *_a: [(zip_fmt, "sig")])
    monkeypatch.setattr(fido, "handle_matches", lambda *_a: None)
    monkeypatch.setattr(
        fido,
        "identify_contents",
        lambda *_a, **_k: calls.__setitem__("recurse", calls["recurse"] + 1),
    )

    fido.walk_zip(str(sample), extension=False)

    assert calls["recurse"] == 1


def test_walk_tar_processes_files_and_recurses(monkeypatch):
    fido = _make_fido(monkeypatch)
    zip_fmt = _format_element("fmt/999", container="zip")
    calls = {"handled": 0, "recurse": 0}

    class DummyMember:
        def __init__(self, name, is_file=True):
            self.name = name
            self.size = 3
            self._is_file = is_file

        def isfile(self):
            return self._is_file

    class DummyTar:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def getmembers(self):
            return [DummyMember("dir", is_file=False), DummyMember("file.bin", is_file=True)]

        def extractfile(self, _item):
            return io.BytesIO(b"abc")

    monkeypatch.setattr(fido_mod.tarfile, "TarFile", DummyTar)
    monkeypatch.setattr(fido, "get_buffers", lambda *_a, **_k: (b"abc", b"abc", 3))
    monkeypatch.setattr(fido, "match_formats", lambda *_a: [(zip_fmt, "sig")])
    monkeypatch.setattr(fido, "handle_matches", lambda *_a: calls.__setitem__("handled", calls["handled"] + 1))
    monkeypatch.setattr(fido, "identify_contents", lambda *_a, **_k: calls.__setitem__("recurse", calls["recurse"] + 1))

    fido.walk_tar("archive.tar", None)

    assert calls["handled"] == 1
    assert calls["recurse"] == 1


def test_main_loadformats_and_useformats(monkeypatch, tmp_path, capsys):
    class DummyFido:
        def __init__(self, **kwargs):
            self.zip = kwargs["zip"]
            self.current_file = ""
            self.loaded = []
            self.formats = [_format_element("fmt/1"), _format_element("fmt/2")]

        def load_fido_xml(self, file):
            self.loaded.append(file)

        def identify_file(self, *_a, **_k):
            return None

        def print_summary(self, _secs):
            return None

    listed = tmp_path / "files.txt"
    listed.write_text("a.bin\n", encoding="utf-8")
    created = {}
    monkeypatch.setattr(
        fido_mod,
        "parse_cli_args",
        lambda *_a: _main_args(
            q=False,
            loadformats="extra1.xml,extra2.xml",
            useformats="fmt/1",
            input=str(listed),
            files=[],
        ),
    )
    monkeypatch.setattr(
        fido_mod,
        "get_local_versions",
        lambda _c: SimpleNamespace(
            pronom_signature="formats-v116.xml",
            pronom_container_signature="container-signature.xml",
            fido_extension_signature="format_extensions.xml",
        ),
    )
    monkeypatch.setattr(fido_mod, "list_files", lambda *_a, **_k: [])
    monkeypatch.setattr(fido_mod, "Fido", lambda **kwargs: created.setdefault("fido", DummyFido(**kwargs)))

    fido_mod.main([])

    assert created["fido"].loaded == ["extra1.xml", "extra2.xml"]
    assert len(created["fido"].formats) == 1
    assert created["fido"].formats[0].find("puid").text == "fmt/1"
    assert "FIDO v" in capsys.readouterr().err


def test_main_keyboard_interrupt_exits_with_context(monkeypatch):
    class DummyFido:
        def __init__(self, **kwargs):
            self.zip = kwargs["zip"]
            self.current_file = "STDIN"

        def identify_stream(self, *_a, **_k):
            raise KeyboardInterrupt()

        def print_summary(self, _secs):
            return None

    monkeypatch.setattr(fido_mod, "parse_cli_args", lambda *_a: _main_args(zip=False, files=["-"]))
    monkeypatch.setattr(
        fido_mod,
        "get_local_versions",
        lambda _c: SimpleNamespace(
            pronom_signature="formats-v116.xml",
            pronom_container_signature="container-signature.xml",
            fido_extension_signature="format_extensions.xml",
        ),
    )
    monkeypatch.setattr(fido_mod, "Fido", DummyFido)

    with pytest.raises(SystemExit) as exc:
        fido_mod.main([])

    assert "Interrupt while identifying file STDIN" in str(exc.value)


def test_process_format_element_replaces_a_childless_element(monkeypatch):
    """An element's truth value is its child count, which is the wrong test.

    A format element with no children was treated as absent, and the semantics
    are scheduled to change so that every element counts as present.
    """
    fido = _make_fido(monkeypatch)
    fido.formats = []
    fido.puid_format_map = {}

    first = XET.Element("format")
    XET.SubElement(first, "puid").text = "fmt/1"
    fido.process_format_element(first)

    replacement = XET.Element("format")
    XET.SubElement(replacement, "puid").text = "fmt/1"
    fido.process_format_element(replacement)

    assert fido.formats == [replacement]
    assert fido.puid_format_map["fmt/1"] is replacement


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        ('a",INJECTED,x', 'a"",INJECTED,x'),
        ("line\nbreak", "line break"),
        ("carriage\rreturn", "carriage return"),
        (None, ""),
        ("plain.txt", "plain.txt"),
    ),
)
def test_field_value_cannot_break_out_of_a_record(raw, expected):
    """A filename is attacker controlled and the templates quote without escaping."""
    assert fido_mod.field_value(raw) == expected


def test_csv_output_round_trips_an_awkward_filename(monkeypatch, capsys):
    """The emitted row must parse back to nine fields with the name intact."""
    fido = _make_fido(monkeypatch)
    fido.current_filesize = 10
    fmt = _format_element("fmt/1")
    XET.SubElement(fmt, "name").text = 'Weird "quoted" name'
    XET.SubElement(fmt, "mime").text = "application/test"

    fido.print_matches('odd",name\n.bin', [(fmt, "sig")], delta_t=0.0, matchtype="signature")

    rows = list(csv.reader(io.StringIO(capsys.readouterr().out)))
    assert len(rows) == 1
    assert len(rows[0]) == 9
    assert rows[0][6] == 'odd",name .bin'


def test_missing_mime_element_is_empty_not_the_string_none(monkeypatch, capsys):
    fido = _make_fido(monkeypatch)
    fido.current_filesize = 10
    fmt = _format_element("fmt/1")
    XET.SubElement(fmt, "name").text = "Test"

    fido.print_matches("f.bin", [(fmt, "sig")], delta_t=0.0, matchtype="signature")

    assert "None" not in capsys.readouterr().out


def test_list_files_reports_a_path_that_is_neither_file_nor_directory(capsys):
    """os.walk yields nothing for these, so a typo looked like a clean empty run."""
    assert list(fido_mod.list_files(["/does/not/exist.txt"])) == []
    assert "Not a file or directory" in capsys.readouterr().err


def test_list_files_skips_blank_lines(tmp_path, capsys):
    """A blank line normalised to "." and silently walked the working directory."""
    assert list(fido_mod.list_files(["", "\n"])) == []
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("declared", (20, 12, 10, None))
def test_eof_buffer_comes_from_the_bytes_actually_read(monkeypatch, declared):
    """A declared length that overstates the data gave an empty or short tail.

    A file can shrink between stat and read, and a zip entry's header can lie,
    and the result was that EOF signatures silently could not match.
    """
    fido = _make_fido(monkeypatch)
    fido.bufsize = 8
    data = b"0123456789"

    _bof, eof, _read = fido.get_buffers(io.BytesIO(data), declared)

    assert eof == data[-8:]


@pytest.mark.parametrize("declared", (12, 16, 20))
def test_declared_length_still_bounds_a_member_inside_a_longer_stream(monkeypatch, declared):
    """The length also bounds a container member, so it must not be read past."""
    fido = _make_fido(monkeypatch)
    fido.bufsize = 8
    data = b"0123456789abcdefghij"

    _bof, eof, _read = fido.get_buffers(io.BytesIO(data), declared)

    assert eof == data[declared - 8:declared]


def test_seekable_eof_buffer_handles_both_cases(monkeypatch):
    fido = _make_fido(monkeypatch)
    fido.bufsize = 8

    _bof, overstated, _ = fido.get_buffers(io.BytesIO(b"0123456789"), 20, seekable=True)
    assert overstated == b"23456789"

    _bof, bounded, _ = fido.get_buffers(io.BytesIO(b"0123456789abcdefghij"), 12, seekable=True)
    assert bounded == b"456789ab"


def test_refuses_a_member_whose_declared_size_is_too_large(monkeypatch, capsys):
    fido = _make_fido(monkeypatch)
    fido.max_member_size = 1024

    assert fido.refuses_member("a.zip!big.bin", 2048, 2048) is True
    assert "exceeds the limit" in capsys.readouterr().err


def test_refuses_a_member_with_an_implausible_compression_ratio(monkeypatch, capsys):
    """A decompression bomb is a small file that expands enormously."""
    fido = _make_fido(monkeypatch)
    fido.max_compression_ratio = 100

    assert fido.refuses_member("a.zip!bomb.bin", 200 * 1024 * 1024, 200 * 1024) is True
    assert "compression ratio" in capsys.readouterr().err


def test_accepts_an_ordinary_member(monkeypatch):
    fido = _make_fido(monkeypatch)

    assert fido.refuses_member("a.zip!doc.xml", 50_000, 5_000) is False
    # An uncompressed member reports no ratio at all
    assert fido.refuses_member("a.tar!doc.xml", 50_000, None) is False


def test_container_recursion_stops_at_the_depth_limit(monkeypatch, capsys):
    """An archive nested inside itself recursed without end, and each level
    held its own spooled copy in memory."""
    fido = _make_fido(monkeypatch)
    fido.max_recursion_depth = 3
    calls = []
    monkeypatch.setattr(fido, "walk_zip", lambda *a, **kw: calls.append(kw.get("depth")))

    fido.identify_contents("a.zip", type="zip", depth=2)
    assert calls == [2]

    fido.identify_contents("a.zip", type="zip", depth=3)
    assert calls == [2]
    assert "Maximum container depth" in capsys.readouterr().err
