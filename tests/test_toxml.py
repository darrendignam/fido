import io
import xml.etree.ElementTree as ET
from types import SimpleNamespace

from fido import toxml


def test_toxml_main_renders_single_row(monkeypatch, capsys):
    monkeypatch.setattr(toxml, "get_local_versions", lambda: SimpleNamespace(pronom_version="999"))
    monkeypatch.setattr(
        toxml.sys,
        "stdin",
        io.StringIO('OK,0,fmt/1000,"Sample Format","Sample Sig",9,sample.bin,application/test,byte\n'),
    )

    toxml.main()

    output = capsys.readouterr().out
    assert "<fido_output>" in output
    assert "<signature_version>999</signature_version>" in output
    assert "<filename>sample.bin</filename>" in output
    assert "<puid>fmt/1000</puid>" in output
    assert "<filesize>9</filesize>" in output
    assert output.strip().endswith("</fido_output>")


def test_toxml_main_renders_multiple_rows(monkeypatch, capsys):
    monkeypatch.setattr(toxml, "get_local_versions", lambda: SimpleNamespace(pronom_version="116"))
    monkeypatch.setattr(
        toxml.sys,
        "stdin",
        io.StringIO(
            "OK,1,fmt/1,Format A,Sig A,4,a.bin,text/plain,byte\n"
            "KO,2,,Unknown,,8,b.bin,,extension\n"
        ),
    )

    toxml.main()

    output = capsys.readouterr().out
    assert output.count("<file>") == 2
    assert "<filename>a.bin</filename>" in output
    assert "<filename>b.bin</filename>" in output
    assert "<status>KO</status>" in output


def _row(filename):
    return "OK,12,fmt/1,Format & Name,Sig<name>,100,{},text/plain,signature".format(filename)


def test_output_is_well_formed_for_awkward_values(monkeypatch, capsys):
    """Fields were interpolated raw, so an ampersand produced unparseable XML."""
    monkeypatch.setattr(toxml.sys, "stdin", io.StringIO(_row('a<tag>b & c"d') + "\n"))
    monkeypatch.setattr(toxml, "get_local_versions", lambda: SimpleNamespace(pronom_version="116"))

    toxml.main()

    tree = ET.fromstring(capsys.readouterr().out)
    assert tree.find("file/filename").text == 'a<tag>b & c"d'
    assert tree.find("file/formatname").text == "Format & Name"
    assert tree.find("file/signaturename").text == "Sig<name>"


def test_a_filename_cannot_forge_elements(monkeypatch, capsys):
    """An unescaped filename could inject a different puid into the report."""
    hostile = "x</filename><puid>fmt/SPOOFED</puid><filename>y"
    monkeypatch.setattr(toxml.sys, "stdin", io.StringIO(_row(hostile) + "\n"))
    monkeypatch.setattr(toxml, "get_local_versions", lambda: SimpleNamespace(pronom_version="116"))

    toxml.main()

    tree = ET.fromstring(capsys.readouterr().out)
    assert [element.text for element in tree.iter("puid")] == ["fmt/1"]
    assert tree.find("file/filename").text == hostile


def test_short_and_blank_rows_are_skipped_and_the_document_closes(monkeypatch, capsys):
    """row[8] raised IndexError, leaving a truncated document with no closing tag."""
    monkeypatch.setattr(toxml.sys, "stdin", io.StringIO("OK,0,fmt/1\n\n" + _row("good.bin") + "\n"))
    monkeypatch.setattr(toxml, "get_local_versions", lambda: SimpleNamespace(pronom_version="116"))

    toxml.main()

    captured = capsys.readouterr()
    tree = ET.fromstring(captured.out)
    assert [element.text for element in tree.iter("filename")] == ["good.bin"]
    assert "expected 9 fields" in captured.err


def test_control_characters_are_removed(monkeypatch, capsys):
    """XML 1.0 cannot carry these even escaped."""
    monkeypatch.setattr(toxml.sys, "stdin", io.StringIO(_row("bad\x0bname") + "\n"))
    monkeypatch.setattr(toxml, "get_local_versions", lambda: SimpleNamespace(pronom_version="116"))

    toxml.main()

    tree = ET.fromstring(capsys.readouterr().out)
    assert tree.find("file/filename").text == "badname"
