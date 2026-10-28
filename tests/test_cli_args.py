import pytest

from fido.cli_args import parse_cli_args
from fido.fido import defaults

# Common argument string


def test_parse_args_input_valid():
    arg_string = (
        "-v -q -recurse -zip -noextension -nocontainer -pronom_only "
        "-input files.txt "
        "-useformats=fmt1,fmt2 -nouseformats=fmt3,fmt4"
    )
    args = parse_cli_args(arg_string.split(), defaults)
    assert args.v
    assert args.q
    assert args.recurse
    assert args.zip
    assert args.noextension
    assert args.nocontainer
    assert args.pronom_only
    assert args.input == "files.txt"
    assert args.useformats == "fmt1,fmt2"
    assert args.nouseformats == "fmt3,fmt4"


def test_parse_args_files_valid():
    arg_string = "-q -zip file1.ext file2.ext"
    args = parse_cli_args(arg_string.split(), defaults)
    assert args.q
    assert args.zip
    assert not args.noextension
    assert not args.nocontainer
    assert not args.pronom_only
    assert args.files == ["file1.ext", "file2.ext"]
    assert args.useformats is None
    assert args.nouseformats is None


def test_parse_args_invalid():
    arg_string = "-q -zip -bad_arg file1.ext file2.ext"
    with pytest.raises(SystemExit):
        parse_cli_args(arg_string.split(), defaults)


def test_parse_files_and_input_invalid():
    arg_string = "-q -zip -input files.txt file1.ext file2.ext"
    with pytest.raises(SystemExit):
        parse_cli_args(arg_string.split(), defaults)


@pytest.mark.parametrize("value", ("0", "-1", "512", "abc", ""))
def test_buffer_sizes_below_the_floor_are_rejected(value):
    """A zero or negative buffer silently misidentified every file.

    -bufsize 0 reported a PDF as Rich Text Format, with matchtype signature.
    """
    with pytest.raises(SystemExit):
        parse_cli_args(["-bufsize", value, "file.bin"], defaults)


@pytest.mark.parametrize("argument", ("-bufsize", "-container_bufsize"))
def test_buffer_sizes_above_the_floor_are_accepted(argument):
    args = parse_cli_args([argument, "4096", "file.bin"], defaults)

    assert getattr(args, argument.lstrip("-")) == 4096
