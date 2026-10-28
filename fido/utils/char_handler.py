#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Character handling routines for Format Identification for Digital Objects (FIDO)."""

# \a\b\n\r\t\v
# MdR: took out '<' and '>' out of _ordinary because they were converted to entities &lt;&gt;
# MdR: moved '!' from _ordinary to _special because it means "NOT" in the regex
# world. At this time no regex in any sig has a negate set, did this to be on
# the safe side
ORDINARY = frozenset(
    " \"#%&',-/0123456789:;=@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
)
SPECIAL = "$()*+.?![]^\\{|}"  # Before: '$*+.?![]^\\{|}'


def escape_char(c):
    """Add appropriate escape sequence to passed character c."""
    if c == "\n":
        return "\\n"
    if c == "\r":
        return "\\r"
    if c in SPECIAL:
        return "\\" + c
    code_point = ord(c)
    if code_point < 256:
        return "\\x{:02x}".format(code_point)
    # A literal above U+00FF has no single-byte escape. Emitting its UTF-8
    # bytes keeps the pattern matching what a UTF-8 source file holds, where
    # indexing a 16 character table used to raise IndexError.
    return "".join("\\x{:02x}".format(byte) for byte in c.encode("utf-8"))


def escape(string):
    """Escape characters in pattern that are non-printable, non-ascii, or special for regexes."""
    return "".join(c if c in ORDINARY else escape_char(c) for c in string)
