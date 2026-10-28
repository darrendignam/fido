#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
FIDO CSV output to XML.

Author: Maurice de Rooij <maurice.de.rooij@nationaalarchief.nl>, September 2011

Usage in combination with FIDO:
- Windows: python fido.py [ARGS] | python toxml.py > output.xml
- Linux: fido.py [ARGS] | toxml.py > output.xml

Usage afterwards:
- Windows: type output.csv | toxml.py > output.xml
- Linux: cat output.csv | toxml.py > output.xml

For difference in usage, see:
- http://bugs.python.org/issue9390
- http://support.microsoft.com/default.aspx?kbid=321788
"""

import csv
import re
import sys
from xml.sax.saxutils import escape as xml_escape

from fido.pronom.versions import get_local_versions

from . import __version__

# A FIDO CSV row carries nine fields
FIELD_COUNT = 9

# Characters XML 1.0 cannot carry at all, even escaped
_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def escape(value):
    """Return @param value safe to place in element content.

    Filenames reach here unmodified, and one containing an ampersand produced a
    document no XML parser would read, while one containing a tag could forge
    entries in the report.
    """
    return xml_escape(_FORBIDDEN.sub("", str(value)))


def main():
    """Generate XML as read from CSV and send it to the standard output stream."""
    # The declared encoding has to be the one actually written, and stdout
    # defaults to the platform encoding, which is not UTF-8 on Windows
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8")

    sys.stdout.write(
        """<?xml version="1.0" encoding="utf-8"?>
<fido_output>
    <versions>
        <fido_version>{0}</fido_version>
        <signature_version>{1}</signature_version>
    </versions>""".format(escape(__version__), escape(get_local_versions().pronom_version))
    )

    try:
        for line_number, row in enumerate(csv.reader(sys.stdin), start=1):
            if not row:
                continue
            if len(row) < FIELD_COUNT:
                sys.stderr.write(
                    "fido-toxml: skipping line {0}: expected {1} fields, got {2}\n".format(
                        line_number, FIELD_COUNT, len(row)
                    )
                )
                continue
            sys.stdout.write(file_element(row))
    finally:
        # Emitted from finally so an interrupted run still closes the document
        sys.stdout.write("\n</fido_output>\n")


def file_element(row):
    """Return the <file> element for one FIDO CSV @param row."""
    return """
    <file>
        <filename>{0}</filename>
        <status>{1}</status>
        <matchtype>{2}</matchtype>
        <time>{3}</time>
        <puid>{4}</puid>
        <mimetype>{5}</mimetype>
        <formatname>{6}</formatname>
        <signaturename>{7}</signaturename>
        <filesize>{8}</filesize>
    </file>""".format(
        escape(row[6]),
        escape(row[0]),
        escape(row[8]),
        escape(row[1]),
        escape(row[2]),
        escape(row[7]),
        escape(row[3]),
        escape(row[4]),
        escape(row[5]),
    )


if __name__ == "__main__":
    main()
