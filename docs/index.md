---
layout: page
title: FIDO Home
---
Format Identification for Digital Objects
-----------------------------------------

FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.

FIDO uses the UK National Archives (TNA) PRONOM File Format and Container
descriptions. PRONOM is available from
<https://www.nationalarchives.gov.uk/pronom/>.

Install
-------

    pip install opf-fido

Then identify a file, a directory, or standard input:

    fido somefile.pdf
    fido -recurse somedirectory
    cat somefile.pdf | fido -

Documentation
-------------

The usage guide, the full list of command line options, the output format and
the signature update process are all documented in the project README, which is
kept with the code so that it cannot drift from the tool it describes:

* [README](https://github.com/openpreserve/fido/blob/main/README.md)
* [Release notes](https://github.com/openpreserve/fido/blob/main/RELEASENOTES.md)
* [Contributing](https://github.com/openpreserve/fido/blob/main/CONTRIBUTING.md)
* [Automating a release](https://github.com/openpreserve/fido/blob/main/docs/releasing.md)

Source and releases
-------------------

* Source: <https://github.com/openpreserve/fido>
* Releases: <https://github.com/openpreserve/fido/releases>
* Issues: <https://github.com/openpreserve/fido/issues>

By the [Open Preservation Foundation](https://www.openpreservation.org).
