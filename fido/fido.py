#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Format Identification for Digital Objects (FIDO).

FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.
"""

import os
import re
import sys
import tarfile
import tempfile
import zipfile
from contextlib import closing
from typing import Optional

from defusedxml import ElementTree as ET

from fido import CONFIG_DIR, __version__
from fido.cli_args import parse_cli_args
from fido.package import OlePackage, ZipPackage
from fido.pronom.versions import get_local_versions, sig_file_actions
from fido.utils.char_handler import escape
from fido.utils.timer import PerfTimer

defaults = {
    "config_dir": CONFIG_DIR,
    "bufsize": 128 * 1024,  # (bytes)
    "regexcachesize": 2084,  # (bytes)
    "printmatch": 'OK,%(info.time)s,%(info.puid)s,"%(info.formatname)s","%(info.signaturename)s",%(info.filesize)s,"%(info.filename)s","%(info.mimetype)s","%(info.matchtype)s"\n',
    "printnomatch": 'KO,%(info.time)s,,,,%(info.filesize)s,"%(info.filename)s",,"%(info.matchtype)s"\n',
    "format_files": ["formats-v116.xml", "format_extensions.xml"],
    "containersignature_file": "container-signature-20231127.xml",
    "container_bufsize": 512 * 1024,  # (bytes)
    "description": """Format Identification for Digital Objects (fido).
FIDO is a command-line tool to identify the file formats of digital objects.
It is designed for simple integration into automated work-flows.""",
    "epilog": """
Open Preservation Foundation (http://www.openpreservation.org)
See License.txt for license information.
Download from: https://github.com/openpreserve/fido/releases
Usage guide: http://wiki.opf-labs.org/display/KB/FIDO+usage+guide
Author: Adam Farquhar (BL), 2010
Maintainer: Maurice de Rooij (OPF/NANETH), 2011, 2012, 2013
FIDO uses the UK National Archives (TNA) PRONOM File Format
and Container descriptions.
PRONOM is available from http://www.nationalarchives.gov.uk/pronom/""",
}


class Fido:
    """Main FIDO application class."""

    def __init__(
        self,
        quiet: bool = False,
        bufsize: Optional[int] = None,
        container_bufsize=None,
        printnomatch=None,
        printmatch=None,
        zip=False,
        nocontainer=False,
        handle_matches=None,
        conf_dir=CONFIG_DIR,
        format_files=None,
        containersignature_file=None,
    ):
        """Initialise a FIDO class instance."""
        global defaults
        self.quiet = quiet
        self.bufsize = defaults["bufsize"] if bufsize is None else bufsize
        self.container_bufsize = defaults["container_bufsize"] if container_bufsize is None else container_bufsize
        self.printmatch = defaults["printmatch"] if printmatch is None else printmatch
        self.printnomatch = defaults["printnomatch"] if printnomatch is None else printnomatch
        self.handle_matches = self.print_matches if handle_matches is None else handle_matches
        self.zip = zip
        self.nocontainer = nocontainer
        self.conf_dir = conf_dir
        self.format_files = defaults["format_files"] if format_files is None else format_files
        self.containersignature_file = defaults["containersignature_file"]
        self.formats = []
        self.puid_format_map = {}
        self.puid_has_priority_over_map = {}
        # load signatures
        for xml_file in self.format_files:
            self.load_fido_xml(os.path.join(os.path.abspath(self.conf_dir), xml_file))
        self.current_file = ""
        self.current_filesize = 0
        self.current_format = None
        self.current_sig = None
        self.current_pat = None
        self.current_count = 0  # Count of calls to match_formats
        re._MAXCACHE = defaults["regexcachesize"]
        self.externalsig = ET.XML("<signature><name>External</name></signature>")

    def convert_container_sequence(self, sig):
        """Parse the PRONOM container sequences and convert to regular expressions."""
        # The sequence is regex matching bytes from a file so the sequence must also be bytes
        seq = b"(?s)"
        inq = False
        byt = False
        rng = False
        ror = False
        for i in range(len(sig)):
            if not inq and not rng:
                if sig[i] == "'":
                    inq = True
                    continue
                if sig[i] == " " or sig[i] == "\n":
                    continue
                if sig[i] == "[":
                    seq += b"("
                    rng = True
                    continue
                if not byt:
                    seq += b"\\x" + sig[i].lower().encode("utf8")
                    byt = True
                    continue
                if byt:
                    seq += sig[i].lower().encode("utf8")
                    byt = False
                    continue
            if inq:
                if sig[i] == "'" and not rng:
                    inq = False
                    continue
                seq += escape(sig[i]).encode("utf8")
                continue
            if rng:
                if sig[i] == "]":
                    seq += b")"
                    rng = False
                    continue
                if sig[i] != "-" and sig[i] != "'" and ror:
                    seq += escape(sig[i]).encode("utf8")
                    continue
                if sig[i] != "-" and sig[i] != "'" and sig[i] != " " and sig[i] != ":" and not ror and not byt:
                    seq += b"\\x" + sig[i].lower().encode("utf8")
                    byt = True
                    continue
                if sig[i] != "-" and sig[i] != "'" and sig[i] != " " and not ror and byt:
                    seq += sig[i].lower().encode("utf8")
                    byt = False
                    continue
                if sig[i] == "-" or sig[i] == " ":
                    seq += b"|"
                    continue
                if sig[i] == "'" and not ror:
                    ror = True
                    continue
                if sig[i] == "'" and ror:
                    ror = False
                    continue

        return seq

    def extract_signatures(self, doc, signature_type="ZIP"):
        """
        Given an XML container signature file, return the signatures by PUID.

        The format of the returned dictionary is:

        {
            puid: [
                {
                    "id": container_signature_id,
                    "files": [
                        {"path": path_inside_container, "sequences": [sequence, ...]},
                        ...
                    ],
                },
                ...
            ]
        }

        A PUID matches when any one of its signatures matches, and a signature
        matches only when every file it names is present and every sequence in
        each of those files is found. Previously only the first file and its
        first sequence were kept, so a signature that distinguishes versions by
        a second file matched every version at once.
        """
        root = doc.getroot()
        format_mappings = root.find("FileFormatMappings")

        def get_puid(element_id):
            mapping = format_mappings.find('FileFormatMapping[@signatureId="{}"]'.format(element_id))
            return None if mapping is None else mapping.attrib["Puid"]

        def file_requirement(file_element):
            sequences = []
            for sub_sequence in file_element.iterfind(
                "BinarySignatures/InternalSignatureCollection/InternalSignature/ByteSequence/SubSequence"
            ):
                sequence = self.convert_container_sequence(sub_sequence.findtext("Sequence"))
                if sequence is None:
                    continue
                max_offset = sub_sequence.attrib.get("SubSeqMaxOffset")
                sequences.append(
                    {
                        "sequence": sequence,
                        # Only a first subsequence counted from the start of the
                        # file has a meaningful maximum offset
                        "max_offset": (
                            int(max_offset)
                            if max_offset is not None and sub_sequence.attrib.get("Position") == "1"
                            else None
                        ),
                    }
                )
            return {"path": file_element.findtext("Path"), "sequences": sequences}

        signatures = {}
        for element in root.iterfind(
            'ContainerSignatures/ContainerSignature[@ContainerType="{}"]'.format(signature_type)
        ):
            puid = get_puid(element.attrib["Id"])
            if puid is None:
                continue
            files = [
                requirement
                for requirement in (file_element for file_element in element.iterfind("Files/File"))
                if requirement.find("BinarySignatures") is not None
            ]
            requirements = [file_requirement(file_element) for file_element in files]
            # A requirement with no usable sequence cannot be tested, so a
            # signature carrying one would match on its remaining files alone
            if not requirements or any(not item["sequences"] or not item["path"] for item in requirements):
                continue
            signatures.setdefault(puid, []).append({"id": element.attrib["Id"], "files": requirements})
        return signatures

    def match_container(self, signature_type, klass, file, signature_file):
        """Return the signature matches for a container."""
        package = klass(
            file,
            self.extract_signatures(signature_file, signature_type=signature_type),
            max_read=self.container_bufsize,
        )
        puids = package.detect_formats()
        results = []
        for puid in puids:
            format = self.puid_format_map.get(puid)
            if format is None:
                # Reachable whenever the container signature file is newer than
                # the format file, for instance after a partial -sigs update
                sys.stderr.write("FIDO: container signature names unknown PUID {}\n".format(puid))
                continue
            results.append((format, format.findtext("name")))
        # Container matches skipped priority resolution, unlike the signature
        # and extension paths, so a file was reported as several mutually
        # exclusive formats at once
        results = [match for match in results if self.as_good_as_any(match[0], results)]
        return results

    def load_fido_xml(self, file):
        """
        Load the fido format information from @param file.

        As a side-effect, set self.formats.
        @return list of ElementTree.Element, one for each format.
        """
        try:
            tree = ET.parse(file)
            for element in tree.getroot().findall("./format"):
                self.process_format_element(element)
        except ET.ParseError as parse_excep:
            sys.stderr.write("Failed to parse signature file {}, exception: {}\n".format(file, parse_excep))
            sys.exit(1)
        return self.formats

    def process_format_element(self, element):
        """Process an individual sig file XML element."""
        # TODO: Handle empty regexes properly; perhaps remove from the format list
        puid = self.get_puid(element)
        # Handle over-writes in multiple file loads
        existing = self.puid_format_map.get(puid)
        if existing is not None:
            # Already have one, so replace old with new!
            self.formats[self.formats.index(existing)] = element
        else:
            self.formats.append(element)
        self.puid_format_map[puid] = element
        # Build some structures to speed things up
        self.puid_has_priority_over_map[puid] = frozenset(
            [puid_element.text for puid_element in element.findall("has_priority_over")]
        )

    # To delete a format: (1) remove from self.formats, (2) remove from puid_format_map, (3) remove from selt.puid_has_priority_over_map
    def get_signatures(self, format):
        """Return the signatures for the format element."""
        return format.findall("signature")

    def has_priority_over(self, format, possibly_inferior):
        """Return true if format has priority over possibly inferior."""
        return self.get_puid(possibly_inferior) in self.puid_has_priority_over_map[self.get_puid(format)]

    def get_puid(self, format):
        """Return the PUID for the format."""
        return format.find("puid").text

    def get_patterns(self, signature):
        """Return the patterns for a signature."""
        return signature.findall("pattern")

    def get_pos(self, pat):
        """Return the position from a pattern."""
        return pat.find("position").text

    def get_regex(self, pat):
        """Return the UTF-8 encoded regex from a pattern."""
        # The regex is matching bytes from a file so regex must also be bytes
        return pat.find("regex").text.encode("utf8")

    def get_extension(self, format):
        """Return the extension for a format."""
        return format.find("extension").text

    def print_matches(self, fullname, matches, delta_t, matchtype=""):
        """
        The default match handler. Prints out information for each match in the list.

        @param fullname is name of the file being matched
        @param matches is a list of (format, signature)
        @param delta_t is the time taken for the match.
        @param matchtype is the type of match (signature, containersignature, extension, fail)
        """

        class Info:
            pass

        obj = Info()
        obj.count = self.current_count
        obj.group_size = len(matches)
        obj.filename = field_value(fullname)
        obj.time = int(delta_t * 1000)
        obj.filesize = self.current_filesize
        obj.matchtype = matchtype
        if len(matches) == 0:
            sys.stdout.write(
                self.printnomatch
                % {
                    "info.time": obj.time,
                    "info.filesize": obj.filesize,
                    "info.filename": obj.filename,
                    "info.count": obj.count,
                    "info.matchtype": "fail",
                }
            )
            return
        i = 0
        for f, sig_name in matches:
            i += 1
            obj.group_index = i
            obj.puid = self.get_puid(f)
            obj.formatname = field_value(f.find("name").text)
            obj.signaturename = field_value(sig_name)
            mime = f.find("mime")
            # An absent element used to print the literal string "None"
            obj.mimetype = field_value(mime.text) if mime is not None else ""
            version = f.find("version")
            obj.version = version.text if version is not None else None
            alias = f.find("alias")
            obj.alias = alias.text if alias is not None else None
            apple_uti = f.find("apple_uid")
            obj.apple_uti = apple_uti.text if apple_uti is not None else None
            sys.stdout.write(
                self.printmatch
                % {
                    "info.time": obj.time,
                    "info.puid": obj.puid,
                    "info.formatname": obj.formatname,
                    "info.signaturename": obj.signaturename,
                    "info.filesize": obj.filesize,
                    "info.filename": obj.filename,
                    "info.mimetype": obj.mimetype,
                    "info.matchtype": obj.matchtype,
                    "info.version": obj.version,
                    "info.alias": obj.alias,
                    "info.apple_uti": obj.apple_uti,
                    "info.group_size": obj.group_size,
                    "info.group_index": obj.group_index,
                    "info.count": obj.count,
                }
            )

    def print_summary(self, secs):
        """Print summary information on the number of matches and time taken."""
        count = self.current_count
        if not self.quiet:
            rate = int(round(count / secs)) if secs != 0 else 9999
            # print >> sys.stderr, 'FIDO: Processed %6d files in %6.2f msec, %2d files/sec' %  (count, secs * 1000, rate)
            sys.stderr.write("FIDO: Processed %6d files in %6.2f msec, %2d files/sec\n" % (count, secs * 1000, rate))

    def identify_file(self, filename, extension=True):
        """
        Identify the type of @param filename.

        Call self.handle_matches instead of returning a value.
        """
        self.current_file = filename
        self.matchtype = "signature"
        try:
            timer = PerfTimer()
            f = open(filename, "rb")
            size = os.stat(filename)[6]
            self.current_filesize = size
            if self.current_filesize == 0:
                sys.stderr.write("FIDO: Zero byte file (empty): Path is: " + filename + "\n")
            bofbuffer, eofbuffer, _ = self.get_buffers(f, size, seekable=True)
            matches = self.match_formats(bofbuffer, eofbuffer)
            container_type = self.container_type(matches)
            if not self.nocontainer and container_type in ("zip", "ole"):
                container_file = ET.parse(os.path.join(os.path.abspath(self.conf_dir), self.containersignature_file))
                if container_type == "zip":
                    container_matches = self.match_container("ZIP", ZipPackage, filename, container_file)
                else:
                    container_matches = self.match_container("OLE2", OlePackage, filename, container_file)
                if len(container_matches) > 0:
                    self.handle_matches(filename, container_matches, timer.duration(), "container")
                    return
            # from here is also repeated in walk_zip
            # we should make this uniform in a next version!
            #
            # filesize is made conditional because files with 0 bytes
            # are falsely characterised being 'rtf' (due to wacky sig)
            # in these cases we try to match the extension instead
            if len(matches) > 0 and self.current_filesize > 0:
                self.handle_matches(filename, matches, timer.duration(), self.matchtype)
            elif extension and (len(matches) == 0 or self.current_filesize == 0):
                matches = self.match_extensions(filename)
                self.handle_matches(filename, matches, timer.duration(), "extension")
            else:
                # Without this a file scanned with -noextension, or a zero byte
                # file, produced no row at all, so counting output rows did not
                # tell you how many files were examined
                self.handle_matches(filename, [], timer.duration(), "fail")
            # only recurse into certain containers, like ZIP or TAR
            container = self.container_type(matches)
            # till here matey!
            if self.zip and self.can_recurse_into_container(container):
                self.identify_contents(filename, type=container, extension=extension)
        except IOError as io_excep:
            # print >> sys.stderr, "FIDO: Error in identify_file: Path is {0}".format(filename)
            sys.stderr.write("FIDO: Error in identify_file: {}, exception: {}\n".format(filename, io_excep))

    def identify_contents(self, filename, fileobj=None, type=False, extension=True):
        """
        Identify each item in a container (such as a zip or tar file).

        Call self.handle_matches on each item.
        @param fileobj could be a file, or a stream.
        """
        if not type:
            return
        if type == "zip":
            self.walk_zip(filename, fileobj, extension=extension)
        elif type == "tar":
            self.walk_tar(filename, fileobj, extension=extension)
        else:  # TODO: ouch!
            # TODO: Ouch indeed, this currently causes Fido to crash.
            # propose that this should be report and return or similar
            # the consequence is that fido fails to recurse containers that aren't
            # zip or tar, that's acceptable behaviour particularly  if clearly documented.
            # Was previously:
            #
            # raise RuntimeError("Unknown container type: " + repr(type))
            #
            # carl@openpreservation.org 10/10/2019
            return

    def identify_multi_object_stream(self, stream, extension=True):
        """
        Method does not work.

        Stream may contain one or more objects each with an HTTP style header
        that must include content-length. The headers consist of keyword:value
        pairs terminated by a newline. There must be a newline following the
        headers.
        """
        offset = 0
        while True:
            timer = PerfTimer()
            content_length = -1
            for line in stream:
                offset += len(line)
                if line == "\n":
                    if content_length < 0:
                        raise EnvironmentError("No content-length provided.")
                    else:
                        break
                pair = line.lower().split(":", 2)
                if pair[0] == "content-length":
                    content_length = int(pair[1])
            if content_length == -1:
                return
            # Consume exactly content-length bytes
            self.current_file = "STDIN!(at " + str(offset) + " bytes)"
            self.current_filesize = content_length
            bofbuffer, eofbuffer, _ = self.get_buffers(stream, content_length)
            matches = self.match_formats(bofbuffer, eofbuffer)
            # MdR: this needs attention
            if len(matches) > 0:
                self.handle_matches(self.current_file, matches, timer.duration(), "signature")
            elif extension and (len(matches) == 0 or self.current_filesize == 0):
                matches = self.match_extensions(self.current_file)
                self.handle_matches(self.current_file, matches, timer.duration(), "extension")

    def identify_stream(self, stream, filename, extension=True):
        """
        Identify the type of @param stream.

        Call self.handle_matches instead of returning a value.
        Does not close stream.
        """
        timer = PerfTimer()
        bofbuffer, eofbuffer, bytes_read = self.get_buffers(stream, length=None)
        self.current_filesize = bytes_read
        self.current_file = "STDIN"
        matches = self.match_formats(bofbuffer, eofbuffer)
        # MdR: this needs attention
        if len(matches) > 0:
            self.handle_matches(self.current_file, matches, timer.duration(), "signature")
        elif extension and (len(matches) == 0 or self.current_filesize == 0):
            # we can only determine the filename from the STDIN stream
            # on Linux, on Windows there is not a (simple) way to do that
            if os.name != "nt":
                try:
                    self.current_file = os.readlink("/proc/self/fd/0")
                except OSError:
                    if filename is not None:
                        self.current_file = filename
                    else:
                        self.current_file = "STDIN"
            else:
                if filename is not None:
                    self.current_file = filename
            matches = self.match_extensions(self.current_file)
            # we have to reset self.current_file if not on Windows
            if os.name != "nt":
                self.current_file = "STDIN"
            self.handle_matches(self.current_file, matches, timer.duration(), "extension")

    def container_type(self, matches):
        """
        Return true if this is a container type.

        Determine if one of the @param matches is the format of a container
        that we can look inside of (e.g., zip, tar).
        @return False, zip, or tar.
        """
        for format_, _ in matches:
            container = format_.find("container")
            if container is not None:
                return container.text

            # aside from checking <container> elements,
            # check for fmt/111, which is OLE
            puid = format_.find("puid")
            if puid is not None and puid.text == "fmt/111":
                return "ole"
        return False

    def can_recurse_into_container(self, container_type):
        """
        Return true if it is possible to recursively process this container.

        Determine if the passed container type can:
        a) be extracted, and
        b) contain individual files which can be identified separately.

        This function is useful for filtering out containers such as OLE,
        which are usually most interesting as compound objects rather than
        for their contents.
        """
        return container_type in ("zip", "tar")

    # This is updated following PR #191: FIX: Develop out FIDO tests with pytest
    # It should fix a problem that streams (not files) would hang.
    # Needs thorough testing, though.
    def blocking_read(self, file, bytes_to_read):
        """Perform a blocking read and return the buffer."""
        bytes_read = 0
        buffer = b""
        while bytes_read < bytes_to_read:
            readbuffer = file.read(bytes_to_read - bytes_read)
            last_read_len = len(readbuffer)
            buffer += readbuffer
            bytes_read += last_read_len
            # break out if EOF is reached, that is zero bytes read.
            if last_read_len < 1:
                break
        return buffer

    def get_buffers(self, stream, length=None, seekable=False):
        """
        Return buffers from the beginning and end of stream.

        Includes number of bytes read if there may be more bytes in the stream.

        If length is None, return the length as found.
        If seekable is False, the steam does not support a seek operation.
        """
        bytes_to_read = self.bufsize if length is None else min(length, self.bufsize)
        bofbuffer = self.blocking_read(stream, bytes_to_read)
        bytes_read = len(bofbuffer)

        if length is not None and seekable and bytes_read == bytes_to_read:
            stream.seek(0, os.SEEK_END)
            # Never read past the declared length, which bounds a member inside
            # a larger stream, but do not trust it to be reached either: a file
            # can shrink between stat and read, and a zip header can lie
            end_of_data = min(length, stream.tell())
            stream.seek(max(0, end_of_data - self.bufsize))
            eofbuffer = self.blocking_read(stream, self.bufsize)
            return bofbuffer, eofbuffer, bytes_read

        # Roll a window forward to the end of the data, stopping at the declared
        # length when there is one. Correct whether or not that length is
        # reached, where the old skip arithmetic produced an empty or truncated
        # tail and EOF signatures then silently could not match.
        remaining = None if length is None else max(0, length - bytes_read)
        prevbuffer = bofbuffer
        while True:
            if remaining == 0:
                eofbuffer = prevbuffer[-self.bufsize:]
                break
            chunk = self.bufsize if remaining is None else min(self.bufsize, remaining)
            buffer = self.blocking_read(stream, chunk)
            bytes_read += len(buffer)
            if remaining is not None:
                remaining -= len(buffer)
            if len(buffer) == self.bufsize:
                prevbuffer = buffer
            else:
                if len(buffer) == 0:
                    eofbuffer = prevbuffer[-self.bufsize:]
                else:
                    eofbuffer = (prevbuffer + buffer)[-self.bufsize:]
                break
        return bofbuffer, eofbuffer, bytes_read

        # Not seekable, so roll a window forward to the real end of the stream.
        # This is correct whether or not a length was declared, where the
        # length-driven skip arithmetic silently produced the wrong tail.
        prevbuffer = bofbuffer
        while True:
            buffer = self.blocking_read(stream, self.bufsize)
            bytes_read += len(buffer)
            if len(buffer) == self.bufsize:
                prevbuffer = buffer
            else:
                if len(buffer) == 0:
                    eofbuffer = prevbuffer
                else:
                    eofbuffer = prevbuffer[-(self.bufsize - len(buffer)):] + buffer
                break
        return bofbuffer, eofbuffer, bytes_read

    def walk_zip(self, filename, fileobj=None, extension=True):
        """
        Identify the type of each item in the zip.

        @param fileobj.  If fileobj is not provided, open.
        @param filename.
        Call self.handle_matches instead of returning a value.
        """
        try:
            with zipfile.ZipFile((fileobj if fileobj else filename), "r") as zipstream:
                for item in zipstream.infolist():
                    if item.is_dir():
                        continue
                    timer = PerfTimer()
                    with zipstream.open(item) as f:
                        item_name = filename + "!" + item.filename
                        self.current_file = item_name
                        self.current_filesize = item.file_size
                        if self.current_filesize == 0:
                            sys.stderr.write("FIDO: Zero byte file (empty): Path is: " + item_name + "\n")
                        bofbuffer, eofbuffer, _ = self.get_buffers(f, item.file_size)
                    matches = self.match_formats(bofbuffer, eofbuffer)
                    if len(matches) > 0 and self.current_filesize > 0:
                        self.handle_matches(item_name, matches, timer.duration(), "signature")
                    elif extension and (len(matches) == 0 or self.current_filesize == 0):
                        matches = self.match_extensions(item_name)
                        self.handle_matches(item_name, matches, timer.duration(), "extension")
                    else:
                        self.handle_matches(item_name, [], timer.duration(), "fail")
                    if self.container_type(matches):
                        # max_size defaults to 0, which never rolls over, so a
                        # large nested member stayed wholly in memory
                        with tempfile.SpooledTemporaryFile(
                            max_size=self.container_bufsize, prefix="Fido"
                        ) as target:
                            with zipstream.open(item) as source:
                                self.copy_stream(source, target)
                            # tarfile takes tell() as the archive start, so
                            # without this a tar inside a zip yielded no members
                            target.seek(0)
                            self.identify_contents(
                                item_name,
                                target,
                                self.container_type(matches),
                                extension=extension,
                            )
        except (IOError, OSError, zipfile.BadZipfile) as err:
            sys.stderr.write("FIDO: ZipError {0}: {1}\n".format(filename, err))

    def walk_tar(self, filename, fileobj, extension=True):
        """
        Identify the type of each item in the tar.

        @param fileobj.  If fileobj is not provided, open.
        @param filename.
        Call self.handle_matches instead of returning a value.
        """
        try:
            with tarfile.TarFile(filename, fileobj=fileobj, mode="r") as tarstream:
                for item in tarstream.getmembers():
                    if not item.isfile():
                        continue
                    timer = PerfTimer()
                    with closing(tarstream.extractfile(item)) as f:
                        tar_item_name = filename + "!" + item.name
                        self.current_file = tar_item_name
                        self.current_filesize = item.size
                        bofbuffer, eofbuffer, _ = self.get_buffers(f, item.size)
                        matches = self.match_formats(bofbuffer, eofbuffer)
                        # Mirrors walk_zip: a tar member used to get no
                        # extension fallback and an empty matchtype column
                        if len(matches) > 0 and self.current_filesize > 0:
                            self.handle_matches(tar_item_name, matches, timer.duration(), "signature")
                        elif extension and (len(matches) == 0 or self.current_filesize == 0):
                            matches = self.match_extensions(tar_item_name)
                            self.handle_matches(tar_item_name, matches, timer.duration(), "extension")
                        else:
                            self.handle_matches(tar_item_name, [], timer.duration(), "fail")
                        if self.container_type(matches):
                            f.seek(0)
                            self.identify_contents(
                                tar_item_name,
                                f,
                                self.container_type(matches),
                                extension=extension,
                            )
        except (tarfile.TarError, OSError) as err:
            sys.stderr.write("FIDO: Error: TarError {0}: {1}\n".format(filename, err))

    def as_good_as_any(self, f1, match_list):
        """
        Return True if the proposed format is as good as any in the match_list.

        For example, if there is no format in the match_list that has priority over the proposed one
        """
        if match_list != []:
            f1_puid = self.get_puid(f1)
            for f2, _ in match_list:
                if f1 == f2:
                    continue
                if f1_puid in self.puid_has_priority_over_map[self.get_puid(f2)]:
                    return False
        return True

    def buffered_read(self, file_pos, overlap):
        """Buffered read of data chunks."""
        buf = ""
        if not overlap:
            bufsize = self.container_bufsize
        else:
            bufsize = self.container_bufsize + overlap
        file_end = self.current_filesize
        with open(self.current_file, "rb") as file_handle:
            file_handle.seek(file_pos)
            if file_end - file_pos < bufsize:
                file_read = file_end - file_pos
            else:
                file_read = self.bufsize
            buf = file_handle.read(file_read)
        return buf

    def match_formats(self, bofbuffer, eofbuffer):
        """
        Apply the patterns for formats to the supplied buffers.

        @return a match list of (format, signature) tuples.
        The list has inferior matches removed.
        """
        self.current_count += 1
        result = []
        for format in self.formats:
            try:
                self.current_format = format
                for sig in self.get_signatures(format):
                    self.current_sig = sig
                    success = True
                    for pat in self.get_patterns(sig):
                        self.current_pat = pat
                        pos = self.get_pos(pat)
                        regex = self.get_regex(pat)
                        if pos == "BOF":
                            if not re.match(regex, bofbuffer):
                                success = False
                                break
                        elif pos in ("EOF", "VAR", "IFB"):
                            buffer_ = eofbuffer if pos == "EOF" else bofbuffer
                            if not re.search(regex, buffer_):
                                success = False
                                break
                    if success:
                        result.append((format, sig.findtext("name")))
            except re.error as err:
                # A pattern that cannot compile means that format can never be
                # identified, so name it rather than emitting a bare message
                sys.stderr.write("FIDO: invalid signature regex for {}: {}\n".format(self.get_puid(format), err))
                continue

        # Priority is resolved once, over the complete match set. Filtering
        # during collection as well made the outcome depend on the order of
        # self.formats, because a format dropped then was missing from the list
        # this pass reasons over.
        return [match for match in result if self.as_good_as_any(match[0], result)]

    def match_extensions(self, filename):
        """Return the list of (format, self.externalsig) for every format whose extension matches the filename."""
        myext = os.path.splitext(filename)[1].lower().lstrip(".")
        result = []
        if not myext:
            return result
        for element in self.formats:
            for format_ in element.findall("extension"):
                if myext == format_.text:
                    result.append((element, self.externalsig.findtext("name")))
                    break
        result = [match for match in result if self.as_good_as_any(match[0], result)]
        return result

    def copy_stream(self, source, target):
        """Copy the stream from source to target."""
        while True:
            buf = source.read(self.bufsize)
            if len(buf) == 0:
                break
            target.write(buf)


def field_value(value):
    """Return @param value safe to interpolate into a line of output.

    A filename is attacker controlled, and the default templates wrap it in
    quotes without escaping, so one containing a quote or a newline could add,
    split or suppress records in the CSV a preservation pipeline ingests.
    """
    if value is None:
        return ""
    text = str(value)
    # CSV quotes an embedded quote by doubling it; a line break ends the record
    return text.replace('"', '""').replace("\r", " ").replace("\n", " ")


def list_files(roots, recurse=False):
    """Return the files one at a time. Roots could be a fileobj or a list."""
    for root in roots:
        root = root.rstrip("\n")
        if not root:
            # A blank line in an -input list used to normalise to ".", which
            # silently walked the working directory
            continue
        root = os.path.normpath(root)
        if os.path.isfile(root):
            yield root
        elif os.path.isdir(root):
            for path, _, files in os.walk(root):
                for f in files:
                    yield os.path.join(path, f)
                if not recurse:
                    break
        else:
            # Neither a file nor a directory: os.walk yields nothing for these,
            # so a typo in a path produced a successful looking empty run
            sys.stderr.write("FIDO: Not a file or directory: {0}\n".format(root))


def main(args=None):
    """Main FIDO method."""
    # Filenames on media imaged from other filesystems are not always valid
    # UTF-8, and one of them used to abort the whole scan from the first
    # sys.stdout.write, losing every file after it
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    if not args:
        args = sys.argv[1:]
    args = parse_cli_args(args, defaults)
    timer = PerfTimer()

    versions = get_local_versions(args.confdir)

    defaults["xml_pronomSignature"] = versions.pronom_signature
    defaults["containersignature_file"] = versions.pronom_container_signature
    defaults["xml_fidoExtensionSignature"] = versions.fido_extension_signature
    defaults["format_files"] = [defaults["xml_pronomSignature"]]

    if args.pronom_only:
        versionHeader = (
            f"FIDO v{__version__} ({defaults['xml_pronomSignature']}, {defaults['containersignature_file']})\n"
        )
    else:
        versionHeader = (
            f"FIDO v{__version__} ({defaults['xml_pronomSignature']}, {defaults['containersignature_file']}, "
            f"{defaults['xml_fidoExtensionSignature']})\n"
        )
        defaults["format_files"].append(defaults["xml_fidoExtensionSignature"])

    if args.v:
        sys.stdout.write(versionHeader)
        sys.exit(0)

    if args.sigs:
        sig_file_actions(args.sigs.lower(), args.confdir)
        sys.exit(0)

    if args.matchprintf:
        args.matchprintf = args.matchprintf.replace(r"\n", "\n")
        args.matchprintf = args.matchprintf.replace(r"\t", "\t")
    if args.nomatchprintf:
        args.nomatchprintf = args.nomatchprintf.replace(r"\n", "\n")
        args.nomatchprintf = args.nomatchprintf.replace(r"\t", "\t")

    fido = Fido(
        quiet=args.q,
        bufsize=args.bufsize,
        container_bufsize=args.container_bufsize,
        printmatch=args.matchprintf,
        printnomatch=args.nomatchprintf,
        zip=args.zip,
        nocontainer=args.nocontainer,
        conf_dir=args.confdir,
    )

    # TODO: Allow conf options to be dis-included
    if args.loadformats:
        for file in args.loadformats.split(","):
            fido.load_fido_xml(file)

    # TODO: remove from maps
    if args.useformats:
        args.useformats = args.useformats.split(",")
        fido.formats = [f for f in fido.formats if f.find("puid").text in args.useformats]
    elif args.nouseformats:
        args.nouseformats = args.nouseformats.split(",")
        fido.formats = [f for f in fido.formats if f.find("puid").text not in args.nouseformats]

    # Set up to use stdin, or open input files:
    if args.input == "-":
        args.files = sys.stdin
    elif args.input:
        args.files = open(args.input, "r")

    # RUN
    try:
        if not args.q:
            sys.stderr.write(versionHeader)
            sys.stderr.flush()
        if (not args.input) and len(args.files) == 1 and args.files[0] == "-":
            if fido.zip:
                raise RuntimeError("Multiple content read from stdin not yet supported.")
            # get_buffers accumulates bytes, so the text wrapper will not do
            stdin = getattr(sys.stdin, "buffer", sys.stdin)
            fido.identify_stream(stdin, args.filename, extension=not args.noextension)
        else:
            for file in list_files(args.files, args.recurse):
                fido.identify_file(file, extension=not args.noextension)
    except KeyboardInterrupt:
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit("FIDO: Interrupt while identifying file {0}".format(fido.current_file))

    if not args.q:
        sys.stdout.flush()
        fido.print_summary(timer.duration())
        sys.stderr.flush()


if __name__ == "__main__":
    main()
