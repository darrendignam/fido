"""Support for containers."""

import re
import sys
import zipfile

import olefile


# Container signatures match near the head of a member, so the whole member
# never needs to be in memory. Without a cap a 200KB archive holding a 200MB
# member drove peak RSS past 450MB.
DEFAULT_MAX_READ = 512 * 1024


class Package:
    """Base class for container support.

    A subclass supplies open_container and read_member; the matching rules live
    here so that ZIP and OLE2 containers cannot drift apart.
    """

    def detect_formats(self):
        """Return the PUIDs of every container signature this package satisfies."""
        results = []
        try:
            with self.open_container() as container:
                for puid, signatures in self.signatures.items():
                    # Signatures for one PUID are alternatives, so any is enough
                    if any(self._signature_matches(container, signature) for signature in signatures):
                        results.append(puid)
        except self.CONTAINER_ERRORS as err:
            sys.stderr.write("FIDO: could not read container: {}\n".format(err))
            return []
        return results

    def _signature_matches(self, container, signature):
        """Return True when every file and every sequence of @param signature matches.

        The per-path results used to be combined with OR, and only the first
        file and its first sequence were kept, so an archive missing the file
        that discriminates between versions matched all of them at once.
        """
        for requirement in signature["files"]:
            contents = self.read_member(container, requirement["path"])
            if contents is None:
                return False
            for sequence in requirement["sequences"]:
                if not self._sequence_matches(contents, sequence):
                    return False
        return True

    @staticmethod
    def _sequence_matches(contents, sequence):
        try:
            match = re.search(sequence["sequence"], contents)
        except re.error as err:
            # A container signature that cannot compile means this format can
            # never be identified; skipping it beats aborting the run
            sys.stderr.write("FIDO: invalid container signature: {}\n".format(err))
            return False
        if match is None:
            return False
        max_offset = sequence["max_offset"]
        return max_offset is None or match.start() <= max_offset


class OlePackage(Package):
    """OlePackage supports OLE containers."""

    CONTAINER_ERRORS = (OSError, ValueError)

    def __init__(self, ole, signatures, max_read=DEFAULT_MAX_READ):
        """Instantiate OlePackage object given the location of its file and signatures."""
        self.ole = ole
        self.signatures = signatures
        self.max_read = max_read

    def open_container(self):
        """Return the opened OLE2 container."""
        return olefile.OleFileIO(self.ole)

    def read_member(self, container, path):
        """Return the head of the stream at @param path, or None if it is absent."""
        stream_path = self._resolve_path(container, path)
        if stream_path is None:
            return None
        with container.openstream(stream_path) as stream:
            return stream.read(self.max_read)

    @staticmethod
    def _resolve_path(container, path):
        """Return the real stream name matching @param path, or None.

        OLE2 stream names carry a control character prefix, for example
        \x01CompObj for CompObj, and it appears on each path component rather
        than only on the first. Stripping one character from the joined path
        missed every nested stream, and matched any name differing by a single
        leading character, so XHeader matched Header.
        """
        wanted = path.split("/")
        fallback = None
        for paths in container.listdir():
            if paths == wanted:
                return "/".join(paths)
            if fallback is None and len(paths) == len(wanted) and all(
                component.lstrip("\x01\x02\x03\x04\x05") == expected
                for component, expected in zip(paths, wanted)
            ):
                fallback = "/".join(paths)
        return fallback


class ZipPackage(Package):
    """ZipPackage supports Zip containers."""

    CONTAINER_ERRORS = (zipfile.BadZipfile, OSError, RuntimeError, UnicodeDecodeError, ValueError)

    def __init__(self, zip_, signatures, max_read=DEFAULT_MAX_READ):
        """Instantiate ZipPackage object given the location of its file and signatures."""
        self.zip = zip_
        self.signatures = signatures
        self.max_read = max_read

    def open_container(self):
        """Return the opened ZIP container."""
        return zipfile.ZipFile(self.zip)

    def read_member(self, container, path):
        """Return the head of the member at @param path, or None if it is absent."""
        try:
            with container.open(path) as member:
                return member.read(self.max_read)
        except KeyError:
            return None
