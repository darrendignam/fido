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
    """Base class for container support."""

    def _process_puid_map(self, data, puid_map):
        results = []
        for puid, signatures in puid_map.items():
            results.extend(self._process_matches(data, puid, signatures))

        return results

    def _process_matches(self, data, puid, signatures):
        results = []
        for signature in signatures:
            try:
                if re.search(signature["signature"], data):
                    results.append(puid)
            except re.error as err:
                # A container signature that cannot compile means this format
                # can never be identified; skipping it beats aborting the run
                sys.stderr.write(
                    "FIDO: invalid container signature for {}: {}\n".format(puid, err)
                )

        return results


class OlePackage(Package):
    """OlePackage supports OLE containers."""

    def __init__(self, ole, signatures, max_read=DEFAULT_MAX_READ):
        """Instantiate OlePackage object given the location of its file and signatures."""
        self.ole = ole
        self.signatures = signatures
        self.max_read = max_read

    def detect_formats(self):
        """Detect available formats inside the OLE container."""
        try:
            with olefile.OleFileIO(self.ole) as ole:
                results = []
                for path, puid_map in self.signatures.items():
                    # Each OLE container signature lists the path of the file inside the OLE
                    # on which it operates; if the file is missing, there can be no match.
                    # This is not a precise match because the name of the stream may slightly
                    # differ; for example, \x01CompObj instead of CompObj
                    filepath = None
                    for paths in ole.listdir():
                        p = "/".join(paths)
                        if p == path or p[1:] == path:
                            filepath = p
                            break

                    # Path to match isn't in the container at all
                    if filepath is None:
                        continue

                    with ole.openstream(filepath) as stream:
                        contents = stream.read(self.max_read)
                        results.extend(self._process_puid_map(contents, puid_map))

                return results
        except IOError:
            return []


class ZipPackage(Package):
    """ZipPackage supports Zip containers."""

    def __init__(self, zip_, signatures, max_read=DEFAULT_MAX_READ):
        """Instantiate ZipPackage object given the location of its file and signatures."""
        self.zip = zip_
        self.signatures = signatures
        self.max_read = max_read

    def detect_formats(self):
        """Detect available formats inside the ZIP container."""
        try:
            with zipfile.ZipFile(self.zip) as zip_:
                results = []
                for path, puid_map in self.signatures.items():
                    # Each ZIP container signature lists the path of the file inside the ZIP
                    # on which it operates; if the file is missing, there can be no match.
                    if path not in zip_.namelist():
                        continue

                    # Extract the requested file from the ZIP only once, and pass the same
                    # data to each signature that requires it.
                    with zip_.open(path) as id_file:
                        contents = id_file.read(self.max_read)
                        results.extend(self._process_puid_map(contents, puid_map))

                return results
        except (zipfile.BadZipfile, RuntimeError, UnicodeDecodeError):
            return []
