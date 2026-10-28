# -*- coding: utf-8 -*-

"""
PRONOM UTILS.

PYTHON FUNCTION TO QUERY PRONOM VERSION
AND DOWNLOAD SIGNATUREFILE
USES PRONOM SOAP SERVICE

Open Planets Foundation (http://www.openplanetsfoundation.org)
See License.txt for license information.
Download from: http://github.com/openplanets/fido/downloads
Author: Maurice de Rooij (OPF/NANETH), 2012

PRONOM UTILS is a library used by FIDO.
FIDO uses the UK National Archives (TNA) PRONOM File Format and Container descriptions.
PRONOM is available from http://www.nationalarchives.gov.uk/pronom/
"""

import os
import re
import sys
import tempfile
import zipfile

import requests
from defusedxml import ElementTree as ET
from defusedxml.ElementTree import ParseError, parse

from fido import CONFIG_DIR

# A server that completes the handshake and then sends nothing would otherwise
# block forever: requests defaults to no timeout at all
HTTP_TIMEOUT = (10, 60)


class LocalVersions(object):
    """
    Parse local versions XML file.

    This is what the XML document should look like:

    <?xml version="1.0" encoding="UTF-8"?>
    <versions>
        <pronomVersion>84</pronomVersion>
        <pronomSignature>formats-v84.xml</pronomSignature>
        <pronomContainerSignature>container-signature-20160121.xml</pronomContainerSignature>
        <fidoExtensionSignature>format_extensions.xml</fidoExtensionSignature>
        <updateScript>1.2.2</updateScript>
        <updateSite>https://fidosigs.openpreservation.org</updateSite>
    </versions>
    """

    PROPS_MAPPING = {
        "pronom_version": "pronomVersion",
        "pronom_signature": "pronomSignature",
        "pronom_container_signature": "pronomContainerSignature",
        "fido_extension_signature": "fidoExtensionSignature",
        "update_script": "updateScript",
        "update_site": "updateSite",
    }

    ROOT_ELEMENT = "versions"

    def __init__(self, versions_file):
        """Instantiate class based on the file indicated in `versions_file`."""
        self.versions_file = versions_file
        self.conf_dir = os.path.abspath(os.path.dirname(versions_file))
        try:
            self.tree = parse(versions_file)
            self.root = self.tree.getroot()
        except FileNotFoundError:
            # No file yet is a fresh start; a corrupt one is not, and treating
            # them alike started FIDO with every signature path set to None
            self.root = ET.Element(self.ROOT_ELEMENT)
            self.tree = ET.ElementTree(self.root)
        except (ParseError, OSError) as err:
            sys.exit("FIDO: {} is not readable as XML: {}".format(versions_file, err))

    def __getattr__(self, name):
        """Extract the element's text content."""
        if name in self.PROPS_MAPPING:
            return self.root.find(self.PROPS_MAPPING[name]).text

    def __setattr__(self, name, value):
        """Update the element's text content."""
        if name in self.PROPS_MAPPING:
            try:
                self.root.find(self.PROPS_MAPPING[name]).text = value
            except AttributeError:
                elem = ET.SubElement(self.root, self.PROPS_MAPPING[name])
                elem.text = value
        else:
            object.__setattr__(self, name, value)

    def get_zip_file(self):
        """Obtain location to the PRONOM XML Zip file based on the current PRONOM version."""
        return os.path.join(self.conf_dir, "pronom-xml-v{}.zip".format(self.pronom_version))

    def get_signature_file(self):
        """Obtain location to the current PRONOM signature file."""
        return os.path.join(self.conf_dir, self.pronom_signature)

    def write(self):
        """Update versions.xml."""
        # Check that all the fields are defined
        for key, value in self.PROPS_MAPPING.items():
            if self.root.find(value) is None:
                raise ValueError("Field {} has not been defined!".format(key))
        # Written via a temporary sibling: an interrupted write left
        # versions.xml truncated, and __init__ then silently substituted an
        # empty root rather than reporting a corrupt configuration
        handle, temporary = tempfile.mkstemp(dir=self.conf_dir, prefix=".versions-", suffix=".part")
        os.close(handle)
        try:
            self.tree.write(temporary, xml_declaration=True, method="xml", encoding="utf-8")
            os.replace(temporary, self.versions_file)
        except BaseException:
            if os.path.exists(temporary):
                os.unlink(temporary)
            raise


def get_local_versions(config_dir=CONFIG_DIR):
    """Return an instance of LocalVersions loaded with `conf/versions.xml`."""
    return LocalVersions(os.path.join(config_dir, "versions.xml"))


def sig_file_actions(sig_act, config_dir=CONFIG_DIR):
    """Process signature file update actions.

    @param config_dir is where versions.xml is read from and where signature
    files are installed. Without it every -sigs action read the packaged
    versions.xml regardless of -confdir, so an alternative signature service
    could not be tested without editing the installed package.
    """
    versions = get_local_versions(config_dir)
    sig_vers = versions.pronom_version

    # Get update URL, add trailing slash if missing
    update_url = versions.update_site
    if not update_url.endswith("/"):
        update_url += "/"

    # Parse parameter and take appropriate action
    if sig_act == "list":
        # List available signature files
        _list_available_versions(update_url)
    elif sig_act in ["check", "update"]:
        # Check or/and update signature file to latest
        _check_update_signatures(sig_vers, update_url, versions, sig_act == "update", config_dir)
    else:
        # Download a specific version of the signature file
        _download_sig_version(sig_act, update_url, versions, config_dir)
    sys.stdout.flush()
    sys.exit(0)


def _list_available_versions(update_url):
    """List available signature files."""
    resp = requests.get(update_url + "format/", timeout=HTTP_TIMEOUT)
    tree = ET.fromstring(resp.content)
    sys.stdout.write("Available signature versions:\n")
    for child in tree.iter("signature"):
        sys.stdout.write("{}\n".format(child.get("version")))


def _check_update_signatures(sig_vers, update_url, versions, is_update=False, config_dir=CONFIG_DIR):
    is_new, latest = _version_check(sig_vers, update_url)
    if is_new:
        sys.stdout.write("Updated signatures v{} are available, current version is v{}\n".format(latest, sig_vers))
        if is_update:
            _output_details(latest, update_url, versions, config_dir)
    else:
        sys.stdout.write("Your signature files are up to date, current version is v{}\n".format(sig_vers))
    sys.exit(0)


def _download_sig_version(sig_act, update_url, versions, config_dir=CONFIG_DIR):
    sys.stdout.write("Downloading signature files for version {}\n".format(sig_act))
    match = re.search(r"^v?(\d+)$", sig_act, re.IGNORECASE)

    if not match:
        sys.exit(
            '{} is not a valid version number, to download a sig file try "-sig v104" or "-sig 104".'.format(sig_act)
        )
    ver = "v" + _get_version(sig_act)
    resp = requests.get(update_url + "format/" + ver + "/", timeout=HTTP_TIMEOUT)
    if resp.status_code != 200:
        sys.exit("No signature files found for {}, REST status {}".format(sig_act, resp.status_code))
    _output_details(re.search(r"\d+|$", ver).group(), update_url, versions, config_dir)  # noqa: W605


def _get_version(ver_string):
    """Parse a PRONOM version number from a string."""
    # The regex is case insensitive, so stripping a lowercase "v" only let
    # "V117" through intact, and int() then raised on it
    match = None if ver_string is None else re.search(r"^v?(\d+)$", ver_string, re.IGNORECASE)
    if not match:
        sys.exit(
            '{} is not a valid version number, to download a sig file try "-sig v104" or "-sig 104".'.format(ver_string)
        )
    return match.group(1)


def _output_details(version, update_url, versions, config_dir=CONFIG_DIR):
    sys.stdout.write("Updating signature file to {}.\n".format(version))
    _write_sigs(version, update_url, "fido", "formats-v{}.xml", config_dir)
    _write_sigs(version, update_url, "droid", "DROID_SignatureFile-v{}.xml", config_dir)
    _write_sigs(version, update_url, "pronom", "pronom-xml-v{}.zip", config_dir)
    versions.pronom_version = "{}".format(version)
    versions.pronom_signature = "formats-v{}.xml".format(version)
    versions.write()


def _version_check(sig_ver, update_url):
    resp = requests.get(update_url + "format/latest/", timeout=HTTP_TIMEOUT)
    if resp.status_code != 200:
        sys.exit("Error getting latest version info: HTTP Status {}".format(resp.status_code))
    root_ele = ET.fromstring(resp.text)
    latest = _get_version(root_ele.get("version"))
    return int(latest) > int(sig_ver), latest


def _write_sigs(latest, update_url, type, name_template, config_dir=CONFIG_DIR):
    # Installed alongside the versions.xml being updated, rather than always
    # inside the package, so that -confdir selects both
    sig_out = os.path.join(config_dir, name_template.format(latest))
    if os.path.exists(sig_out) and _is_valid_signature_file(sig_out, type):
        return
    resp = requests.get(update_url + "format/{0}/{1}/".format(latest, type), timeout=HTTP_TIMEOUT)
    if resp.status_code != 200:
        sys.exit(
            "Error downloading {} signatures: HTTP Status {}".format(type, resp.status_code)
        )
    # Written to a sibling and renamed, so a failure leaves the working
    # signature set in place. Installing the body unchecked meant an error page
    # became the signature file, and the os.path.exists guard above then
    # skipped the download forever, so the damage could not be repaired.
    _install_atomically(sig_out, resp.content, type)


# A maintenance page is well formed XML, so parsing is not enough: the root
# element has to be the one this kind of signature file carries
EXPECTED_ROOTS = {"fido": "formats", "droid": "FFSignatureFile"}


def _is_valid_signature_file(path, kind):
    """Return True if @param path holds something usable as @param kind data."""
    try:
        if os.path.getsize(path) == 0:
            return False
        if kind == "pronom":
            with zipfile.ZipFile(path) as archive:
                return archive.testzip() is None
        root = parse(path).getroot()
    except (ParseError, OSError, zipfile.BadZipFile):
        return False
    expected = EXPECTED_ROOTS.get(kind)
    # Namespaced roots arrive as {uri}tag
    return expected is None or root.tag.rsplit("}", 1)[-1] == expected


def _install_atomically(destination, content, kind):
    """Write @param content to @param destination via a temporary sibling."""
    directory = os.path.dirname(destination)
    handle, temporary = tempfile.mkstemp(dir=directory, prefix=".fido-", suffix=".part")
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(content)
        if not _is_valid_signature_file(temporary, kind):
            raise ValueError("downloaded data for {} is not usable".format(os.path.basename(destination)))
        os.replace(temporary, destination)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
