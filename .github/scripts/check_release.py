#!/usr/bin/env python3
"""Release time consistency checks for FIDO.

Each check guards a failure that otherwise surfaces at the end of a long build,
or after an upload that cannot be taken back:

* the git tag and the version the artefacts carry disagree, so the release is
  named after one version and its assets after another
* a version reaches PyPI with nothing in RELEASENOTES.md describing it
* the PRONOM signature data is missing from an artefact that installs cleanly
  and then cannot identify anything, or build leftovers are shipped alongside it

Both release.yml and publish-pypi.yml call this, so the comparison has one
implementation rather than one per workflow.
"""

import argparse
import sys
import tarfile
import zipfile
from pathlib import Path

from packaging.version import InvalidVersion, Version

# Present in every artefact. The two globbed names change with each PRONOM
# release, so they are matched by prefix rather than listed
REQUIRED_DATA = ("fido/conf/versions.xml", "fido/conf/format_extensions.xml")
REQUIRED_DATA_GLOBS = (("fido/conf/formats-v", ".xml"), ("fido/conf/container-signature-", ".xml"))

BYTECODE_MARKERS = ("__pycache__", ".pyc", ".pyo")


class CheckFailed(Exception):
    """A check found a real disagreement, as opposed to being unable to run."""


def parse_version(raw, description):
    """Return @param raw as a Version, or fail naming what could not be read."""
    try:
        return Version(raw)
    except InvalidVersion as exc:
        raise CheckFailed("{0} is not a PEP 440 version: {1}".format(description, exc))


def version_from_tag(tag):
    """Return the version a git tag names.

    FIDO tags carry a v prefix, v1.6.1 and v2.0.0rc1, which is not part of the
    version itself.
    """
    return parse_version(tag[1:] if tag.startswith("v") else tag, "tag {0}".format(tag))


def check_version(declared, tag=None):
    """Return the declared version, having checked @param tag agrees with it.

    Comparison is by PEP 440 equality, not string equality, because the two are
    not the same: __version__ of "2.0.0-dev" is normalised to 2.0.0.dev0 in
    artefact filenames and on the index, so comparing the raw strings rejects a
    build's own artefacts.
    """
    version = parse_version(declared, "declared version {0}".format(declared))
    if tag is not None and version_from_tag(tag) != version:
        raise CheckFailed(
            "tag {0} names version {1}, but the package declares {2}".format(tag, version_from_tag(tag), version)
        )
    return version


def check_notes(declared, notes_path):
    """Check RELEASENOTES.md has a heading for @param declared.

    A prerelease is accepted against its own heading or the heading of the
    release it leads to, so 2.0.0rc1 is covered by "Fido 2.0.0" and an rc does
    not need a notes edit of its own.
    """
    version = parse_version(declared, "declared version {0}".format(declared))
    accepted = {str(version)}
    if version.is_prerelease:
        accepted.add(str(Version(version.base_version)))

    notes = Path(notes_path)
    if not notes.is_file():
        raise CheckFailed("{0} does not exist".format(notes_path))

    headings = {
        line.split(None, 1)[1].strip()
        for line in notes.read_text(encoding="utf-8").splitlines()
        if line.lower().startswith("fido ") and len(line.split(None, 1)) == 2
    }
    found = sorted(accepted & headings)
    if not found:
        raise CheckFailed(
            "{0} has no heading for {1} (accepted: {2})".format(notes_path, version, ", ".join(sorted(accepted)))
        )
    return found[0]


def _missing_data(names):
    """Return the required data files absent from @param names."""
    missing = [name for name in REQUIRED_DATA if name not in names]
    for prefix, suffix in REQUIRED_DATA_GLOBS:
        if not any(name.startswith(prefix) and name.endswith(suffix) for name in names):
            missing.append("{0}*{1}".format(prefix, suffix))
    return missing


def _bytecode(names):
    """Return the shipped bytecode in @param names."""
    return sorted(name for name in names if any(marker in name for marker in BYTECODE_MARKERS))


def _summarise(names, limit=5):
    """Return @param names as a log line, bounded so a long list stays readable."""
    shown = ", ".join(names[:limit])
    return shown if len(names) <= limit else "{0} and {1} more".format(shown, len(names) - limit)


def _metadata_version(text, source):
    """Return the Version from a METADATA or PKG-INFO body."""
    for line in text.splitlines():
        if line.startswith("Version:"):
            return parse_version(line.split(":", 1)[1].strip(), "{0} version".format(source))
    raise CheckFailed("{0} carries no Version field".format(source))


def read_wheel(path):
    """Return (member names, declared Version) for a wheel."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata) != 1:
            raise CheckFailed("{0} holds {1} dist-info METADATA files".format(path.name, len(metadata)))
        text = archive.read(metadata[0]).decode("utf-8")
    return names, _metadata_version(text, path.name)


def read_sdist(path):
    """Return (member names without the root directory, declared Version)."""
    with tarfile.open(path) as archive:
        members = archive.getnames()
        stripped = [name.partition("/")[2] for name in members]
        info = [name for name in members if name.partition("/")[2] == "PKG-INFO"]
        if len(info) != 1:
            raise CheckFailed("{0} holds {1} PKG-INFO files".format(path.name, len(info)))
        handle = archive.extractfile(info[0])
        text = handle.read().decode("utf-8")
    return stripped, _metadata_version(text, path.name)


def check_artifacts(dist_dir, declared):
    """Check the built artefacts carry the version, the data and nothing else.

    The signature data reaches an artefact through package-data rather than as
    importable code, so a packaging mistake yields a wheel that installs without
    error and identifies nothing.
    """
    version = parse_version(declared, "declared version {0}".format(declared))
    dist = Path(dist_dir)
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise CheckFailed(
            "expected one wheel and one sdist in {0}, found {1} and {2}".format(dist_dir, len(wheels), len(sdists))
        )

    problems = []
    for path, reader in ((wheels[0], read_wheel), (sdists[0], read_sdist)):
        names, built = reader(path)
        faults = []
        if built != version:
            faults.append("declares version {0}, expected {1}".format(built, version))
        missing = _missing_data(names)
        if missing:
            faults.append("is missing signature data: {0}".format(", ".join(missing)))
        shipped_bytecode = _bytecode(names)
        if shipped_bytecode:
            faults.append("ships {0} bytecode entries: {1}".format(len(shipped_bytecode), _summarise(shipped_bytecode)))
        if faults:
            problems.extend("{0} {1}".format(path.name, fault) for fault in faults)
        else:
            print("{0}: version {1}, {2} members, signature data present, no bytecode".format(
                path.name, built, len(names)
            ))

    if problems:
        raise CheckFailed("\n".join(problems))
    return version


def main(argv=None):
    """Run the requested check, reporting a failure on stderr."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subcommands = parser.add_subparsers(dest="check", required=True)

    version = subcommands.add_parser("version", help="check the tag against the declared version")
    version.add_argument("--declared", required=True, help="the version the package declares")
    version.add_argument("--tag", help="the git tag being released, with or without its v prefix")

    notes = subcommands.add_parser("notes", help="check the release notes cover the version")
    notes.add_argument("--declared", required=True)
    notes.add_argument("--notes", default="RELEASENOTES.md")

    artifacts = subcommands.add_parser("artifacts", help="check the built artefacts")
    artifacts.add_argument("--declared", required=True)
    artifacts.add_argument("--dist", default="dist")

    args = parser.parse_args(argv)
    try:
        if args.check == "version":
            parsed = check_version(args.declared, args.tag)
            # Captured by the workflow and appended to $GITHUB_OUTPUT, so the
            # normalisation happens once rather than in each job that needs it
            print("version={0}".format(args.declared))
            print("normalised={0}".format(parsed))
            print("prerelease={0}".format("true" if parsed.is_prerelease else "false"))
        elif args.check == "notes":
            print("release notes heading: Fido {0}".format(check_notes(args.declared, args.notes)))
        else:
            check_artifacts(args.dist, args.declared)
    except CheckFailed as exc:
        print("check_release: {0}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
