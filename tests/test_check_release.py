#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for the release time checks in .github/scripts/check_release.py.

The script is driven through its command line, the way the workflows drive it,
so the exit codes the workflow steps depend on are what gets asserted rather
than the return values of the functions behind them.
"""

import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

CHECK_RELEASE = Path(__file__).resolve().parent.parent / ".github" / "scripts" / "check_release.py"

# Enough of fido/conf to satisfy the required set, including the two names that
# change with every PRONOM release and so are matched by prefix
DATA_FILES = (
    "fido/conf/versions.xml",
    "fido/conf/format_extensions.xml",
    "fido/conf/formats-v116.xml",
    "fido/conf/container-signature-20231127.xml",
)


def run_check(*arguments):
    """Return the completed run of check_release.py with @param arguments."""
    return subprocess.run(
        [sys.executable, str(CHECK_RELEASE)] + [str(argument) for argument in arguments],
        capture_output=True,
        text=True,
    )


def assert_passed(result):
    """Assert the check succeeded, showing both streams when it did not."""
    assert result.returncode == 0, "exit {0}\nstdout:\n{1}\nstderr:\n{2}".format(
        result.returncode, result.stdout, result.stderr
    )


def assert_failed(result, *expected_fragments):
    """Assert the check failed and said why."""
    assert result.returncode == 1, "expected exit 1, got {0}\nstdout:\n{1}".format(result.returncode, result.stdout)
    for fragment in expected_fragments:
        assert fragment in result.stderr, "{0!r} missing from stderr:\n{1}".format(fragment, result.stderr)


def make_wheel(directory, version, data_files=DATA_FILES, bytecode=()):
    """Write a minimal wheel carrying @param version and return its path."""
    path = directory / "opf_fido-{0}-py3-none-any.whl".format(version)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "opf_fido-{0}.dist-info/METADATA".format(version),
            "Metadata-Version: 2.1\nName: opf-fido\nVersion: {0}\n".format(version),
        )
        archive.writestr("fido/__init__.py", "")
        for name in data_files:
            archive.writestr(name, "<xml/>")
        for name in bytecode:
            archive.writestr(name, b"\x00")
    return path


def make_sdist(directory, version, data_files=DATA_FILES, bytecode=()):
    """Write a minimal sdist carrying @param version and return its path."""
    path = directory / "opf_fido-{0}.tar.gz".format(version)
    root = "opf_fido-{0}".format(version)
    with tarfile.open(path, "w:gz") as archive:
        for name, body in [
            ("PKG-INFO", "Metadata-Version: 2.1\nName: opf-fido\nVersion: {0}\n".format(version)),
            ("fido/__init__.py", ""),
        ] + [(name, "<xml/>") for name in data_files] + [(name, "x") for name in bytecode]:
            member = tarfile.TarInfo("{0}/{1}".format(root, name))
            payload = body.encode("utf-8")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return path


@pytest.fixture
def dist(tmp_path):
    """A dist directory holding one good wheel and one good sdist."""
    directory = tmp_path / "dist"
    directory.mkdir()
    return directory


@pytest.mark.parametrize(
    ("declared", "tag", "normalised", "prerelease"),
    (
        # The mismatch this check exists for: __version__ of 2.0.0-dev is
        # normalised to 2.0.0.dev0, so comparing raw strings rejects the
        # build's own artefacts
        ("2.0.0-dev", "v2.0.0.dev0", "2.0.0.dev0", "true"),
        ("2.0.0-dev", "2.0.0-dev", "2.0.0.dev0", "true"),
        # FIDO tags carry a v prefix, which is not part of the version
        ("1.6.1", "v1.6.1", "1.6.1", "false"),
        ("0.0.1rc1", "v0.0.1rc1", "0.0.1rc1", "true"),
    ),
)
def test_a_tag_that_agrees_after_normalisation_is_accepted(declared, tag, normalised, prerelease):
    result = run_check("version", "--declared", declared, "--tag", tag)

    assert_passed(result)
    assert "normalised={0}".format(normalised) in result.stdout
    assert "prerelease={0}".format(prerelease) in result.stdout


def test_a_tag_naming_another_version_is_refused():
    """A tag that disagrees would produce a release whose assets are all named
    after the other version."""
    result = run_check("version", "--declared", "2.0.0-dev", "--tag", "v1.6.1")

    assert_failed(result, "tag v1.6.1 names version 1.6.1", "declares 2.0.0.dev0")


def test_a_version_that_is_not_pep_440_is_refused():
    """0.0.1-test reads like a sensible throwaway tag and is not a version at
    all: python -m build refuses it, after the metadata job has passed."""
    result = run_check("version", "--declared", "0.0.1-test")

    assert_failed(result, "is not a PEP 440 version")


def test_the_version_check_runs_without_a_tag():
    """workflow_dispatch has no tag, and the build is still worth exercising."""
    result = run_check("version", "--declared", "2.0.0-dev")

    assert_passed(result)
    assert "normalised=2.0.0.dev0" in result.stdout


def test_release_notes_must_carry_the_version(tmp_path):
    notes = tmp_path / "RELEASENOTES.md"
    notes.write_text("RELEASE NOTES\n=============\n\nFido 2.0.0\n----------\n", encoding="utf-8")

    assert_passed(run_check("notes", "--declared", "2.0.0", "--notes", notes))


def test_a_prerelease_is_covered_by_the_release_it_leads_to(tmp_path):
    """Otherwise every rc needs a notes edit of its own."""
    notes = tmp_path / "RELEASENOTES.md"
    notes.write_text("Fido 2.0.0\n----------\n", encoding="utf-8")

    result = run_check("notes", "--declared", "2.0.0rc1", "--notes", notes)

    assert_passed(result)
    assert "Fido 2.0.0" in result.stdout


def test_an_undocumented_version_is_refused(tmp_path):
    notes = tmp_path / "RELEASENOTES.md"
    notes.write_text("Fido 1.6.1\n----------\n", encoding="utf-8")

    assert_failed(run_check("notes", "--declared", "2.0.0", "--notes", notes), "no heading for 2.0.0")


def test_missing_release_notes_are_refused(tmp_path):
    assert_failed(run_check("notes", "--declared", "2.0.0", "--notes", tmp_path / "absent.md"), "does not exist")


def test_a_correct_pair_of_artefacts_passes(dist):
    make_wheel(dist, "2.0.0.dev0")
    make_sdist(dist, "2.0.0.dev0")

    result = run_check("artifacts", "--declared", "2.0.0-dev", "--dist", dist)

    assert_passed(result)
    assert "signature data present, no bytecode" in result.stdout


def test_shipped_bytecode_is_refused(dist):
    """The wheel carried 17 .pyc files, including bytecode for modules that had
    moved, because the package-data glob was *.*."""
    make_wheel(dist, "2.0.0.dev0", bytecode=("fido/__pycache__/fido.cpython-312.pyc",))
    make_sdist(dist, "2.0.0.dev0")

    assert_failed(run_check("artifacts", "--declared", "2.0.0-dev", "--dist", dist), "ships 1 bytecode entries")


@pytest.mark.parametrize("absent", DATA_FILES)
def test_missing_signature_data_is_refused(dist, absent):
    """Without it the artefact installs cleanly and identifies nothing."""
    kept = tuple(name for name in DATA_FILES if name != absent)
    make_wheel(dist, "2.0.0.dev0", data_files=kept)
    make_sdist(dist, "2.0.0.dev0")

    assert_failed(run_check("artifacts", "--declared", "2.0.0-dev", "--dist", dist), "is missing signature data")


def test_an_artefact_built_from_another_version_is_refused(dist):
    """A release built from the wrong ref would upload the wrong version."""
    make_wheel(dist, "1.6.1")
    make_sdist(dist, "2.0.0.dev0")

    assert_failed(run_check("artifacts", "--declared", "2.0.0-dev", "--dist", dist), "declares version 1.6.1")


@pytest.mark.parametrize("wheels", (0, 2))
def test_anything_but_one_wheel_and_one_sdist_is_refused(dist, wheels):
    """Two builds in one directory would make which artefact was checked a
    matter of sort order."""
    for index in range(wheels):
        make_wheel(dist, "2.0.0.dev{0}".format(index))
    make_sdist(dist, "2.0.0.dev0")

    assert_failed(run_check("artifacts", "--declared", "2.0.0-dev", "--dist", dist), "expected one wheel and one sdist")
