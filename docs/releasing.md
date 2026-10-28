---
layout: page
title: Automating a FIDO release
---

How to automate a PyPI release
------------------------------

Short answer: tag the commit, let GitHub Actions build and verify the artefacts,
review the draft GitHub release, and publish it. Publishing the release triggers
the upload to PyPI, authenticated by Trusted Publishing rather than by a stored
API token.

This mirrors the arrangement used by the sister project jpylyzer, adapted for a
pure Python package built from `pyproject.toml`.

### Why Trusted Publishing rather than an API token

A PyPI API token stored in repository secrets is a long lived credential that
grants upload rights to the project. Anyone who can run a workflow, or who can
read the secret through a malicious pull request or a compromised action, can
publish a package under the project name.

Trusted Publishing removes the stored credential. PyPI is configured to trust a
specific workflow in a specific repository, and the workflow authenticates with
a short lived OpenID Connect token that GitHub mints for that one run. There is
no secret to leak, rotate, or accidentally print into a log.

### One time setup

**1. Decide which project name to publish.** The package name in
`pyproject.toml` is `opf-fido`, which is the name the upstream Open Preservation
Foundation project publishes. A fork cannot upload to a project it does not own,
so check this before wiring anything up:

- Publishing from the upstream repository: the OPF maintainers add the trusted
  publisher to the existing `opf-fido` project.
- Rehearsing from a fork: use TestPyPI, which is a separate index with separate
  ownership, and add `repository-url: https://test.pypi.org/legacy/` to the
  publish step.
- Releasing a genuinely separate fork build: change `name` in `pyproject.toml`
  to a name nobody has taken, otherwise the upload is rejected.

**2. Add the trusted publisher on PyPI.** Under the project's
Publishing settings, or via "pending publisher" if the project does not exist
yet, add a GitHub publisher with these four values:

| Field | Value |
| --- | --- |
| Owner | the GitHub user or organisation |
| Repository | `fido` |
| Workflow name | `publish-pypi.yml` |
| Environment | `pypi` |

The workflow filename must match exactly. A mismatch fails at upload time, after
a successful build, which is a confusing place to discover a typo.

**3. Protect the environment.** The workflow declares
`environment: name: pypi`. GitHub creates that environment automatically on the
first run, but an auto created environment has no protection rules, so by itself
it gates nothing. To require a human approval before any upload, open the
repository settings, select the `pypi` environment, and add required reviewers.

For a brand new project name, step 2 uses a pending publisher, which PyPI
converts into a normal publisher when the first upload creates the project.

### The release flow

```
git tag 2.0.0 && git push origin 2.0.0
        |
        v
  release.yml                       (triggered by the tag)
    metadata          reads fido.__version__, fails if the tag disagrees
    python-packages   builds sdist and wheel, twine check,
                      asserts conf/*.xml is inside the wheel
    smoke-test        installs the wheel on Linux, macOS and Windows,
                      across two Python versions, and identifies a GIF
    github-release    creates a DRAFT release carrying both artefacts
        |
        v
  review the draft, write the release notes, click Publish
        |
        v
  publish-pypi.yml                  (triggered by release: published)
    rebuilds, twine check, re-checks the tag against the version,
    uploads via Trusted Publishing
```

The draft release is the deliberate review gate. Nothing reaches PyPI until a
human publishes the release, and the artefacts attached to the draft are the
ones that were tested.

### Why the extra verification steps

Two checks are specific to FIDO and worth keeping.

**The wheel must contain the signature data.** FIDO's PRONOM signatures live in
`fido/conf/*.xml` and reach the wheel through `[tool.setuptools.package-data]`,
not as importable code. A packaging mistake there produces a wheel that installs
without error and then cannot identify anything, because the signature file it
names in `versions.xml` is absent. The build job therefore opens the wheel and
asserts that `versions.xml`, `format_extensions.xml`, a `formats-v*.xml` and a
`container-signature-*.xml` are all present.

**The installed wheel must actually identify a file.** The smoke test job runs
with no checkout at all, installs only the built wheel, and identifies a small
GIF, asserting the result contains `fmt/4`. Running without a checkout matters:
with the source tree present, an import or a data file can resolve from the
working directory and hide the packaging defect the test exists to catch.

### Version and tag discipline

The version has one source, `__version__` in `fido/__init__.py`, which
`pyproject.toml` reads through `[tool.setuptools.dynamic]`. Both workflows fail
if the git tag does not match it, so the tag, the metadata and the artefact
filenames cannot disagree.

Note that PyPI normalises versions per PEP 440. The current `2.0.0-dev` becomes
`2.0.0.dev0` in artefact filenames and on the index, and `pip install opf-fido`
will not select a development release unless `--pre` is passed. Tag a final
release as `2.0.0`, and set `__version__` to match, when the intent is a release
users install by default. The `metadata` job marks anything that is not exactly
`N.N.N` as a prerelease on the GitHub release.

### Rehearsing without risk

Before the first real upload:

1. Run `release.yml` manually with `workflow_dispatch` on a branch. The
   `github-release` job is skipped unless the ref is a tag, so this exercises
   the build, the packaging check and the smoke test without creating anything.
2. Point the publish step at TestPyPI and publish a prerelease tag end to end.
3. Only then add the production publisher.

### What is not automated here

jpylyzer's release workflow also builds a Debian package and Windows binaries.
Neither is reproduced for FIDO, because FIDO has no `debian/` directory, no
packaging script and no PyInstaller specification, so there is nothing to drive.
Adding them is possible but is a separate piece of work, and a PyInstaller build
would need to bundle the several megabytes of signature data in `fido/conf`
explicitly.

### Checklist for a release

- [ ] `__version__` in `fido/__init__.py` is the version being released
- [ ] `RELEASENOTES.md` has an entry for it
- [ ] The test suite passes on the supported Python versions
- [ ] `git tag <version>` matches `__version__` exactly, then push the tag
- [ ] `release.yml` is green, including the smoke test on all three platforms
- [ ] The draft release carries both the sdist and the wheel
- [ ] Release notes written, then publish the release
- [ ] `publish-pypi.yml` is green and the version appears on PyPI
