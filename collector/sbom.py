"""Lockfile parser and CycloneDX 1.5 SBOM emitter for kaos-* packages.

Stdlib only. No `cyclonedx-python-lib` dependency. Target: CycloneDX 1.5
JSON schema (https://cyclonedx.org/docs/1.5/json/) satisfying the
CISA Minimum Elements for an SBOM.

Module surface
--------------

- :class:`Component` --- normalized in-memory record (Python or Rust crate).
- :func:`parse_uv_lock` --- parse a ``uv.lock`` TOML file (uv >=0.4, lockfile
  format version 1 with revision >=3).
- :func:`parse_cargo_lock` --- parse a ``Cargo.lock`` TOML file (format
  versions 3 and 4).
- :func:`enrich_from_pypi` --- fill license/supplier from PyPI JSON, using a
  caller-supplied retry-aware HTTP helper (``gh_run``-style callable).
- :func:`normalize_license` --- collapse common license-string variants to
  SPDX expressions valid against SPDX License List 3.24.
- :func:`to_cyclonedx_1_5` --- shape components into a CycloneDX 1.5 JSON
  envelope ready for :func:`json.dump`.

The module is intentionally synchronous, deterministic, and easy to unit-test
with fixture lockfiles. Network access happens only in
:func:`enrich_from_pypi`, and only via the injected ``gh_run`` callable so
tests can stub it.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
import tomllib
import urllib.parse
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

__all__ = [
    "Component",
    "Hash",
    "HttpFetcher",
    "enrich_from_pypi",
    "license_class",
    "normalize_license",
    "parse_cargo_lock",
    "parse_uv_lock",
    "to_cyclonedx_1_5",
]

# ---------------------------------------------------------------------------
# SPDX License List 3.24 -- canonical IDs we emit. Authoritative source:
# https://spdx.org/licenses/  (June 2024 snapshot).
# ---------------------------------------------------------------------------

_SPDX_3_24_CANONICAL: frozenset[str] = frozenset(
    {
        "0BSD",
        "AGPL-3.0-only",
        "AGPL-3.0-or-later",
        "Apache-1.1",
        "Apache-2.0",
        "Artistic-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSD-3-Clause-Clear",
        "BSL-1.0",
        "BUSL-1.1",
        "CC-BY-3.0",
        "CC-BY-4.0",
        "CC-BY-NC-3.0",
        "CC-BY-NC-4.0",
        "CC-BY-ND-4.0",
        "CC-BY-SA-3.0",
        "CC-BY-SA-4.0",
        "CC0-1.0",
        "EPL-1.0",
        "EPL-2.0",
        "Elastic-2.0",
        "GPL-2.0-only",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "LGPL-2.1-only",
        "LGPL-2.1-or-later",
        "LGPL-3.0-only",
        "LGPL-3.0-or-later",
        "MIT",
        "MIT-0",
        "MIT-CMU",
        "MPL-1.1",
        "MPL-2.0",
        # Unicode license family — added to SPDX in v3.20+ (Unicode-DFS)
        # and v3.24+ (Unicode-3.0). Used by every icu_* and yoke/zerovec
        # crate in the ICU4X / Bytecode-Alliance ecosystem.
        "Unicode-3.0",
        "Unicode-DFS-2015",
        "Unicode-DFS-2016",
        "Unicode-TOU",
        "OFL-1.1",
        "PSF-2.0",
        "Python-2.0",
        "SSPL-1.0",
        "Unlicense",
        "WTFPL",
        "Zlib",
    }
)

#: Folds 40+ common license-string variants (from PyPI Trove classifiers,
#: ``setup.py`` ``license=`` free text, and Cargo manifests) to canonical
#: SPDX IDs. Keys are lowercased / stripped before lookup -- callers should
#: go through :func:`normalize_license` rather than touching this dict.
_LICENSE_ALIASES: dict[str, str] = {
    # Apache family
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "asl2.0": "Apache-2.0",
    "license: apache": "Apache-2.0",
    # MIT family
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "expat": "MIT",
    "expat license": "MIT",
    "mit-cmu": "MIT-CMU",
    "hpnd": "MIT-CMU",  # pillow historically uses HPND-derived MIT-CMU
    "hpnd license": "MIT-CMU",
    "mit-0": "MIT-0",
    # BSD family
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause",
    "freebsd": "BSD-2-Clause",
    "0bsd": "0BSD",
    # Python / PSF
    "psf": "Python-2.0",
    "psf-2.0": "PSF-2.0",
    "psfl": "Python-2.0",
    "python": "Python-2.0",
    "python software foundation license": "Python-2.0",
    "python-2.0": "Python-2.0",
    # ISC / MPL / EPL / Zlib / Unlicense / WTFPL / Boost
    "isc": "ISC",
    "isc license": "ISC",
    "mpl": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "epl-2.0": "EPL-2.0",
    "zlib": "Zlib",
    "zlib/libpng": "Zlib",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "wtfpl": "WTFPL",
    "bsl-1.0": "BSL-1.0",
    "boost software license 1.0": "BSL-1.0",
    "cc0": "CC0-1.0",
    "cc0-1.0": "CC0-1.0",
    # Copyleft (flagged elsewhere, but still normalized)
    "gpl": "GPL-3.0-or-later",
    "gpl-2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gplv2": "GPL-2.0-only",
    "gplv2+": "GPL-2.0-or-later",
    "gpl-3": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gplv3": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later",
    "lgpl": "LGPL-3.0-or-later",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgplv3": "LGPL-3.0-only",
    "agpl": "AGPL-3.0-or-later",
    "agpl-3.0": "AGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    # Source-available
    "sspl": "SSPL-1.0",
    "sspl-1.0": "SSPL-1.0",
    "busl-1.1": "BUSL-1.1",
    "elastic-2.0": "Elastic-2.0",
}

# License classes for the kaos-compliance gate.
LicenseClass = Literal[
    "permissive", "weak-copyleft", "strong-copyleft", "source-available", "unknown"
]

_LICENSE_CLASS: dict[str, LicenseClass] = {
    "0BSD": "permissive",
    "Apache-2.0": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "BSD-3-Clause-Clear": "permissive",
    "BSL-1.0": "permissive",
    "CC0-1.0": "permissive",
    "ISC": "permissive",
    "MIT": "permissive",
    "MIT-0": "permissive",
    "PSF-2.0": "permissive",
    "Python-2.0": "permissive",
    "Unlicense": "permissive",
    "WTFPL": "permissive",
    "Zlib": "permissive",
    "MPL-1.1": "weak-copyleft",
    "MPL-2.0": "weak-copyleft",
    "Unicode-3.0": "permissive",
    "Unicode-DFS-2015": "permissive",
    "Unicode-DFS-2016": "permissive",
    "Unicode-TOU": "permissive",
    "EPL-1.0": "weak-copyleft",
    "EPL-2.0": "weak-copyleft",
    "LGPL-2.1-only": "weak-copyleft",
    "LGPL-2.1-or-later": "weak-copyleft",
    "LGPL-3.0-only": "weak-copyleft",
    "LGPL-3.0-or-later": "weak-copyleft",
    "GPL-2.0-only": "strong-copyleft",
    "GPL-2.0-or-later": "strong-copyleft",
    "GPL-3.0-only": "strong-copyleft",
    "GPL-3.0-or-later": "strong-copyleft",
    "AGPL-3.0-only": "strong-copyleft",
    "AGPL-3.0-or-later": "strong-copyleft",
    "CC-BY-NC-3.0": "source-available",
    "CC-BY-NC-4.0": "source-available",
    "CC-BY-ND-4.0": "source-available",
    "SSPL-1.0": "source-available",
    "BUSL-1.1": "source-available",
    "Elastic-2.0": "source-available",
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Hash:
    """A single hash. ``alg`` follows CycloneDX naming (e.g. ``SHA-256``)."""

    alg: str
    value: str


@dataclass(slots=True)
class Component:
    """Normalized in-memory record for a single transitive dependency.

    Populated by the lockfile parsers and then enriched by
    :func:`enrich_from_pypi`. Field names mirror CycloneDX where practical.

    Attributes:
        name: Distribution name (PyPI) or crate name (Cargo).
        version: Lockfile-pinned version.
        ecosystem: ``pypi`` or ``cargo``.
        purl: Synthesized Package URL identifier.
        hashes: One or more file-level hashes from the lockfile.
        source_url: URL of the sdist or wheel used to resolve the pin.
        license_hint_from_metadata: Raw license string from the lockfile
            (Cargo carries ``license = ...``; uv.lock does not, so this is
            ``None`` for PyPI deps until :func:`enrich_from_pypi` fills it).
        license_spdx: Normalized SPDX expression, set by
            :func:`enrich_from_pypi` or :func:`normalize_license`.
        supplier: Free-text supplier name (CISA Minimum Element).
        dependencies: Names of the component's direct dependencies; markers
            are stripped (we record the union, not the per-marker subset).
        dist_url: URL the dashboard should link to for the component page.
        is_root: True only for the package being SBOM'd (e.g. ``kaos-core``
            itself); never enriched, no supplier lookup.
    """

    name: str
    version: str
    ecosystem: Literal["pypi", "cargo"]
    purl: str
    hashes: list[Hash] = field(default_factory=list)
    source_url: str | None = None
    license_hint_from_metadata: str | None = None
    license_spdx: str | None = None
    supplier: str | None = None
    dependencies: list[str] = field(default_factory=list)
    dist_url: str | None = None
    is_root: bool = False


# ---------------------------------------------------------------------------
# License normalization
# ---------------------------------------------------------------------------

_TROVE_PREFIX = "License :: OSI Approved :: "
_TROVE_PREFIX_LOOSE = "License ::"


def normalize_license(raw: str | None) -> str:
    """Fold a raw license string to a canonical SPDX expression.

    The function is conservative: it returns SPDX expressions from
    SPDX License List 3.24 when it can, and a ``LicenseRef-unknown-*``
    expression keyed on the SHA1 of the input otherwise. Returning
    ``LicenseRef-*`` (rather than the literal ``"unknown"``) keeps the
    CycloneDX output round-trippable through SPDX export.

    Args:
        raw: A license-like string from any source -- PyPI metadata, a
            Cargo manifest, a Trove classifier, or ``None``.

    Returns:
        A string that is either (a) in :data:`_SPDX_3_24_CANONICAL`, (b) a
        valid SPDX compound expression like ``"MIT OR Apache-2.0"``, or (c) a
        ``LicenseRef-unknown-<hash>`` placeholder.
    """
    if not raw:
        return _unknown_ref("")
    s = raw.strip()
    if not s:
        return _unknown_ref("")

    # Trove classifier prefix? Strip and recurse on the tail.
    if s.startswith(_TROVE_PREFIX):
        return normalize_license(s[len(_TROVE_PREFIX) :])
    if s.startswith(_TROVE_PREFIX_LOOSE):
        return normalize_license(s.split("::")[-1])

    # Already canonical?
    if s in _SPDX_3_24_CANONICAL:
        return s

    # SPDX compound expression? Validate each ID. Accept case-insensitive
    # joiners so "BSD-3-Clause and Public-Domain" round-trips, and accept
    # license exceptions in the WITH position (e.g.,
    # "Apache-2.0 WITH LLVM-exception"). Parenthesized groupings are
    # stripped so "(MIT OR Apache-2.0) AND Unicode-3.0" parses.
    if re.search(r"\b(AND|OR|WITH)\b", s, re.IGNORECASE):
        tokens = re.split(r"\s+(?:AND|OR|WITH)\s+", s, flags=re.IGNORECASE)
        cleaned = [t.strip("() ").strip() for t in tokens]
        if all(_is_valid_spdx_token(t) for t in cleaned):
            return re.sub(
                r"\s+(and|or|with)\s+",
                lambda m: f" {m.group(1).upper()} ",
                s,
                flags=re.IGNORECASE,
            )

    folded = _LICENSE_ALIASES.get(s.lower())
    if folded:
        return folded

    # Strip parenthesized clauses like "(Apache-2.0)" / "Apache-2.0 license"
    stripped = re.sub(r"[\(\)]", "", s).strip()
    stripped = re.sub(r"\s+license$", "", stripped, flags=re.IGNORECASE).strip()
    folded = _LICENSE_ALIASES.get(stripped.lower())
    if folded:
        return folded

    # Last-ditch: text-mine the verbose copyright-blob form that many
    # PyPI packages dump into the `license` field instead of an SPDX
    # expression. Look for unambiguous marker phrases from the major
    # permissive licenses. The window is 2048 chars — wide enough that
    # SciPy / Polars / azure-* / playwright resolve while still narrow
    # enough that "BSD" only matches when the license header is present.
    head = s[:2048].lower()
    text_mined = _text_mine_license(head)
    if text_mined:
        return text_mined

    return _unknown_ref(s)


# SPDX license-exception IDs accepted in the WITH position of a
# compound expression. We hand-curate the ones that show up in our
# transitive trees today; adding more is safe and cheap.
_SPDX_EXCEPTIONS: frozenset[str] = frozenset(
    {
        "LLVM-exception",
        "Classpath-exception-2.0",
        "OpenSSL-exception",
        "GCC-exception-2.0",
        "GCC-exception-3.1",
        "Bison-exception-2.2",
        "Autoconf-exception-3.0",
        "Font-exception-2.0",
    }
)


def _is_valid_spdx_token(t: str) -> bool:
    """Token in a compound expression: SPDX ID or known exception."""
    return t in _SPDX_3_24_CANONICAL or t in _SPDX_EXCEPTIONS


# Conservative phrase → SPDX expression map for text-mining verbose
# `info.license` blobs from PyPI. Order matters: longer / more-specific
# phrases first so "Mozilla Public License Version 2.0" isn't shadowed
# by a bare "license".
_LICENSE_TEXT_MARKERS: tuple[tuple[str, str], ...] = (
    ("apache license, version 2.0", "Apache-2.0"),
    ("apache-2.0 license", "Apache-2.0"),
    ("the apache license", "Apache-2.0"),
    ("mozilla public license, version 2.0", "MPL-2.0"),
    ("mozilla public license version 2.0", "MPL-2.0"),
    ("mpl-2.0", "MPL-2.0"),
    ("gnu general public license, version 3", "GPL-3.0-or-later"),
    ("gnu general public license, version 2", "GPL-2.0-or-later"),
    ("gnu lesser general public license, version 3", "LGPL-3.0-or-later"),
    ("gnu lesser general public license, version 2", "LGPL-2.1-or-later"),
    ("gnu affero general public license", "AGPL-3.0-or-later"),
    ("the mit license", "MIT"),
    ("mit license", "MIT"),
    ("bsd 3-clause", "BSD-3-Clause"),
    ("bsd-3-clause", "BSD-3-Clause"),
    ("bsd 2-clause", "BSD-2-Clause"),
    ("bsd-2-clause", "BSD-2-Clause"),
    ("isc license", "ISC"),
    ("zlib license", "Zlib"),
    ("the unlicense", "Unlicense"),
    ("python software foundation license", "PSF-2.0"),
    ("psf license", "PSF-2.0"),
)


def _text_mine_license(head: str) -> str | None:
    """Return an SPDX expression for known license phrases, or None.

    ``head`` should already be lowercase and bounded to a small prefix
    of the input. Matches the first occurring marker phrase in the
    ordered list so a verbose ``"... MIT and Apache ..."`` blob still
    resolves to the first license-evidence marker rather than to a
    LicenseRef-unknown.
    """
    for needle, spdx in _LICENSE_TEXT_MARKERS:
        if needle in head:
            return spdx
    return None


def _unknown_ref(raw: str) -> str:
    """Return a stable ``LicenseRef-unknown-<8hex>`` token for unmappable input."""
    h = hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"LicenseRef-unknown-{h}"


def license_class(spdx: str | None) -> LicenseClass:
    """Map an SPDX expression to a kaos-compliance gate class.

    Compound expressions (``A OR B``) take the *most permissive* class
    available, since the user is permitted to pick. Compound expressions with
    ``AND`` take the *most restrictive*.
    """
    if not spdx or spdx.startswith("LicenseRef-unknown"):
        return "unknown"
    if " OR " in spdx:
        parts = [p.strip("() ") for p in spdx.split(" OR ")]
        classes = [_LICENSE_CLASS.get(p, "unknown") for p in parts]
        for c in ("permissive", "weak-copyleft", "strong-copyleft", "source-available", "unknown"):
            if c in classes:
                return c  # type: ignore[return-value]
    if " AND " in spdx:
        parts = [p.strip("() ") for p in spdx.split(" AND ")]
        classes = [_LICENSE_CLASS.get(p, "unknown") for p in parts]
        for c in ("unknown", "source-available", "strong-copyleft", "weak-copyleft", "permissive"):
            if c in classes:
                return c  # type: ignore[return-value]
    return _LICENSE_CLASS.get(spdx, "unknown")


# ---------------------------------------------------------------------------
# Lockfile parsers
# ---------------------------------------------------------------------------


def _purl_pypi(name: str, version: str) -> str:
    # PURL spec: pkg:pypi/<name>@<version>; name is normalized to lowercase
    # with hyphens collapsed, per the PURL pypi type spec.
    norm = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:pypi/{urllib.parse.quote(norm, safe='')}@{urllib.parse.quote(version, safe='')}"


def _purl_cargo(name: str, version: str) -> str:
    return f"pkg:cargo/{urllib.parse.quote(name, safe='')}@{urllib.parse.quote(version, safe='')}"


def parse_uv_lock(path: Path) -> list[Component]:
    """Parse a ``uv.lock`` file and return one :class:`Component` per pin.

    The lockfile schema we target is ``version = 1`` with ``revision >= 3``,
    which is what uv >=0.4 emits. We extract:

    * ``name``, ``version``
    * sdist URL (preferred) and its SHA-256
    * each wheel URL and its SHA-256 (we keep them all -- a single
      cross-platform SBOM may reference multiple wheel artifacts)
    * the dependency name list (markers are stripped: a dep present under
      *any* marker is treated as a dep)

    Path-source and editable packages (e.g. the package being SBOM'd itself,
    or a sibling workspace member) are returned with ``is_root=True`` and
    no ``source_url`` -- enrichment will skip them.

    Args:
        path: Filesystem path to ``uv.lock``.

    Returns:
        Components in lockfile order. Determinism is preserved so the SBOM
        is reproducible across runs on the same lockfile.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: list[Component] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        if not name:
            continue
        version = pkg.get("version", "0.0.0+unknown")
        source = pkg.get("source", {}) or {}
        is_root = "editable" in source or "virtual" in source

        hashes: list[Hash] = []
        sdist = pkg.get("sdist")
        source_url: str | None = None
        if isinstance(sdist, dict):
            source_url = sdist.get("url")
            if sdist.get("hash", "").startswith("sha256:"):
                hashes.append(Hash("SHA-256", sdist["hash"].split(":", 1)[1]))
        for w in pkg.get("wheels", []) or []:
            if not isinstance(w, dict):
                continue
            if source_url is None:
                source_url = w.get("url")
            h = w.get("hash", "")
            if h.startswith("sha256:"):
                hashes.append(Hash("SHA-256", h.split(":", 1)[1]))

        deps: list[str] = []
        for d in pkg.get("dependencies", []) or []:
            if isinstance(d, dict) and d.get("name"):
                deps.append(d["name"])
        # uv groups optional deps under [package.optional-dependencies.<extra>]
        # but we omit them: a "compliance" SBOM should describe what we
        # actually resolve, not what *could* be resolved.

        comp = Component(
            name=name,
            version=version,
            ecosystem="pypi",
            purl=_purl_pypi(name, version),
            hashes=hashes,
            source_url=source_url,
            license_hint_from_metadata=None,
            dependencies=sorted(set(deps)),
            dist_url=f"https://pypi.org/project/{name}/{version}/",
            is_root=is_root,
        )
        out.append(comp)
    return out


def parse_cargo_lock(path: Path) -> list[Component]:
    """Parse a ``Cargo.lock`` file (format v3 or v4) and return components.

    Cargo's lockfile does not record license data -- the field lives in the
    crate's ``Cargo.toml`` published manifest. We surface what we have
    (name, version, checksum, source) and leave license enrichment to a
    separate crates.io fetch (out of scope for the initial collector;
    add later as ``enrich_from_crates_io``).

    Args:
        path: Filesystem path to ``Cargo.lock``.

    Returns:
        Components in lockfile order. Path-source crates (``source`` absent)
        are marked ``is_root=True``.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out: list[Component] = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version:
            continue
        source = pkg.get("source")
        is_root = source is None
        hashes: list[Hash] = []
        if pkg.get("checksum"):
            hashes.append(Hash("SHA-256", pkg["checksum"]))
        deps_raw = pkg.get("dependencies", []) or []
        # Cargo dep entries look like "serde 1.0.0 (registry+...)"; we only
        # want the bare crate name. Versions are resolved via the [[package]]
        # table at the top level.
        deps = sorted({re.split(r"\s+", d, maxsplit=1)[0] for d in deps_raw})
        out.append(
            Component(
                name=name,
                version=version,
                ecosystem="cargo",
                purl=_purl_cargo(name, version),
                hashes=hashes,
                source_url=source if isinstance(source, str) else None,
                license_hint_from_metadata=None,
                dependencies=deps,
                dist_url=f"https://crates.io/crates/{name}/{version}",
                is_root=is_root,
            )
        )
    return out


# ---------------------------------------------------------------------------
# PyPI enrichment
# ---------------------------------------------------------------------------


class HttpFetcher(Protocol):
    """Minimal interface the retry-aware HTTP helper must satisfy.

    The collector accepts any callable shaped like the kaos-compliance
    ``gh_run`` helper: synchronous, retry-aware, returns a parsed JSON dict
    (or ``None`` on terminal failure). We do not import the helper here so
    the parser stays stdlib-only and trivially unit-testable.
    """

    def __call__(self, url: str, /) -> dict[str, Any] | None:  # pragma: no cover - protocol
        ...


def enrich_from_pypi(
    components: list[Component],
    *,
    gh_run: HttpFetcher,
) -> list[Component]:
    """Fill ``license_spdx`` and ``supplier`` on each PyPI component.

    For each component with ``ecosystem == "pypi"`` and ``is_root == False``,
    we call ``gh_run("https://pypi.org/pypi/<name>/<version>/json")``. The
    response is shaped per PEP 691 / the legacy PyPI JSON API.

    Resolution order for the SPDX license:

    1. ``info.license_expression`` (PEP 639, populated for newer releases).
    2. ``info.license`` (legacy free-text field).
    3. The first ``"License :: ..."`` Trove classifier under
       ``info.classifiers``.

    Resolution order for ``supplier`` matches the README fallback chain:
    ``info.author`` -> ``info.maintainer`` -> homepage hostname ->
    ``"Unknown / community"``.

    Args:
        components: List of components from :func:`parse_uv_lock`. Mutated
            in place *and* returned for convenience.
        gh_run: A retry-aware HTTP fetcher. Must return parsed JSON or
            ``None``.

    Returns:
        The same list, with ``license_spdx`` and ``supplier`` populated.
    """
    for c in components:
        if c.ecosystem != "pypi" or c.is_root:
            continue
        url = f"https://pypi.org/pypi/{c.name}/{c.version}/json"
        payload = gh_run(url)
        if not payload:
            c.license_spdx = normalize_license(c.license_hint_from_metadata)
            c.supplier = c.supplier or "Unknown / community"
            continue
        info = payload.get("info", {}) or {}
        raw_license = (
            info.get("license_expression")
            or info.get("license")
            or _first_trove_license(info.get("classifiers") or [])
        )
        c.license_hint_from_metadata = raw_license
        c.license_spdx = normalize_license(raw_license)
        c.supplier = _pick_supplier(info)
    return components


def enrich_from_crates_io(
    components: list[Component],
    *,
    gh_run: HttpFetcher,
) -> list[Component]:
    """Populate ``license_spdx`` + ``supplier`` for Rust components.

    Cargo.lock does not carry license metadata — the field lives in
    each crate's ``Cargo.toml`` on crates.io. Without this enrichment,
    every Rust transitive dep falls through to ``LicenseRef-unknown``,
    which is the single biggest source of yellow-pill noise on the
    dashboard.

    We query ``https://crates.io/api/v1/crates/<name>/<version>`` for
    each Rust component. The license field there is already an SPDX
    expression (Cargo enforces this at publish), so the normalization
    pass simplifies to a direct ``normalize_license`` call.

    Args:
        components: List of Component records. Mutated in place.
        gh_run: Retry-aware HTTP fetcher.

    Returns:
        Same list, with cargo components' ``license_spdx`` filled.
    """
    for c in components:
        if c.ecosystem != "cargo" or c.is_root:
            continue
        url = f"https://crates.io/api/v1/crates/{c.name}/{c.version}"
        payload = gh_run(url)
        if not payload:
            continue
        version_info = payload.get("version") or {}
        raw_license = version_info.get("license")
        if raw_license:
            c.license_hint_from_metadata = raw_license
            c.license_spdx = normalize_license(raw_license)
        # crates.io exposes a `published_by.name` field for some
        # crates; fall back to the crate's `homepage` host. Many crates
        # leave both empty, in which case we keep whatever the lockfile
        # supplier sentinel was.
        published_by = (version_info.get("published_by") or {}).get("name")
        if isinstance(published_by, str) and published_by.strip():
            c.supplier = published_by.strip()
        else:
            homepage = (payload.get("crate") or {}).get("homepage")
            if isinstance(homepage, str) and homepage:
                try:
                    host = urllib.parse.urlparse(homepage).hostname or ""
                    if host:
                        c.supplier = host.lower().removeprefix("www.")
                except ValueError:
                    pass
    return components


def _first_trove_license(classifiers: Iterable[str]) -> str | None:
    for cls in classifiers:
        if cls.startswith("License ::") and "OSI Approved" in cls:
            return cls
    for cls in classifiers:
        if cls.startswith("License ::"):
            return cls
    return None


def _pick_supplier(info: dict[str, Any]) -> str:
    for key in ("author", "maintainer"):
        v = info.get(key)
        if isinstance(v, str) and v.strip() and v.strip().upper() != "UNKNOWN":
            return v.strip()
    homepage = info.get("home_page") or (info.get("project_urls") or {}).get("Homepage")
    if isinstance(homepage, str) and homepage:
        try:
            host = urllib.parse.urlparse(homepage).hostname or ""
            if host:
                return host.lower().removeprefix("www.")
        except ValueError:
            pass
    return "Unknown / community"


# ---------------------------------------------------------------------------
# CycloneDX 1.5 emitter
# ---------------------------------------------------------------------------

_CDX_SPEC_VERSION = "1.5"
_CDX_BOM_FORMAT = "CycloneDX"


def to_cyclonedx_1_5(
    components: list[Component],
    *,
    package_name: str,
    package_version: str,
    timestamp: _dt.datetime | None = None,
    serial_number: str | None = None,
    tool_name: str = "kaos-compliance.sbom",
    tool_version: str = "0.1.0",
) -> dict[str, Any]:
    """Shape :class:`Component` records into a CycloneDX 1.5 JSON dict.

    The output passes the CISA Minimum Elements:

    * **Author of SBOM**: ``metadata.tools[]`` lists this module.
    * **Timestamp**: ``metadata.timestamp`` ISO-8601 Zulu.
    * **Supplier**: ``components[].supplier.name``.
    * **Component name / version**: ``components[].name`` / ``.version``.
    * **Unique identifier**: ``components[].purl`` + at least one
      ``components[].hashes[]`` entry.
    * **Dependency relationship**: top-level ``dependencies[]`` graph.

    Args:
        components: Output of :func:`parse_uv_lock` (optionally enriched).
        package_name: Name of the kaos package being described (the "root"
            component in CycloneDX terms).
        package_version: Version of the root component.
        timestamp: SBOM creation time; defaults to ``datetime.now(UTC)``.
        serial_number: CycloneDX ``serialNumber`` (a urn:uuid:...). A fresh
            v4 UUID is generated if omitted.
        tool_name: ``metadata.tools[0].name`` value.
        tool_version: ``metadata.tools[0].version`` value.

    Returns:
        A JSON-serializable dict ready for :func:`json.dump`.
    """
    ts = timestamp or _dt.datetime.now(tz=_dt.UTC)
    sn = serial_number or f"urn:uuid:{uuid.uuid4()}"

    # Separate the root from transitive deps. uv.lock includes the package
    # being locked as a [[package]] entry with source.editable == ".".
    transitive = [c for c in components if not c.is_root]

    cdx_components = [_component_to_cdx(c) for c in transitive]
    dependencies = _build_dependency_graph(components, package_name, package_version)

    root_purl = _purl_pypi(package_name, package_version)
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": _CDX_BOM_FORMAT,
        "specVersion": _CDX_SPEC_VERSION,
        "serialNumber": sn,
        "version": 1,
        "metadata": {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": [
                {
                    "vendor": "273 Ventures",
                    "name": tool_name,
                    "version": tool_version,
                }
            ],
            "component": {
                "type": "library",
                "bom-ref": root_purl,
                "name": package_name,
                "version": package_version,
                "purl": root_purl,
            },
        },
        "components": cdx_components,
        "dependencies": dependencies,
    }


def _component_to_cdx(c: Component) -> dict[str, Any]:
    """Convert a single :class:`Component` to a CycloneDX 1.5 ``component``."""
    out: dict[str, Any] = {
        "type": "library",
        "bom-ref": c.purl,
        "name": c.name,
        "version": c.version,
        "purl": c.purl,
    }
    if c.supplier:
        out["supplier"] = {"name": c.supplier}
    if c.hashes:
        out["hashes"] = [{"alg": h.alg, "content": h.value} for h in c.hashes]
    if c.license_spdx:
        if c.license_spdx.startswith("LicenseRef-"):
            out["licenses"] = [{"license": {"name": c.license_spdx}}]
        elif re.search(r"\b(AND|OR|WITH)\b", c.license_spdx):
            out["licenses"] = [{"expression": c.license_spdx}]
        else:
            out["licenses"] = [{"license": {"id": c.license_spdx}}]
    refs: list[dict[str, str]] = []
    if c.source_url:
        refs.append({"type": "distribution", "url": c.source_url})
    if c.dist_url:
        refs.append({"type": "website", "url": c.dist_url})
    if refs:
        out["externalReferences"] = refs
    cls = license_class(c.license_spdx)
    out["properties"] = [{"name": "kaos:license-class", "value": cls}]
    return out


def _build_dependency_graph(
    components: list[Component], root_name: str, root_version: str
) -> list[dict[str, Any]]:
    """Construct the CycloneDX 1.5 ``dependencies[]`` adjacency list.

    Each entry has ``{"ref": <bom-ref>, "dependsOn": [<bom-ref>, ...]}``.
    The root component's ``dependsOn`` lists every component whose name
    appears in the root's ``dependencies`` list (or, if the lockfile did
    not record root deps, every transitive component as a flat fallback).
    """
    by_name: dict[str, Component] = {c.name: c for c in components}
    root_purl = _purl_pypi(root_name, root_version)

    root_comp = by_name.get(root_name)
    root_deps: list[str]
    if root_comp and root_comp.dependencies:
        root_deps = [by_name[d].purl for d in root_comp.dependencies if d in by_name]
    else:
        root_deps = [c.purl for c in components if not c.is_root]

    entries: list[dict[str, Any]] = [{"ref": root_purl, "dependsOn": sorted(root_deps)}]
    for c in components:
        if c.is_root:
            continue
        depends_on = sorted(by_name[d].purl for d in c.dependencies if d in by_name)
        entries.append({"ref": c.purl, "dependsOn": depends_on})
    return entries


# ---------------------------------------------------------------------------
# Convenience: end-to-end driver used by ``sample_sbom.json`` generation.
# ---------------------------------------------------------------------------


def build_sbom_from_lockfile(
    uv_lock: Path,
    *,
    package_name: str,
    package_version: str,
    gh_run: HttpFetcher | None = None,
    cargo_lock: Path | None = None,
) -> dict[str, Any]:
    """End-to-end: parse lockfile(s), optionally enrich, emit CycloneDX dict.

    Args:
        uv_lock: Required path to a ``uv.lock``.
        package_name: Name of the kaos package being described.
        package_version: Version of the kaos package being described.
        gh_run: Optional retry-aware HTTP fetcher. If omitted, license/supplier
            are not enriched and will fall back to ``LicenseRef-unknown-*`` /
            ``Unknown / community``. This is the offline mode used by CI.
        cargo_lock: Optional path to a sibling ``Cargo.lock``.

    Returns:
        A CycloneDX 1.5 JSON-serializable dict.
    """
    components = parse_uv_lock(uv_lock)
    if cargo_lock and cargo_lock.exists():
        components.extend(parse_cargo_lock(cargo_lock))
    if gh_run is not None:
        enrich_from_pypi(components, gh_run=gh_run)
    else:
        for c in components:
            if c.ecosystem == "pypi" and not c.is_root:
                c.license_spdx = normalize_license(c.license_hint_from_metadata)
                c.supplier = c.supplier or "Unknown / community"
    return to_cyclonedx_1_5(
        components,
        package_name=package_name,
        package_version=package_version,
    )


# A lightweight built-in offline "license book" for the most common PyPI
# packages we see across kaos-*. This is *not* a substitute for live PyPI
# enrichment; it exists so that ``sample_sbom.json`` can be generated in
# CI without network and still show realistic license coverage. Update by
# hand; ``enrich_from_pypi`` always wins when run.
OFFLINE_LICENSE_BOOK: dict[str, tuple[str, str]] = {
    # name -> (spdx, supplier)
    "annotated-types": ("MIT", "Adrian Garcia Badaracco"),
    "anyio": ("MIT", "Alex Gronholm"),
    "certifi": ("MPL-2.0", "Kenneth Reitz"),
    "cffi": ("MIT", "Armin Rigo, Maciej Fijalkowski"),
    "click": ("BSD-3-Clause", "Pallets"),
    "colorama": ("BSD-3-Clause", "Jonathan Hartley"),
    "coverage": ("Apache-2.0", "Ned Batchelder and 231 others"),
    "cryptography": ("Apache-2.0 OR BSD-3-Clause", "The cryptography developers"),
    "h11": ("MIT", "Nathaniel J. Smith"),
    "httpcore": ("BSD-3-Clause", "Tom Christie"),
    "httpx": ("BSD-3-Clause", "Tom Christie"),
    "idna": ("BSD-3-Clause", "Kim Davies"),
    "iniconfig": ("MIT", "Ronny Pfannschmidt, Holger Krekel"),
    "jaraco-classes": ("MIT", "Jason R. Coombs"),
    "jaraco-context": ("MIT", "Jason R. Coombs"),
    "jaraco-functools": ("MIT", "Jason R. Coombs"),
    "jeepney": ("MIT", "Thomas Kluyver"),
    "keyring": ("MIT", "Kang Zhang, Jason R. Coombs"),
    "more-itertools": ("MIT", "Erik Rose"),
    "packaging": ("Apache-2.0 OR BSD-2-Clause", "Donald Stufft"),
    "pluggy": ("MIT", "Holger Krekel"),
    "py-cpuinfo": ("MIT", "Matthew Brennan Jones"),
    "pycparser": ("BSD-3-Clause", "Eli Bendersky"),
    "pydantic": ("MIT", "Samuel Colvin"),
    "pydantic-core": ("MIT", "Samuel Colvin"),
    "pydantic-settings": ("MIT", "Samuel Colvin"),
    "pygments": ("BSD-2-Clause", "Georg Brandl"),
    "pytest": ("MIT", "Holger Krekel et al."),
    "pytest-asyncio": ("Apache-2.0", "Tin Tvrtkovic"),
    "pytest-benchmark": ("BSD-2-Clause", "Ionel Cristian Maries"),
    "pytest-cov": ("MIT", "Marc Schlaich"),
    "python-dotenv": ("BSD-3-Clause", "Saurabh Kumar"),
    "pywin32": ("PSF-2.0", "Mark Hammond"),
    "pywin32-ctypes": ("BSD-3-Clause", "Enthought"),
    "ruff": ("MIT", "Astral Software Inc."),
    "secretstorage": ("BSD-3-Clause", "Dmitry Shachnev"),
    "ty": ("MIT", "Astral Software Inc."),
    "typing-extensions": (
        "PSF-2.0",
        "Guido van Rossum, Jukka Lehtosalo, Lukasz Langa, Michael Lee",
    ),
    "typing-inspection": ("MIT", "Pydantic Services Inc."),
}


def apply_offline_license_book(components: list[Component]) -> None:
    """Populate license + supplier from :data:`OFFLINE_LICENSE_BOOK` in place.

    Used by ``sample_sbom.json`` generation when running offline. Only fills
    fields that are still empty -- live PyPI enrichment always wins.
    """
    for c in components:
        if c.ecosystem != "pypi" or c.is_root:
            continue
        if c.license_spdx and not c.license_spdx.startswith("LicenseRef-unknown"):
            continue
        rec = OFFLINE_LICENSE_BOOK.get(c.name)
        if rec:
            c.license_spdx = normalize_license(rec[0])
            c.supplier = rec[1]
        else:
            c.license_spdx = c.license_spdx or normalize_license(None)
            c.supplier = c.supplier or "Unknown / community"


if __name__ == "__main__":  # pragma: no cover - manual driver
    import json
    import sys

    if len(sys.argv) < 4:
        print(
            "usage: python lockfile_parser.py <uv.lock> "
            "<package-name> <package-version> [cargo.lock]",
            file=sys.stderr,
        )
        sys.exit(2)
    lock = Path(sys.argv[1])
    name = sys.argv[2]
    ver = sys.argv[3]
    cargo = Path(sys.argv[4]) if len(sys.argv) > 4 else None
    comps = parse_uv_lock(lock)
    if cargo and cargo.exists():
        comps.extend(parse_cargo_lock(cargo))
    apply_offline_license_book(comps)
    sbom = to_cyclonedx_1_5(comps, package_name=name, package_version=ver)
    json.dump(sbom, sys.stdout, indent=2, sort_keys=False)
