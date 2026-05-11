# Data model

> Schema documentation for `api/v1/snapshot.json` — the source-of-truth
> JSON the dashboard renders from. This document is the contract every
> consumer (renderer, downstream ingest tooling, automated audit
> scripts) is allowed to assume.
>
> A machine-readable JSON Schema lives at
> `api/v1/snapshot.schema.json` (published alongside the snapshot).
> This document is the human-readable mirror.

## Top-level shape

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-05-11T16:00:00Z",
  "generator": {"name": "kaos-compliance", "version": "0.0.1"},
  "heartbeat": {
    "last_full_sweep_at": "2026-05-11T00:00:00Z",
    "last_light_sweep_at": "2026-05-11T16:00:00Z",
    "last_security_sweep_at": "2026-05-11T12:00:00Z",
    "stale_threshold_hours": 26
  },
  "modules": [ /* per-package snapshot rows */ ]
}
```

### `schema_version`

Semantic version of this schema. Breaking changes bump the major
component and document the migration in `CHANGELOG.md`. Consumers
should check this and fail fast on unknown majors.

### `generated_at`

RFC 3339 UTC timestamp at the moment the collector started the sweep.
A snapshot is consistent within itself but slightly lagged across
sections (the snapshot's CI section was queried slightly before its
governance section). Treat the timestamp as a lower bound on freshness.

### `generator`

The producer of the snapshot. `name` is always `"kaos-compliance"`;
`version` matches `collector/__init__.py:__version__`.

### `heartbeat`

The watchdog block. Three timestamps (one per cron cadence) plus a
staleness threshold. When the dashboard's footer/header renders the
heartbeat block, it uses this to decide whether to red-flag the page
as stale. The methodology document calls this out under "Stale data is
loudly marked stale."

| Field | Meaning |
|---|---|
| `last_full_sweep_at` | Last 24h-cron sweep completion (full supply-chain + governance + LLM diary). |
| `last_light_sweep_at` | Last hourly light sweep (CI / Security / open-PR refresh only). |
| `last_security_sweep_at` | Last 4h security cron (advisory + attestation refresh). |
| `stale_threshold_hours` | If `now - last_full_sweep_at > stale_threshold_hours`, the dashboard flags itself stale. |

## `modules[]` — per-package row

Every public 273v/kaos-* repo (except `kaos-compliance` itself) gets
one entry. The keys are stable; the values can be `null` when a
section's collector failed (see `errors`).

```json
{
  "name": "kaos-core",
  "identity": { ... },
  "ci": { ... },
  "security": { ... },
  "open_prs": { ... },
  "freshness": { ... },
  "supply_chain": { ... },
  "governance": { ... },
  "code_metrics": { ... },
  "errors": []
}
```

### `name`

Repository name without org prefix (`kaos-core`, not `273v/kaos-core`).

### `identity`

```json
{
  "pypi_version": "0.1.0a5",
  "pypi_url": "https://pypi.org/project/kaos-core/0.1.0a5/",
  "main_head_sha": "de34304…",
  "latest_tag": "v0.1.0a5",
  "latest_tag_sha": "de34304…",
  "tag_at_head": true,
  "commits_past_tag": 0,
  "repo_visibility": "public",
  "last_commit_at": "2026-05-11T01:57:49Z"
}
```

- `pypi_version`: latest published PyPI version. `null` if the package
  has never published or PyPI returned 404.
- `tag_at_head`: `true` iff `latest_tag_sha == main_head_sha`.
- `repo_visibility`: `"public"` for the 16 tracked repos.

### `ci`

```json
{
  "workflow_conclusion": "success",
  "workflow_run_id": 12345678,
  "workflow_run_url": "https://github.com/273v/kaos-core/actions/runs/12345678",
  "head_sha": "de34304…",
  "run_completed_at": "2026-05-11T01:00:00Z",
  "matrix": [
    {
      "name": "Test (linux-x64 / Python 3.13)",
      "conclusion": "success",
      "status": "completed",
      "started_at": "2026-05-11T00:55:00Z",
      "completed_at": "2026-05-11T00:56:00Z",
      "duration_seconds": 60
    }
  ]
}
```

- `workflow_conclusion`: one of `success | failure | cancelled | timed_out | action_required | null`.
- `matrix[]`: every job in the latest CI run. The renderer parses
  `name` to derive (os, python) cells.

### `security`

Same shape as `ci` but for the `Security` workflow. Each `jobs[]`
entry corresponds to one scanner (`gitleaks`, `bandit`, `vulture`,
`pip-audit`, `cargo-audit`, `cargo-deny` — depending on the repo).

### `open_prs`

```json
{
  "count": 2,
  "titles": ["#42 feat: …", "#43 fix: …"]
}
```

`count` is `null` when the `gh pr list` call failed after retries.
The dashboard's "open PRs: N" indicator distinguishes `null` (lookup
failed — show `ERR`) from `0` (truly no open PRs).

### `freshness`

```json
{
  "days_since_last_commit": 0,
  "days_since_last_release": 1,
  "days_since_last_security_scan": 0
}
```

All values are non-negative ints or `null`.

### `supply_chain`

The PEP 740 + SBOM section. Schema:

```json
{
  "pypi_version": "0.1.0a3",
  "pypi_release_iso": "2026-05-10T08:34:02Z",
  "wheel_platforms": [
    "macos-arm64",
    "linux-aarch64-manylinux_2_28",
    "linux-x86_64-manylinux_2_28",
    "win-amd64",
    "win-arm64"
  ],
  "wheel_sha256s": {
    "kaos_graph-0.1.0a3-cp313-abi3-macosx_11_0_arm64.whl": "abc123…"
  },
  "is_abi3": true,
  "has_musllinux_wheel": false,
  "license_expression": "Apache-2.0",
  "license_files_in_wheel": ["LICENSE", "NOTICE"],
  "attestations": {
    "pep740_present": true,
    "publisher_kind": "GitHub",
    "publisher_source_repo": "273v/kaos-graph",
    "publisher_workflow_ref": "release.yml@pypi",
    "rekor_log_index": 1501440071,
    "verified_count": 6,
    "total_count": 6
  },
  "sbom": {
    "components_count": 80,
    "license_breakdown": {"Apache-2.0": 24, "MIT": 12, …},
    "weak_copyleft": ["certifi"],
    "strong_copyleft": [],
    "unknown_license": ["target-lexicon", …],
    "sbom_artifact_path": "data/sbom/kaos-graph-0.1.0a3.cdx.json"
  },
  "errors": []
}
```

### `governance`

```json
{
  "dco_signoff_rate_90d": 0.703,
  "conventional_commits_rate_90d": 0.838,
  "verified_commit_ratio_90d": 0.108,
  "commits_90d": 37,
  "unique_committers_90d": 1,
  "branch_protection_enabled": false,
  "branch_protection_summary": {},
  "codeowners_path": ".github/CODEOWNERS",
  "security_md_present": true,
  "security_md_disclosure_window_days": 90,
  "notice_present": true,
  "license_files_in_sdist": ["LICENSE", "NOTICE"],
  "releases_90d": 5,
  "median_pr_age_days": null,
  "open_pr_count": 0,
  "open_issue_count": 0,
  "time_to_pypi_seconds_median": 55,
  "errors": []
}
```

Rate fields are floats in `[0.0, 1.0]`. Count fields are non-negative
ints. `null` means the lookup failed after retries OR the input set
was empty (e.g., `median_pr_age_days` is `null` when no PRs were open
during the window).

### `code_metrics`

```json
{
  "python": {
    "src_loc": 6943,
    "tests_loc": 5241,
    "src_files": 90,
    "tests_files": 44
  },
  "rust": {
    "src_loc": 0,
    "tests_loc": 0,
    "src_files": 0,
    "tests_files": 0
  },
  "errors": []
}
```

Source-lines-of-code (sloc), counted non-blank + non-comment + skipping
Python docstrings and Rust block comments. Excludes generated dirs
(`.venv`, `target`, `dist`, `build`, `__pycache__`, `_site`,
`site-packages`, `.pytest_cache`, `.ruff_cache`, `.ty_cache`) and
lockfiles.

### `errors`

A flat list of `"<section>: <message>"` strings collected during the
sweep. The dashboard surfaces these on the per-package detail page so
gaps are visible.

## Schema-stability commitments

1. **Renaming or removing a top-level key bumps the major `schema_version`.**
2. **Adding a new optional key is a minor bump.** Consumers MUST tolerate
   unknown keys (forward-compatibility).
3. **Changing the semantics of a value without renaming the key is a major bump.**
   The methodology document is the authoritative semantics; CI fails
   if either drifts without a versioning entry in `CHANGELOG.md`.
4. **Timestamps are always RFC 3339 UTC with the literal `Z` suffix.**
5. **Numeric fields are always non-negative.** Use `null` for honest gaps
   never `-1` or `0` sentinels.

## Verifying a snapshot independently

```bash
# Pull the live snapshot
curl -s https://273v.github.io/kaos-compliance/api/v1/snapshot.json -o snap.json

# Validate against the JSON Schema (requires jsonschema CLI)
curl -s https://273v.github.io/kaos-compliance/api/v1/snapshot.schema.json -o schema.json
jsonschema -i snap.json schema.json

# Spot-check the PEP 740 attestation for one package
python3 -c "
import json
d = json.load(open('snap.json'))
for m in d['modules']:
    a = (m.get('supply_chain') or {}).get('attestations') or {}
    if a.get('pep740_present'):
        print(f\"{m['name']}: Rekor log #{a['rekor_log_index']}\")
" | head -5
```

---

*Schema version 1.0 — initial draft, 2026-05-11.*
