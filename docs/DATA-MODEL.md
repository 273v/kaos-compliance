# Data model

> The dashboard's HTML is one render of `api/v1/snapshot.json`. This
> document is the prose specification of that JSON's shape. The
> machine-readable version is published at
> `api/v1/snapshot.schema.json` (JSON Schema Draft 2020-12) and is
> regenerated on every render so the two never drift.

## At a glance

```
snapshot.json
├── schema_version                      "1.0"
├── generated_at                        RFC 3339 UTC, trailing Z
├── generator                           { name, version }
├── heartbeat
│   ├── last_full_sweep_at
│   ├── last_light_sweep_at
│   ├── last_security_sweep_at
│   └── stale_threshold_hours           default 26
└── modules[]                           one per public 273v/kaos-* repo
    ├── name
    ├── identity                        IdentitySection
    ├── ci                              CISection
    ├── security                        SecuritySection
    ├── open_prs                        OpenPRsSection
    ├── freshness                       FreshnessSection
    ├── supply_chain                    dict — output of collector.supply_chain
    ├── governance                      dict — output of collector.governance
    ├── code_metrics                    dict — output of collector.code_metrics
    ├── advisories                      dict — output of collector.advisories (OSV.dev)
    └── errors[]                        per-section failure strings
```

The schema is **closed at the top level**: `additionalProperties: false`
on the root snapshot and on every dataclass-backed section. The four
dict-backed sections (`supply_chain`, `governance`, `code_metrics`,
`advisories`)
permit additional properties so collectors can add new fields without
a breaking schema bump.

## Per-section reference

### identity (`IdentitySection`)

| Field | Type | Meaning |
|---|---|---|
| `pypi_version` | `str \| null` | Latest published version on PyPI. |
| `pypi_url` | `str \| null` | Canonical project URL on pypi.org. |
| `main_head_sha` | `str \| null` | Latest commit SHA on `main`. |
| `latest_tag` | `str \| null` | Latest `v*` tag (lexicographic). |
| `latest_tag_sha` | `str \| null` | Commit SHA the tag points at. |
| `tag_at_head` | `bool \| null` | True iff the latest tag is on `main`'s HEAD. |
| `commits_past_tag` | `int \| null` | Commits since `latest_tag`. |
| `repo_visibility` | `str \| null` | `"public"` or `"private"`. |
| `last_commit_at` | `str \| null` | RFC 3339 timestamp of last commit. |

### ci (`CISection`)

Latest workflow run named `CI` on `main`. Matrix is the per-job
breakdown (one entry per `{os, python-version}` cell).

| Field | Type | Meaning |
|---|---|---|
| `workflow_conclusion` | `str \| null` | `success`, `failure`, `cancelled`, &hellip; |
| `workflow_run_id` | `int \| null` | GitHub run ID for the verify link. |
| `workflow_run_url` | `str \| null` | Direct URL to the run. |
| `head_sha` | `str \| null` | SHA the run was triggered against. |
| `run_completed_at` | `str \| null` | RFC 3339 completion timestamp. |
| `matrix[]` | `array` | Per-job dicts: `name`, `conclusion`, `status`, `started_at`, `completed_at`, `duration_seconds`. |
| `compat_conclusion` | `str \| null` | Latest `compat` run on `main` (cross-OS / preview-Python, weekly + tags). |
| `compat_run_url` / `compat_completed_at` | `str \| null` | Evidence link and completion time for that run. |
| `min_deps_conclusion` | `str \| null` | Latest `min-deps` run on `main` (suite at lowest declared versions). |
| `min_deps_run_url` / `min_deps_completed_at` | `str \| null` | Evidence link and completion time for that run. |

### security (`SecuritySection`)

`workflow_*`, `jobs[]` and `run_completed_at` describe the latest
`security-light` run (every PR / push: incremental gitleaks, bandit,
vulture). The `full_*` fields describe the latest `security-full` run
(weekly + tags: full-history gitleaks, pip-audit, cargo-audit,
cargo-deny): `full_workflow_conclusion`, `full_workflow_run_id`,
`full_workflow_run_url`, `full_jobs[]`, `full_run_completed_at`.

### open_prs (`OpenPRsSection`)

| Field | Type | Meaning |
|---|---|---|
| `count` | `int \| null` | Open PR count against `main`. `null` on lookup failure. |
| `titles[]` | `array of str` | `#<num> <title>` entries. |
| `oldest_age_days` | `int \| null` | Age of the oldest open PR; `null` when none are open. |
| `dependabot_count` | `int \| null` | Open PRs authored by Dependabot. |

### freshness (`FreshnessSection`)

| Field | Type | Meaning |
|---|---|---|
| `days_since_last_commit` | `int \| null` | Days since last commit on `main`. |
| `days_since_last_release` | `int \| null` | Days since last PyPI release. |
| `days_since_last_security_scan` | `int \| null` | Days since last `Security` run. |

### supply_chain (dict)

Emitted by `collector/supply_chain.py`. Top-level fields:

- `pypi_version`, `pypi_release_iso`, `wheel_platforms[]`, `wheel_sha256s{}`
- `is_abi3`, `has_musllinux_wheel`, `license_expression`,
  `license_files_in_wheel[]`
- `attestations{}` &mdash; `pep740_present`, `publisher_kind`,
  `publisher_source_repo`, `publisher_workflow_ref`, `rekor_log_index`,
  `verified_count`, `total_count`
- `sbom{}` &mdash; `components_count`, `license_breakdown{}`,
  `weak_copyleft[]`, `strong_copyleft[]`, `unknown_license[]`,
  `sbom_artifact_path`
- `errors[]`

The schema constrains the leaf types but accepts
`additionalProperties: true` so new fields are non-breaking.

### governance (dict)

Emitted by `collector/governance.py`. Rate fields are bounded `[0.0, 1.0]`:
`dco_signoff_rate_90d`, `conventional_commits_rate_90d`,
`verified_commit_ratio_90d`. Counts (`commits_90d`,
`unique_committers_90d`, `releases_90d`, `open_pr_count`,
`open_issue_count`) are non-negative integers or `null`.
`branch_protection_enabled`, `security_md_present`, `notice_present`
are booleans (the latter two default to `false` when no signal is
available). See the JSON Schema for the full type table.

### code_metrics (dict)

Emitted by `collector/code_metrics.py`. Shape:

```jsonc
{
  "python": { "src_loc": int|null, "tests_loc": int|null,
              "src_files": int|null, "tests_files": int|null },
  "rust":   { ...same... },
  "errors": [string, ...]
}
```

### advisories (dict)

Emitted by `collector/advisories.py`: OSV.dev advisories open against
every third-party pin in the repo's `uv.lock` and `Cargo.lock`.

```jsonc
{
  "source": "osv.dev",
  "scanned_components": int|null,   // null = scan did not run (gray, not 0)
  "open": [{"id", "aliases", "package", "version", "ecosystem",
            "severity",             // critical|high|moderate|low|unknown
            "informational",        // RustSec category, e.g. "unsound"
            "summary", "url"}],
  "notices": [ ...same row shape... ],  // RustSec unmaintained / notice; not counted
  "counts": {"critical", "high", "moderate", "low", "unknown", "total"},
  "errors": [string, ...]
}
```

## Rolling History Endpoints

`api/v1/history/YYYY-MM-DD.json` is a compact per-day projection of
`snapshot.json`. It exists only to drive trend SVGs and previous-sweep
diffs; `snapshot.json` remains the source of truth for evidence URLs and
nested detail.

Each per-module history row carries booleans for build/tests/security/
updates/attestation/branch-protection state (`*_pass` follow the pill
rules in `collector/health.py`; history schema 1.2 from 2026-09-23) plus
integer counters: `advisories_open`, `commits_90d`, `releases_90d`,
`loc_total`, `src_loc`, `tests_loc`, and `files_total`. Missing or uncollected counters are `null`.

`api/v1/history.json` is the rolling 90-day index. Arrays under
`packages.<name>.<signal>` are aligned to the top-level `dates` array.
Older per-day files that lack newer additive counters are padded with
`null`, so consumers must tolerate gaps.

## Versioning

`schema_version` is the snapshot-level version. We bump it for
**breaking** changes only:

- Removing a required field.
- Changing the type of an existing field in a way consumers can't
  tolerate (e.g. `string` &rarr; `number`).
- Reshaping a section (e.g. flattening a nested dict).

Additive changes &mdash; new optional fields, new sections under the
dict-backed collectors &mdash; are **non-breaking**; consumers MUST
tolerate them. The JSON Schema enforces this distinction
mechanically (`additionalProperties: false` on the dataclass-backed
sections, `additionalProperties: true` on the dict-backed ones).

## Schema generation contract

The JSON Schema at `api/v1/snapshot.schema.json` is produced by
`collector/schema.py` walking the dataclass annotations in
`collector/snapshot.py`. The output is deterministic: re-deriving the
schema from a checkout of any given commit yields identical bytes.
The `$comment` field carries the collector version that produced it
so consumers can pin against a specific release.

To re-derive the schema locally:

```bash
uv run python -m collector.schema --output snapshot.schema.json --pretty
```

To validate a snapshot against the schema:

```bash
uvx --from jsonschema jsonschema -i snapshot.json snapshot.schema.json
```

Both invocations are exercised by `tests/test_schema.py` in CI, so a
shape change that breaks the schema is caught before deploy.

---

*Data-model spec version 1.0 &mdash; first added 2026-05-11 alongside
R23 (publishing the JSON Schema).*
