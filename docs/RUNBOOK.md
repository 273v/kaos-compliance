# Runbook

> What to do when something goes wrong with the kaos-compliance
> dashboard. The audience is whoever's on call (currently
> @mjbommar; @jillbomm as secondary per CODEOWNERS).

If you're reading this because the dashboard footer says "stale," skip
to **Stale heartbeat** below.

## Component map

```
                  ┌──────────────────────────────────────┐
                  │   GitHub Actions cron workflows      │
                  │  (in 273v/kaos-compliance)           │
                  │                                       │
                  │  sweep.yml - profile=light    (1h)   │
                  │  sweep.yml - profile=security (4h)   │
                  │  sweep.yml - profile=full     (24h)  │
                  └────────────────┬─────────────────────┘
                                   │ writes
                                   ▼
                  ┌──────────────────────────────────────┐
                  │  collector/ (Python)                 │
                  │  → api/v1/snapshot.json              │
                  │  → api/v1/sbom/*.cdx.json            │
                  │  → heartbeat.json                    │
                  └────────────────┬─────────────────────┘
                                   │ feeds
                                   ▼
                  ┌──────────────────────────────────────┐
                  │  render/ (Python + Jinja2)           │
                  │  → 7 static HTML pages               │
                  │  → mirrored JSON endpoints           │
                  └────────────────┬─────────────────────┘
                                   │ pushed force to gh-pages branch
                                   ▼
                  ┌──────────────────────────────────────┐
                  │  GitHub Pages                        │
                  │  273v.github.io/kaos-compliance/     │
                  └──────────────────────────────────────┘
```

## On-call decision tree

### Symptom: dashboard footer says "STALE — last full sweep > 26h ago"

1. Check the most recent run of `sweep.yml`:
   ```bash
   gh run list --workflow=Sweep --limit=5 --repo 273v/kaos-compliance
   ```
2. If the run **failed**: open it, find the failing job, scroll to the
   step that broke. Common failures:
   - `gh api … 403 rate-limit exceeded` — see "Rate limit hit" below.
   - `pypi.org timed out` — usually transient; re-run with
     `gh workflow run sweep.yml -f profile=full --repo 273v/kaos-compliance`.
   - `LLM API key missing` — diary section only; rest of sweep should
     still publish. If everything else also fails, the runner doesn't
     have secrets; check `Settings → Secrets`.
3. If the run **succeeded but gh-pages didn't update**: the deploy step
   at the tail of the workflow swaps to `gh-pages` and force-pushes.
   Check that the swap didn't silently fail (the script aborts on `set
   -e` but earlier versions didn't — verify by inspecting recent
   gh-pages commits: `gh api repos/273v/kaos-compliance/commits?sha=gh-pages --jq '.[0].commit.committer.date'`).
4. If nothing has run at all in 26h: cron may be paused. GitHub
   auto-disables crons in repos that have had no commits for 60 days.
   A no-op commit to `main` re-arms it.

### Symptom: a specific package shows `ERR` in a pill

1. Open the per-package detail page (`/packages/<name>.html`).
2. The `errors[]` array at the bottom lists what failed.
3. Most common: GitHub Actions API throttling — runs that ranked 6+ in
   the page get truncated. Fix by widening the per_page cap in
   `collector/ci.py`.
4. If `ERR` is persistent across multiple sweeps for one package only,
   that package's GH Actions are probably misconfigured. Cross-check
   `gh api repos/273v/<name>/actions/workflows`.

### Symptom: rate limit hit

GitHub's authenticated REST limit is 5000 req/h. A full sweep across 16
repos uses ~700-1200 requests. If we hit the limit, the collector's
exponential-backoff (in `collector/retry.py`) will sleep 6× the rate
limit headers' `retry-after`.

If a sweep was killed entirely:

1. Check current limit headroom:
   ```bash
   gh api rate_limit --jq '.resources.core'
   ```
2. If `remaining < 200`, wait the window or use a different PAT with
   higher quota.
3. If `remaining > 4000` but the sweep still died, the issue is GH's
   secondary rate limit (concurrent requests); reduce concurrency in
   `collector/snapshot.py` (`MAX_INFLIGHT = 8` → `4`).

### Symptom: a renderer template broke

The deploy step pre-flights `render/__main__.py` before swapping
branches. If the renderer crashes mid-sweep, the previous gh-pages
contents remain — site stays up but stale.

1. Reproduce locally:
   ```bash
   cd /home/mjbommar/projects/273v/kaos-compliance
   uv run python -m render --snapshot api/v1/snapshot.json --out /tmp/site
   ```
2. The traceback names the template + line. Fix in
   `render/templates/<file>.j2`.
3. Push a fix, then trigger `sweep.yml` with `profile=full` manually.

### Symptom: license policy classifies a known-good component as a violation

1. Open `policy/license-allowlist.yaml`.
2. If the component is missing from `approved_expressions` /
   `parser_gaps`, add it with `audit_ref` + `rationale` (rationale is
   *public* — keep it accurate).
3. Cross-reference `docs/LICENSE-AUDIT.md` Section A or B and add a
   row.
4. Re-run the renderer; the per-package view + `/license-policy.html`
   should now classify it correctly.

### Symptom: snapshot deploy pushed to wrong branch (e.g., main)

Has happened once. Symptom: surprise commit on main containing
rendered HTML.

1. Revert the bad commit on main:
   ```bash
   git revert <sha> && git push origin main
   ```
2. Audit `scripts/deploy.sh` for the `git checkout gh-pages` failure
   mode that doesn't abort the script. The current version
   stashes-before-checkout and aborts on checkout failure.

## Manual operations

### Manually trigger a sweep

```bash
gh workflow run sweep.yml -f profile=full --repo 273v/kaos-compliance
gh workflow run sweep.yml -f profile=light --repo 273v/kaos-compliance
gh workflow run sweep.yml -f profile=security --repo 273v/kaos-compliance
```

### Re-deploy from latest snapshot without re-collecting

If gh-pages broke but the snapshot is fine:

```bash
gh workflow run sweep.yml -f profile=light --repo 273v/kaos-compliance
```

There is no deploy-only workflow at the moment. Re-running the light
profile is the lowest-cost rebuild+deploy path.

### Audit public-PR hardening settings

Several hardening controls are important but not public dashboard
signals because GitHub exposes them through admin-only APIs. Audit them
after repo creation, after changing branch protection, and during the
quarterly maintenance pass:

```bash
repos=$(jq -r '.modules[].name' data/snapshots/latest.json; echo kaos-compliance | sort -u)

for repo in $repos; do
  echo "== $repo =="
  gh api "repos/273v/$repo/actions/permissions" \
    --jq '{allowed_actions, sha_pinning_required}'
  gh api "repos/273v/$repo/actions/permissions/workflow" \
    --jq '{default_workflow_permissions, can_approve_pull_request_reviews}'
  gh api "repos/273v/$repo/actions/permissions/fork-pr-contributor-approval" \
    --jq .
  gh api "repos/273v/$repo/branches/main/protection" \
    --jq '{required_status_checks, required_pull_request_reviews, enforce_admins, required_linear_history}'
  gh api "repos/273v/$repo" \
    --jq '.security_and_analysis | {secret_scanning, secret_scanning_push_protection}'
done
```

Expected baseline: selected Actions, full-SHA pinning required,
read-only default workflow token, Actions token cannot approve PRs,
fork approval for all external contributors, CODEOWNER review and
last-push approval on `main`, admin enforcement on, linear history on,
secret scanning enabled, and push protection enabled.

For `kaos-compliance`, also confirm `.github/workflows/ci.yml` keeps
the external-fork guard on every job:

```yaml
if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
```

GitHub does not allow disabling forks on an org-owned public repository,
so this workflow guard and the contribution policy are the enforcement
layer for "do not execute external fork PR code" in this repo.

### Roll back gh-pages to N runs ago

```bash
# Find the commit to roll back to
gh api repos/273v/kaos-compliance/commits?sha=gh-pages --jq '.[].sha' | head -5

# Force-push gh-pages to that commit (DESTRUCTIVE — confirm first)
git push origin <commit-sha>:gh-pages --force
```

### Add a new package to the dashboard

1. Confirm it's a public repo under `273v/` matching `kaos-*`.
2. `collector/snapshot.py:discover_public_kaos_repos` auto-discovers
   public repos on next sweep — no code change needed.
3. To exclude a repo: add its name to `EXCLUDED_REPOS` in the same
   function.

## Escalation

| Severity | Definition | Action |
|---|---|---|
| P0 | Dashboard shows incorrect security claim (false-green pill). | Page @mjbommar immediately. Take dashboard offline if needed: `gh api -X DELETE repos/273v/kaos-compliance/pages` then re-deploy after fix. |
| P1 | Dashboard is stale > 48h or shows widespread `ERR`. | Page @mjbommar within 4h. |
| P2 | Single package shows `ERR` or visual rendering bug. | File an issue; fix in next sweep cycle. |
| P3 | Wording / methodology nits, broken external links. | File an issue, batch into next docs pass. |

Reporting channel: <https://github.com/273v/kaos-compliance/issues>.
For security-sensitive reports, see `SECURITY.md`.

## Periodic maintenance (not on-call)

- **Quarterly**: walk through `docs/LICENSE-AUDIT.md`, re-confirm each
  exception is still warranted.
- **Quarterly**: run the public-PR hardening audit above across every
  public repo in the dashboard plus `kaos-compliance`.
- **Quarterly**: rotate the GitHub Actions secrets used by the
  collector (LLM keys, any non-default PATs).
- **Quarterly**: run `scripts/verify-links.sh` to catch dead anchors
  on the dashboard.
- **Annually**: refresh the methodology doc against any framework
  bumps (OpenSSF Scorecard, SLSA, NIST SSDF, CISA SBOM).

---

*Last updated: 2026-05-12.*
