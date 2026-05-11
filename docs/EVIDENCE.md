# Independent verification recipes

> The kaos-compliance dashboard makes specific claims about every
> 273v/kaos-* package. This document is the recipe book for how a
> third party can verify each claim WITHOUT trusting the dashboard.
> Every recipe uses public sources only and reproduces in <30s with
> stock CLI tooling.

If a claim on the dashboard doesn't have a recipe here, that's a
documentation bug — please file an issue.

## Verifying a release came from a specific workflow at a specific commit (PEP 740)

The dashboard's headline trust claim: every PyPI release on a tracked
package was published by a specific GitHub Actions workflow at a
specific commit. To verify independently:

```bash
PKG=kaos-graph
VER=0.1.0a3

# Pull the simple-index detail page (PEP 691 JSON form)
curl -sH 'Accept: application/vnd.pypi.simple.v1+json' \
  "https://pypi.org/simple/${PKG}/" \
  | jq -r --arg v "$VER" '.files[] | select(.filename | contains($v)) | .provenance' \
  | head -1
```

The output is the URL of a sigstore DSSE bundle. Fetch it:

```bash
PROVENANCE_URL=$(curl -sH 'Accept: application/vnd.pypi.simple.v1+json' \
  "https://pypi.org/simple/${PKG}/" \
  | jq -r --arg v "$VER" '.files[] | select(.filename | contains($v)) | .provenance' \
  | head -1)

curl -sL "$PROVENANCE_URL" | jq '.publisher'
```

You'll see:

```json
{
  "kind": "GitHub",
  "repository": "273v/kaos-graph",
  "workflow": "release.yml",
  "environment": "pypi"
}
```

The Rekor log index from the dashboard ties this back to the public
transparency log:

```bash
REKOR_INDEX=$(jq -r '.modules[] | select(.name=="'"$PKG"'") | .supply_chain.attestations.rekor_log_index' \
  <(curl -s https://273v.github.io/kaos-compliance/api/v1/snapshot.json))

curl -s "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=${REKOR_INDEX}"
```

Match the log entry's payload SHA against the wheel SHA from PyPI; if
they match, the wheel on PyPI is byte-identical to what the workflow
emitted at sign time. This closes the build-to-publish chain
verifiably and does not require trusting either 273V or this
dashboard.

## Verifying a workflow run actually ran (CI / Security)

Every "Build / Tests / Security" pill on the dashboard links to its
underlying GitHub Actions run. To verify the run actually ran and
concluded as claimed:

```bash
PKG=kaos-core
RUN_ID=$(jq -r '.modules[] | select(.name=="'"$PKG"'") | .ci.workflow_run_id' \
  <(curl -s https://273v.github.io/kaos-compliance/api/v1/snapshot.json))

gh api "repos/273v/${PKG}/actions/runs/${RUN_ID}" --jq '{name, status, conclusion, head_sha, created_at, html_url}'
```

The dashboard's claim is unfalsifiable without a `gh api` round-trip,
which is why every pill is an anchor.

## Verifying the SBOM matches the wheel

```bash
PKG=kaos-graph
VER=0.1.0a3

# Get the SBOM from the dashboard
curl -s "https://273v.github.io/kaos-compliance/api/v1/sbom/${PKG}-${VER}.cdx.json" -o sbom.json

# Verify it's valid CycloneDX 1.5
jq -e '.bomFormat == "CycloneDX" and .specVersion == "1.5"' sbom.json

# Cross-check component count against the snapshot's claim
SNAP_COUNT=$(jq '.modules[] | select(.name=="'"$PKG"'") | .supply_chain.sbom.components_count' \
  <(curl -s https://273v.github.io/kaos-compliance/api/v1/snapshot.json))
SBOM_COUNT=$(jq '.components | length' sbom.json)
[ "$SNAP_COUNT" -eq "$SBOM_COUNT" ] && echo "match" || echo "DIFFERS"
```

## Verifying license claims (per-component)

Pick any component flagged as an approved exception on the policy
page (`/license-policy.html`), then verify the upstream license:

```bash
# Pull the policy + the upstream license
COMPONENT=certifi
curl -s "https://pypi.org/pypi/${COMPONENT}/json" \
  | jq -r '.info | {license_expression, license, classifiers}'
```

Match against `policy/license-allowlist.yaml` and the
`docs/LICENSE-AUDIT.md` audit row. If the upstream license is anything
other than what the policy claims, the dashboard is wrong and we want
to know.

## Verifying governance signals

DCO sign-off rate is a count of `Signed-off-by:` trailers in the last
90 days of commits:

```bash
PKG=kaos-core

# Count commits in the 90-day window
gh api "repos/273v/${PKG}/commits?since=$(date -u -d '90 days ago' +%Y-%m-%dT%H:%M:%SZ)&per_page=100" --paginate \
  | jq -r '.[] | .commit.message' \
  | awk 'BEGIN{total=0;signed=0} /^Signed-off-by:/{signed++} {if(/^[a-z]+:|^Merge /) total++} END{print signed/total}'
```

(Approximate — the dashboard's collector handles edge cases like
multi-line subjects.) Compare against the snapshot's
`governance.dco_signoff_rate_90d`.

Branch protection state:

```bash
gh api "repos/273v/${PKG}/branches/main/protection" --jq '.required_pull_request_reviews // "not protected"'
```

Compare against the snapshot's `governance.branch_protection_enabled`.

## Verifying the dashboard hasn't been tampered with

The snapshot itself should be signed at publication time (this is
issue R4 / H in the audit punch list; pending). Until that lands, the
strongest integrity check available is:

```bash
# Pull the snapshot and the git commit that produced it
SNAP_SHA=$(curl -sI https://273v.github.io/kaos-compliance/api/v1/snapshot.json | grep -i etag)
GH_PAGES_SHA=$(gh api repos/273v/kaos-compliance/branches/gh-pages --jq '.commit.sha')

# The gh-pages branch is force-pushed on every deploy, so the commit
# tip equals the deployed content. The commit history of gh-pages is
# the public audit trail.
gh api "repos/273v/kaos-compliance/commits/${GH_PAGES_SHA}" --jq '{sha, commit: {author, message}}'
```

Once snapshot signing lands, the recipe becomes:

```bash
curl -sL https://273v.github.io/kaos-compliance/api/v1/snapshot.sig \
  | cosign verify-blob \
    --signature - \
    --identity-regex 'https://github\.com/273v/kaos-compliance/.+' \
    --oidc-issuer 'https://token\.actions\.githubusercontent\.com' \
    https://273v.github.io/kaos-compliance/api/v1/snapshot.json
```

## Reporting a verification failure

If any of the recipes above produces output that contradicts a
dashboard claim:

1. File an issue at <https://github.com/273v/kaos-compliance/issues>
   with the recipe you ran, the output you got, and the dashboard
   page that claimed otherwise.
2. The dashboard's `SECURITY.md` covers vulnerabilities; methodology
   discrepancies are issue-track items.

Verification failures are the most valuable issue type this repo can
receive. They are the test of whether the dashboard's claims hold.

---

*Last updated: 2026-05-11.*
