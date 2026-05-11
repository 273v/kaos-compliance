# Evidence and verification

> Every claim the dashboard makes is reproducible by a third party
> without privileged access. This document is the index of those
> reproduction recipes. If a claim doesn't have a recipe here, treat it
> as unverified.

## Verifying the dashboard hasn't been tampered with

The dashboard's HTML pages are generated from a single JSON document,
[`api/v1/snapshot.json`](https://273v.github.io/kaos-compliance/api/v1/snapshot.json).
That JSON is signed at publish time with a **keyless sigstore
signature** issued by the kaos-compliance sweep workflow via GitHub
OIDC, and the bundle is published alongside the JSON at
`api/v1/snapshot.sig`.

A consumer who fetches the snapshot can verify two independent claims
before trusting any field on the dashboard:

1. **The bytes weren't altered after they left the runner.** The
   cosign signature covers the SHA-256 of `snapshot.json`.
2. **The bytes were produced by THIS workflow on THIS repo.** The
   Fulcio certificate that backs the signature names the workflow
   identity; consumers MUST assert the identity matches before
   trusting the chain.

### Step-by-step

```bash
# 1. Fetch the signed snapshot + its bundle.
curl -sSfo snapshot.json     https://273v.github.io/kaos-compliance/api/v1/snapshot.json
curl -sSfo snapshot.sig      https://273v.github.io/kaos-compliance/api/v1/snapshot.sig

# 2. Install cosign (skip if you already have v2.2+).
#    https://github.com/sigstore/cosign/releases  (or use the cosign-installer
#    action in your own workflow).

# 3. Verify, pinning BOTH the issuer and the workflow identity.
cosign verify-blob \
  --bundle snapshot.sig \
  --certificate-identity-regexp \
    'https://github.com/273v/kaos-compliance/\.github/workflows/sweep\.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  snapshot.json
```

A successful verification prints `Verified OK` and exits 0. Any other
result &mdash; including missing bundle, identity mismatch, or hash
mismatch &mdash; means the snapshot you have in front of you is not the
one the workflow produced. Stop and investigate before consuming any
field.

### What the signature does NOT prove

- It does **not** prove the data is *correct*; only that the bytes
  were minted by the workflow. A bug in the collector still ships
  signed bytes. Independent reproduction of the per-claim
  verification recipes (see below) is the only way to catch that.
- It does **not** prove the upstream APIs (GitHub, PyPI, OSV, Rekor)
  were honest at collection time. The dashboard inherits the trust
  posture of its inputs.
- It does **not** authenticate the maintainer machine that triggered
  the workflow. The signature ties bytes to a workflow run, not to a
  human.

### Identity contract

The expected certificate identity is:

```
https://github.com/273v/kaos-compliance/.github/workflows/sweep.yml@refs/heads/main
```

Issuer: `https://token.actions.githubusercontent.com`.

A small metadata sidecar published at `api/v1/snapshot.sig.meta.json`
echoes the run ID + git SHA + expected identity so automated
verifiers can pin their checks without parsing the workflow YAML.

### Local-only renders

When the renderer runs outside GitHub Actions (developer workstation,
CI smoke tests), there is no OIDC token available, so the signing
script is a no-op and the dashboard publishes only the JSON. The
header pill on the index page renders gray with the label
"snapshot unsigned (local render)" so the absence is visible.

## Per-claim verification recipes

See [`METHODOLOGY.md` &sect; "Verifying a claim independently"](METHODOLOGY.md#verifying-a-claim-independently)
for the link-by-link verification table covering CI runs, PyPI
metadata, PEP 740 attestations, Rekor entries, OSV cross-checks,
SBOMs, branch protection, and disclosure policy.

## Validating the snapshot's shape

The published JSON is accompanied by a JSON Schema (Draft 2020-12) at
[`api/v1/snapshot.schema.json`](https://273v.github.io/kaos-compliance/api/v1/snapshot.schema.json).
A consumer who wants to ingest the snapshot programmatically should
validate against the schema before consuming any field &mdash; this
catches drift between dashboard versions cleanly:

```bash
curl -sSfo snapshot.json        https://273v.github.io/kaos-compliance/api/v1/snapshot.json
curl -sSfo snapshot.schema.json https://273v.github.io/kaos-compliance/api/v1/snapshot.schema.json

uvx --from jsonschema jsonschema -i snapshot.json snapshot.schema.json
# (or `pipx install check-jsonschema && check-jsonschema --schemafile snapshot.schema.json snapshot.json`)
```

The schema is derived deterministically from the dataclasses in
`collector/snapshot.py` (via `collector/schema.py`), so the schema
that ships in any given snapshot describes the JSON shape that the
same collector emit. If validation fails on a snapshot that the
dashboard treats as valid, that's a bug &mdash; file an issue.

## Reporting tampering

If verification fails &mdash; the cosign bundle is missing, the identity
doesn't match, or the JSON has been altered &mdash; file a confidential
issue per `SECURITY.md`. Do not publish a tampered snapshot
externally; we'd rather investigate quietly first.

---

*Evidence guide version 1.0 &mdash; first added 2026-05-11 alongside the
keyless signing rollout (R4) and the published JSON Schema (R23).*
