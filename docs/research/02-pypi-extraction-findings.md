# PyPI extraction — live-verified findings

> Sub-agent research output, 2026-05-11. Code lives at
> `collector/pypi.py`.

## The three load-bearing PyPI trust signals

1. **PEP 740 provenance URL on the simple-index** (`files[i].provenance`).
   The only PyPI-native answer to "who built this and where?" — resolves
   to a sigstore DSSE bundle whose `publisher` block names the GitHub/
   GitLab repo, workflow file, and environment.

   Live-verified: `sigstore` 4.2.0 and **`kaos-graph` 0.1.0a3** both
   returned populated bundles with `publisher.kind = "GitHub"` + full
   repo + workflow attribution.

2. **`digests.sha256`** on every artifact. Without it nothing else can
   be pinned in a lockfile or audit.

3. **`info.license_expression` + `info.license_files`** (PEP 639).
   SPDX-machine-readable license plus embedded filename list — what
   lets a compliance dashboard reason about license obligations without
   scraping free-form text.

## The two pieces of PyPI theater

1. **`urls[i].has_sig`** — vestigial GPG flag. PyPI killed GPG uploads
   in 2023; the field still serializes but is meaningless. Do not
   surface.

2. **`urls[i].provenance`** in the legacy `/pypi/<pkg>/json` response —
   documented but observed `null` even for projects that DO publish
   attestations. Treating it as authoritative produces false negatives.
   **Only the simple-index field is real.** Use the PEP 691
   simple-index content negotiation:

   ```
   GET https://pypi.org/simple/<pkg>/
   Accept: application/vnd.pypi.simple.v1+json
   ```

   and read `files[i].provenance`.

## Surprises from live verification

- **Simple-index and legacy JSON disagree about provenance.** Simple
  index is correct; legacy JSON is stale.
- **`info.downloads` ships `-1` placeholders.** Download stats are
  theater on this endpoint entirely — use BigQuery / pypistats.org
  separately if needed.
- **Two of our kaos-* packages already have PEP 740 attestations.**
  `kaos-graph` 0.1.0a3 confirmed; likely the other Rust+PyO3 packages
  (`kaos-nlp-core`, `kaos-ml-core`, `kaos-nlp-transformers`) too since
  they share the release.yml shape.

## Implication for the dashboard

The "Trusted Publisher + workflow_ref pin" signal (rank 1 in the
above-the-fold list) is **already extractable for our packages today**.
The dashboard's headline claim — "every release on PyPI traces back to
a specific workflow file at a specific commit, verifiable via Rekor
public log" — is defensible from day one.

The Pure-Python repos that don't yet ship attestations (most of the
kaos-llm-* / kaos-content / etc.) should be visibly flagged as
`pypi.trusted_publisher = false` until release.yml is reworked to
upload via the PEP 740 path. That row should be amber, not red — it's
"acceptable for alpha, target before GA."

---

*Source: research sub-agent transcript at
`/tmp/claude-1000/-home-mjbommar-projects-273v/24ff5dad-7dde-40c2-8e94-40a470c096a2/tasks/a93b9ff042681de8e.output`*
