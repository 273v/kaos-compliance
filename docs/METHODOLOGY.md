# Methodology

> This document explains every claim the kaos-compliance dashboard
> makes and how a third party can independently reproduce the
> verification. If a claim doesn't have a verification path here, it's
> a bug — please file an issue.

## Principles

1. **Public sources only.** Every signal is extracted from a publicly
   accessible source: GitHub REST API, PyPI JSON + simple-index, the
   sigstore Rekor transparency log, or files committed to the public
   `273v/kaos-*` repos. No private endpoints, no privileged credentials,
   no internal-only artifacts.
2. **JSON is the source of truth.** The dashboard's HTML is one render
   of `data/snapshots/latest.json`. The same JSON is published for
   compliance ingest at `https://273v.github.io/kaos-compliance/api/v1/snapshot.json`.
3. **Every claim links to evidence.** Each card on the dashboard
   carries a `Verify` link that opens the underlying source (a GitHub
   workflow run, a PyPI metadata page, a Rekor log entry, or a file in
   this repo).
4. **No invented scores.** We surface the OpenSSF Scorecard aggregate
   (a pre-composited industry-standard number) and the underlying
   signals. We do not compute a competing composite. Buyers compose
   their own bar from the per-signal evidence.
5. **Stale data is loudly marked stale.** Every snapshot carries a
   generation timestamp; the dashboard shows a freshness indicator on
   every card. If the cron stops running, the indicator goes amber
   within 2 hours and red within 24.

## Cadence

| Cron | Cadence | What runs | Why |
|---|---|---|---|
| Light | every 1h | CI conclusions, open PR counts, queue depth | These move fast; staleness is misleading. |
| Security | every 4h | bandit / vulture / cargo-* / pip-audit / gitleaks conclusions; OSV cross-check; PyPI attestation refresh | Slower-moving but high-signal; refresh often enough that a published advisory shows up within a working day. |
| Full | every 24h (UTC midnight) | Full sweep + SBOM rebuild + LLM diary + history rotation | The expensive path. Rebuilds the full transitive dep tree and runs the daily narrative. |

Cron is driven primarily by GitHub Actions on this repo. A local cron
job on the developer machine acts as a backup and runs the LLM diary
when the GHA secrets don't have the model-provider API key wired.

## Frameworks anchored

This dashboard maps signals to:

- **[OpenSSF Scorecard v5](https://scorecard.dev)** — all 19 checks.
- **[SLSA 1.0](https://slsa.dev)** — Build L1-L3, Source L1-L3 (Source
  track still draft as of 2026-05).
- **[NIST SSDF (SP 800-218)](https://csrc.nist.gov/Projects/ssdf)** —
  the 12 practice IDs with publicly evidenceable signals.
- **[CISA SBOM Minimum Elements](https://www.cisa.gov/sbom)**.
- **[PEP 740](https://peps.python.org/pep-0740/) +
  [sigstore](https://www.sigstore.dev/) + PyPI Trusted Publishers**.
- **[Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)**
  (Annex I Part II conformity signals; full enforcement guidance not
  expected until 2027).

See [`docs/research/01-compliance-signal-inventory.md`](research/01-compliance-signal-inventory.md)
for the per-framework signal-to-source mapping table.

## Anti-patterns we explicitly avoid

The dashboard does not surface:

1. **Raw test coverage percentage as a top-line metric.** A 90%-covered
   abandoned project is worse than a 60%-covered actively-maintained
   one. Coverage *trend* is shown one click down; coverage absolute is
   not.
2. **"Signed commits" as a binary green check.** Without policy
   enforcement, signed-commit ratio is decorative. We show the ratio
   paired with the branch-protection-required-signature state, or omit.
3. **SBOM presence without dependency edges.** A component list with
   no `dependencies[]` graph is a manifest, not an SBOM. We visibly
   downgrade these.
4. **A composite "compliance score out of 100".** Buyers see through
   it; it incentivizes gaming cheap signals (badges, file presence) at
   the cost of expensive ones (review discipline, attestation hygiene).
5. **Maintainer-identity signals** (country, employer, real name).
   Encourages discrimination, generates false positives on
   pseudonymous-but-trusted maintainers, adds zero supply-chain
   integrity.
6. **GitHub stars.** A popularity metric, not a trust metric.

## Verifying a claim independently

Every dashboard card has a `Verify` link. Following it should let you
reproduce the underlying lookup without any privileged access:

| Card | Verify link points at |
|---|---|
| Latest PyPI version | `https://pypi.org/project/<pkg>/<version>/` |
| Wheel platform matrix | `https://pypi.org/pypi/<pkg>/<version>/json` (`urls[]`) |
| PEP 740 attestation | `https://pypi.org/simple/<pkg>/` (Accept: `application/vnd.pypi.simple.v1+json`) → `files[i].provenance` URL |
| Sigstore Rekor entry | `https://rekor.sigstore.dev/api/v1/log/entries?logIndex=<N>` |
| CI run | `https://github.com/273v/<pkg>/actions/runs/<run-id>` |
| Security scan | Same as above for the Security workflow |
| Open advisories | `https://api.osv.dev/v1/query` with the package PURL |
| SBOM | `data/sbom/<pkg>-<version>.cdx.json` in this repo |
| Branch protection | `gh api repos/273v/<pkg>/branches/main/protection` |
| Disclosure policy | `https://github.com/273v/<pkg>/blob/main/SECURITY.md` |

If a `Verify` link doesn't reproduce, the dashboard claim is wrong and
should be reported.

## Limits and honest gaps

Things this dashboard does **not** prove:

- **Reproducible builds.** We surface SLSA build-level claims but do
  not independently rebuild artifacts. A separate effort is required
  to attest reproducibility.
- **Per-commit author identity beyond GitHub's `verification.verified`
  state.** GitHub's GPG-key claim is what we report; deeper identity
  proofing (e.g., DCO sign-off matching a known steward) is not done.
- **Source-of-truth for transitive licenses.** We rely on the published
  license metadata of each dep. If a published license is wrong, our
  aggregation is wrong. We do not legally audit license claims.
- **Operational security of the maintainer machines.** A dashboard can
  prove the artifact came from a specific workflow; it cannot prove
  the workflow's secrets weren't exfiltrated upstream. That's outside
  the scope of any public dashboard.

These gaps are intentionally surfaced so a buyer knows what they still
need to ask for in a vendor questionnaire.

---

*Methodology version 1.0 — initial draft, 2026-05-11.*
