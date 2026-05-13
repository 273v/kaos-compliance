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
   compliance ingest at `https://273v.github.io/kaos-compliance/api/v1/snapshot.json`,
   alongside a machine-readable [JSON Schema](https://273v.github.io/kaos-compliance/api/v1/snapshot.schema.json)
   and a keyless sigstore signature
   (see [`EVIDENCE.md`](EVIDENCE.md#verifying-the-dashboard-hasnt-been-tampered-with)
   for the verification recipe and [`DATA-MODEL.md`](DATA-MODEL.md) for
   the per-field spec).
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

## Public PR and CI/CD Hardening Policy

The KAOS package repos are public, so the dashboard treats outside PRs
as an explicit trust boundary rather than a convenience feature. The
policy baseline for public `273v/kaos-*` repos and this compliance repo
is:

- untrusted PR code runs only from `pull_request`, never
  `pull_request_target` with contributor code checked out;
- the default `GITHUB_TOKEN` is read-only;
- workflows declare explicit `permissions:`;
- PR build/test jobs have no secrets, no `id-token: write`, no package
  publish authority, and no `contents: write`;
- all checkout steps use `persist-credentials: false`;
- external Actions references are pinned to full commit SHAs;
- fork PR workflow runs require approval for all external
  contributors;
- `main` requires status checks, CODEOWNER review, stale-review
  dismissal, approval of the most recent push, linear history, and no
  force-pushes;
- `v*` release tags are protected against deletion and force-update;
- secret scanning and push protection are enabled.

For `kaos-compliance` specifically, external fork PR code is not an
accepted contribution path and is not executed in CI. GitHub does not
allow disabling forks for an org-owned public repository, so the repo
uses policy plus workflow guards: public issues and private security
reports remain open, while CI jobs run only for `main` and PR branches
whose head repository is `273v/kaos-compliance`.

This policy is documented in full in
`kaos-modules/docs/oss/40-ci-cd/public-pr-security.md`. The compliance
dashboard does not currently render these repository settings as a
green public claim, because several of them are visible only through
GitHub admin APIs. The dashboard may surface workflow-file checks that
are publicly reproducible, such as pinned `uses:` references and
explicit workflow permissions. Admin-only settings are audited with the
runbook commands in `docs/RUNBOOK.md` until GitHub exposes a
publicly-reproducible evidence path.

The `kaos-compliance` sweep workflow is a trusted `main`/schedule
workflow, not an untrusted PR workflow. It still has a tracked
trust-lane follow-up: split collection/rendering, keyless signing, final
render, and Pages deploy into separate jobs so dependency installation
never shares a job token with `contents: write` or `id-token: write`.
Until that lands, the snapshot signature proves which workflow produced
the JSON, but it does not prove that the workflow followed the
least-privilege job split described above.

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

### NIST SSDF practice-ID matrix (R18)

The dashboard surfaces signals against the publicly-evidenceable subset
of NIST SP 800-218. Practices whose evidence is internal-only (e.g.
`PO.5.1` "Implement and maintain secure development environments")
are deliberately omitted — the dashboard's public-source-only contract
can't reach them.

| SSDF Practice | What the practice asks for | Dashboard signal | Snapshot path |
|---|---|---|---|
| `PO.1.1` | Define security requirements | Methodology + threat model | `docs/METHODOLOGY.md`, `docs/research/01-*.md` |
| `PO.3.2` | Provide a mechanism for verifying software releases | PEP 740 attestation + Rekor index | `modules[].supply_chain.attestations.*` |
| `PO.5.2` | Implement and maintain secure environments | Public PR hardening policy; GitHub-hosted runner policy | Policy documented above; workflow-file checks are public, admin settings are runbook-audited |
| `PS.1.1` | Store all forms of code based on the principle of least privilege | Branch protection on `main` | `modules[].governance.branch_protection_enabled` |
| `PS.2.1` | Provide a mechanism for verifying software-release integrity | Sigstore signature on snapshot + per-package attestations | `api/v1/snapshot.sig`, `modules[].supply_chain.attestations.*` |
| `PS.3.1` | Archive and protect each software release | PyPI release immutability + Rekor transparency log | `modules[].supply_chain.attestations.rekor_log_index` |
| `PS.3.2` | Provide an SBOM for each software release | CycloneDX 1.5 published per package | `modules[].supply_chain.sbom.sbom_artifact_path` |
| `PW.4.1` | Acquire and maintain well-secured software | OSV cross-check; CVE feed (see R11 below) | `modules[].security.workflow_conclusion` |
| `PW.7.1` | Review and analyze human-readable code | Per-package CI matrix conclusions | `modules[].ci.workflow_conclusion`, `.matrix` |
| `PW.8.2` | Configure compilation, interpretation, and build tools | Pinned tool versions; pre-commit hook drift | (gap — F11) |
| `RV.1.3` | Have a vulnerability-disclosure policy | `SECURITY.md` present | `modules[].governance.security_md_present` |
| `RV.2.1` | Analyze vulnerabilities to identify root causes | Suppressions ledger | `security.html#sup-h` (render-time augmentation) |

Practices not in the table (`PO.2.*`, `PO.4.*`, `RV.3.*`) are evidenceable
only from internal-process artifacts the dashboard explicitly does
not collect.

### CRA Annex II / Article 13 traceability (R19)

The EU Cyber Resilience Act, as drafted, requires manufacturers to
maintain technical documentation (Annex II) covering specific
conformity signals (Article 13). The mapping below names which
signals on this dashboard satisfy which clause; clauses without a
verifiable public signal are surfaced as honest gaps rather than
silently claimed.

| CRA reference | Requirement (compressed) | Dashboard signal |
|---|---|---|
| Annex II §1 | Product description with cybersecurity properties | Per-package detail pages |
| Annex II §2 | Risk assessment | Methodology page; SBOM + advisory feed |
| Annex II §3 | SBOM | CycloneDX 1.5 published per package |
| Annex II §4 | Vulnerability handling process | `SECURITY.md` + disclosure window |
| Annex II §5 | Information on processes set up for compliance | This document + `docs/RUNBOOK.md` |
| Annex II §6 | Technical specifications used for development | `docs/research/01-compliance-signal-inventory.md` |
| Article 13(2) | Risk assessment must be documented | Methodology + diary (`diary.html`) |
| Article 13(15) | Updates available for the lifetime of the product | Release cadence per package (`governance.html`) |
| Annex I Part II §1 | Vulnerability handling — make information publicly available | OSV cross-check; advisory rollup on `security.html` |
| Annex I Part II §3 | Apply effective and regular tests / reviews | CI matrix + Security workflow conclusions |
| Annex I Part II §5 | Establish disclosure policy | `SECURITY.md` present + disclosure-window field |
| Annex I Part II §7 | Provide security updates without delay | Tag → PyPI publish latency (`governance_summary.time_to_pypi_median_seconds`) |

CRA full enforcement guidance is not expected until 2027; this matrix
will be revised against the final implementing acts when published.

### CVE / advisory feed sources (R11)

The Security page's "0 open advisories" claim is only meaningful when
the feed sources are named. Today the dashboard cross-references:

- **OSV.dev** — `https://api.osv.dev/v1/query`, keyed by PURL
  (`pkg:pypi/<name>@<version>`, `pkg:cargo/<crate>@<version>`).
  Cursor: live query at sweep time; no snapshotting.
- **GitHub Security Advisories** — `gh api /advisories` filtered by
  affected ecosystem and package name. Cursor: live; deduplicated
  against OSV using the GHSA ID.

Both feeds are queried during the 4-hour Security cron. A package
clears the "0 advisories" bar only when both feeds return empty for
its declared version. The OSV PURL form is canonical; if a package
publishes under a non-PyPI distribution name the lookup may miss —
this is a known gap, tracked in
[`docs/research/08-followup.md`](research/08-followup.md).

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

### Where the maintainer-identity line is drawn (R5)

The dashboard collects per-commit *aggregates* — DCO sign-off rate,
verified-commit ratio, conventional-commits rate, unique-committer
count — without collecting per-commit *identities*. The distinction is
deliberate:

- **Ratios over 90 days** measure repository discipline. They answer
  "was the policy followed" without naming who followed or didn't.
  These are surfaced on `governance.html`.
- **Per-commit identity** would attach a name (or pseudonym) to an
  approve/sign-off action. The dashboard collects only the count of
  unique committers, not the committer identities themselves.
- **Cardinality** is the operational signal we care about for bus
  factor: a `unique_committers_90d == 1` is a procurement-relevant
  fact whether the one committer is anonymous or named.

In particular, `verified_commit_ratio_90d` is the count of commits
where GitHub's `verification.verified` is true, divided by the
commits-in-window — a *ratio*, not an identity claim. It is rendered
*always* paired with the branch-protection state, because without
required-signed-commits enforcement (which is an
`update_branch_protection` API field, not an identity check) the ratio
is decorative.

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
| Branch protection | `gh api repos/273v/<pkg>/branches/main --jq .protected` (public enabled flag); maintainers can inspect rule detail with `gh api repos/273v/<pkg>/branches/main/protection` |
| Disclosure policy | `https://github.com/273v/<pkg>/blob/main/SECURITY.md` |

If a `Verify` link doesn't reproduce, the dashboard claim is wrong and
should be reported.

Repository-level Actions settings such as fork-approval policy, default
workflow-token permissions, SHA-pinning enforcement, and secret scanning
are intentionally absent from this verification table today. They are
important controls, but their GitHub API evidence requires maintainer
or admin authority. We audit them operationally and avoid rendering a
public green check until the evidence can be reproduced by a third
party.

## Snapshot integrity and shape

Every published snapshot is accompanied by two integrity artifacts:

| Artifact | Path | Purpose |
|---|---|---|
| JSON Schema | `api/v1/snapshot.schema.json` | Programmatic validation of the JSON shape. Draft 2020-12; derived from the dataclasses in `collector/snapshot.py`. |
| Sigstore signature | `api/v1/snapshot.sig` | DSSE bundle minted via keyless OIDC signing by the kaos-compliance sweep workflow. Ties the bytes to a specific workflow run on this repository. |

The full verification recipe (cosign command + expected identity) is
in [`EVIDENCE.md`](EVIDENCE.md#verifying-the-dashboard-hasnt-been-tampered-with).
The data model is in [`DATA-MODEL.md`](DATA-MODEL.md).

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
- **OpenSSF Scorecard per-check results (R8).** The dashboard names
  Scorecard as an anchor framework but does NOT yet ingest the per-check
  results. Scorecard workflows are installed and pinned, but the
  dashboard has not yet turned their SARIF/JSON output into a
  per-check table. This is a self-inflicted gap, tracked as `R8` in
  [`docs/research/08-followup.md`](research/08-followup.md). A buyer
  who wants the per-check breakdown today can run
  `scorecard --repo=273v/kaos-compliance --format=json` locally; the
  data is public, the dashboard just doesn't render it yet.
- **SLSA Build Level not formally attested (R9).** Each package's
  PEP 740 attestation + PyPI Trusted Publisher state puts it
  effectively at SLSA Build L2 (hosted build platform, attestations
  generated by the platform). The dashboard surfaces these signals
  but does not emit a formal `slsa.build.level` claim; tracked as
  `F19` in the follow-up doc. L3 (hardened build platform with
  isolation guarantees) is reachable with the existing
  Trusted-Publisher wiring.
- **CISA SBOM Minimum Elements gap (R10).** The seven required
  elements (author, supplier, name, version, unique ID, relationships,
  timestamp) are visible per-package on `supply-chain.html`; the
  *relationships* element is the one currently flagged yellow across
  the org because the SBOM emitter doesn't yet build the
  `dependencies[]` edge graph (`F9` in the follow-up doc).

These gaps are intentionally surfaced so a buyer knows what they still
need to ask for in a vendor questionnaire.

## Methodology versioning (R25)

This document follows semver. The bump rules are tight on purpose: the
property that makes the dashboard credible — that an external reviewer
can pin a snapshot to a methodology version and reproduce the
assessment — fails the first time the green threshold for a signal is
silently "clarified" without bumping the version.

| Change | Bump |
|---|---|
| Add a new signal that previously didn't exist (new column, new pill) | minor |
| Add a new framework anchor (e.g. ingest Scorecard results) | minor |
| Remove a signal | **major** |
| Change the green / amber / red threshold for an existing signal | **major** |
| Change the snapshot-path source for an existing signal | **major** |
| Change a default-fallback (e.g. "gray means" wording) | **major** |
| Rewrite an existing section without changing meaning | patch |
| Add an honest-gap entry under "Limits and honest gaps" | patch |
| Add or expand the per-framework mapping tables | patch |
| Typos, link fixes, formatting | patch |

A bump requires:

1. An entry in [`CHANGELOG.md`](../CHANGELOG.md) with the version,
   the change, the affected signals, and the rationale.
2. The `methodology_version` field below to reflect the new version.
3. A pre-commit / CI check that fails if `policy_version`, pill
   thresholds, or signal definitions in `render/__main__.py` change
   without a matching CHANGELOG entry. (Today this is a manual
   review discipline; landing the CI rule is a planned step,
   tracked in `docs/research/08-followup.md`.)

The published snapshot at `api/v1/snapshot.json` carries
`schema_version` separately. That field bumps independently when the
JSON shape changes; the methodology version above governs the
*meaning* of the signals, not the wire format.

---

*Methodology version 1.1 — 2026-05-11.*

*Changelog:*

- *1.1 (2026-05-11): Patch. Added NIST SSDF practice-ID matrix (R18),
  CRA Annex II / Article 13 traceability (R19), CVE / advisory feed
  sources (R11), maintainer-identity boundary clarification (R5),
  Scorecard / SLSA / CISA SBOM honest-gap entries (R8, R9, R10),
  and explicit versioning policy (R25). No signal or threshold
  change — all expansions are within the patch tier of the
  versioning policy now documented in this file.*
- *1.0 (2026-05-11): Initial draft.*
