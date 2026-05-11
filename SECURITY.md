# Security policy

The `kaos-compliance` dashboard surfaces public, verifiable claims
about the KAOS open-source ecosystem. Treat the dashboard itself with
the same scrutiny it applies to the packages it tracks.

## Reporting a vulnerability

If you believe you've found a vulnerability in this repository or in
the dashboard's data pipeline (collector, renderer, or the published
JSON snapshots), please report it through one of the following
channels, ordered by preference:

1. **GitHub private vulnerability reporting** — open a report at
   <https://github.com/273v/kaos-compliance/security/advisories/new>.
   This is the fastest path and routes directly to the maintainers
   with non-public scratch space for back-and-forth.
2. **Email** — <security@273ventures.com>. Encrypt with the
   organization PGP key published at <https://273ventures.com/pgp> if
   the report contains sensitive details.

Please **do not** open a public GitHub issue or pull request for a
suspected vulnerability before the fix has shipped.

## Disclosure window

We target a **90-day** coordinated-disclosure window from the date a
report is acknowledged. If the issue is publicly exploited in the wild
before the 90 days elapse, we may publish a fix and an advisory
earlier.

This window aligns with the disclosure policy across the rest of the
KAOS ecosystem (kaos-core, kaos-graph, kaos-source, etc.) and with the
Cyber Resilience Act's Annex I Part II §5 expectation for
coordinated-disclosure programs.

## Scope

### In scope

- The collector, renderer, and any script under `scripts/`.
- The data published at `https://273v.github.io/kaos-compliance/` and
  its `api/v1/*.json` endpoints (i.e., issues like cache poisoning,
  injection through misformatted snapshot data, supply-chain integrity
  of the deployed artifacts).
- The methodology document (`docs/METHODOLOGY.md`) — if a documented
  claim materially mis-represents what the dashboard actually surfaces,
  that's a bug, not a feature.

### Out of scope

- Vulnerabilities in the packages the dashboard tracks (`kaos-core`,
  `kaos-graph`, etc.). Each of those packages has its own
  `SECURITY.md` — please report to the relevant package directly.
- Vulnerabilities in third-party dependencies (`jinja2`, `gh` CLI,
  etc.) that are tracked upstream. The dashboard's pip-audit pass and
  CycloneDX SBOM will surface these automatically; out-of-band reports
  are welcome but not required.
- "GitHub Pages is rendering my page wrong" — that's a GitHub Platform
  concern, not ours.

## Hall of fame

Reports that materially improve the dashboard's accuracy or its
methodology will be credited in the relevant changelog entry, with
attribution at the reporter's preference (name, handle, organization,
or pseudonymous).

---

*Last reviewed: 2026-05-11. This policy applies to every branch of
this repository, including `main` and `gh-pages`.*
