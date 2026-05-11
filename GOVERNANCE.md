# Governance

This document describes how the `kaos-compliance` project is governed:
who decides what, how decisions get made, who can be paged when
something breaks, and how succession works if a key person becomes
unavailable. It addresses F17 of the internal process audit
("governance is undocumented — bus-factor risk").

## Project scope

`kaos-compliance` is a continuous-compliance dashboard for the
273V/kaos-* ecosystem. It is **public**. Its outputs are consumed by
external regulated-industry stakeholders. Decisions about what the
dashboard claims, how it computes those claims, and which evidence it
links to are therefore governance decisions, not just engineering
decisions.

## Roles

### Maintainers

The maintainers own the project's technical direction, release
cadence, and methodology.

| Role | Person | Responsibilities |
|---|---|---|
| Primary maintainer | @mjbommar (Michael Bommarito) | Methodology, release sign-off, security responses, on-call. |
| Secondary maintainer | @jillbomm | Code review, secondary on-call, succession in primary's absence. |

Both maintainers appear in `CODEOWNERS` for every critical path. PRs
touching methodology (`docs/METHODOLOGY.md`), policy
(`policy/license-allowlist.yaml`), or the collector schema
(`api/v1/snapshot.schema.json`) require **two** maintainer approvals.

### Contributors

Anyone who opens a PR or issue. Contributors do not require an org
affiliation. PRs are accepted on technical merit and adherence to
the methodology contract. Contributors must follow `CONTRIBUTING.md`
and sign commits with `git commit -s` (DCO).

### Reporters

Anyone reporting a verification failure (see `docs/EVIDENCE.md`) or a
security vulnerability (see `SECURITY.md`). Reporters are not required
to contribute fixes. Verification-failure reports that produce a real
fix are credited in `CHANGELOG.md`.

## Decision-making

Decisions fall into three classes, ordered by reversibility:

1. **Reversible operational decisions** (e.g., cron timing, retry
   parameters, renderer styling). One maintainer review suffices.
2. **Methodology decisions** (e.g., changing what a "green Build" pill
   means, adding/removing a pill, changing a threshold). Two
   maintainer approvals AND a `docs/METHODOLOGY.md` entry. Discussed
   on the PR; no separate forum.
3. **Schema-breaking decisions** (e.g., renaming a top-level field in
   `api/v1/snapshot.json`, removing a section). Two maintainer
   approvals, a `CHANGELOG.md` entry under "Breaking changes," a
   schema-version bump in `api/v1/snapshot.schema.json`, and a
   pre-announcement (issue with `breaking-change` label, posted at
   least 30 days before the merge). Consumers of the JSON endpoint
   are external; we treat the schema as a published contract.

Disagreement resolution: open a PR with the proposed change and let
the discussion be public. If maintainers disagree and consensus
isn't reached on the PR, the primary maintainer has tiebreaker
authority but must record the disagreement and rationale in the PR
description so the audit trail is intact.

## On-call and escalation

See `docs/RUNBOOK.md` for the operational decision tree. The escalation
contract is:

| Severity | Definition | Page |
|---|---|---|
| P0 | Dashboard shows a materially-incorrect security claim. | Primary maintainer immediately; if no response within 30 min, secondary maintainer. |
| P1 | Dashboard stale > 48h or widespread `ERR`. | Primary within 4h. |
| P2 | Single-package `ERR` or visual bug. | File an issue. |
| P3 | Wording / methodology nits, dead links. | File an issue. |

If both maintainers are unreachable for > 72h, the dashboard's
heartbeat watchdog will auto-mark it stale (after 26h) and the public
banner makes that visible. There is no automated takeover; consumers
are told to treat stale pages as untrusted, which is the correct
default.

## Key material and credentials

The dashboard uses the following credentials, all stored as GitHub
Actions repository secrets:

| Secret | Used by | Rotation cadence |
|---|---|---|
| `GITHUB_TOKEN` | Sweep workflows (auto-issued per-run) | N/A — ephemeral |
| `KAOS_COMPLIANCE_PAT` | Cross-org reads with higher rate limit | Quarterly |
| `SIMULATOR_OPENAI_API_KEY` | LLM diary | Quarterly or on suspected compromise |
| `SIMULATOR_ANTHROPIC_API_KEY` | LLM diary fallback | Quarterly or on suspected compromise |
| `COSIGN_KEYLESS_OIDC` | Snapshot signing (planned, R4) | N/A — keyless via GH OIDC |

Each rotation is logged as a PR description on the rotation-day
commit (no separate ledger required; `git log -S 'rotated'` finds
them).

The signing identity used to sign `api/v1/snapshot.json` (once R4
lands) is **keyless via GitHub OIDC** — there is no long-lived private
key to lose, exfiltrate, or rotate. The identity claim is the workflow
identity (`273v/kaos-compliance/.github/workflows/sweep-full.yml@refs/heads/main`),
verifiable by any third party via the Rekor transparency log.

## Succession

If the primary maintainer becomes unavailable for an extended period:

1. The secondary maintainer assumes primary responsibilities.
2. A new secondary maintainer is nominated within 30 days. Nominations
   go through a PR that adds the new GitHub handle to `CODEOWNERS` and
   this document. Two existing maintainer approvals (or one, if only
   one remains) merge the change.
3. If both maintainers become unavailable, the project enters a stale
   state: the dashboard's heartbeat watchdog already surfaces this,
   and no claims are added or modified until a maintainer returns or a
   new one is appointed by the 273 Ventures organization.

273 Ventures retains org-admin rights to the GitHub repository at
all times and can appoint replacement maintainers in the limit case.

## Conflict of interest

The dashboard makes claims about software the maintainers also build
and ship. To prevent self-rating drift:

- The methodology is **public** (`docs/METHODOLOGY.md`). Anyone can
  fork it and re-evaluate the kaos-* ecosystem against the same rules.
- The source code is **public**. Anyone can audit the collector for
  bias.
- Every pill links to **upstream evidence** (GitHub Actions runs, PyPI
  pages, sigstore logs) the maintainers do not control. If we tried
  to fake a claim, the evidence link would expose it.
- Verification-failure reports (`docs/EVIDENCE.md`) are explicitly
  welcomed and credited.

Maintainers MUST NOT modify the collector to grant their own packages
favorable treatment. Reviewers SHOULD reject any PR that special-cases
specific package names in the collector logic.

## Project lifecycle

The project is currently in **active development** (pre-1.0 schema).
The schema is documented in `docs/DATA-MODEL.md` and `api/v1/snapshot.schema.json`.
Schema-stability commitments take effect at `schema_version >= 1.0`
(see `docs/DATA-MODEL.md`).

If the project is wound down:

1. A final sweep is published with the heartbeat watchdog set to a
   permanently-stale state and a deprecation notice on every page.
2. The `gh-pages` branch is preserved (not deleted) so the historical
   record remains addressable.
3. `SECURITY.md` is updated to point reporters to a successor or to a
   plain `it@273ventures.com` mailbox.

## Changes to this document

Changes to `GOVERNANCE.md` itself require two maintainer approvals.
This is intentional — the rules for changing the rules should be the
same as the rules for changing what the dashboard claims.

---

*Last updated: 2026-05-11.*
