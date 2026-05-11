# Contributing to kaos-compliance

The `kaos-compliance` dashboard publishes verifiable, evidence-backed
claims about the public KAOS open-source ecosystem. Contributions are
welcome — particularly ones that tighten the link between the claim
surfaced on the dashboard and the public evidence underneath.

## Ground rules

The dashboard's value is its honesty. Every contribution must respect
the principles laid out in [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md):

1. **Public sources only.** No private endpoints, no privileged
   credentials, no internal-only artifacts.
2. **JSON is the source of truth.** The HTML is one render of
   `data/snapshots/latest.json`. Don't hand-edit HTML; change the
   collector or renderer.
3. **Every claim links to evidence.** A new card without a `Verify`
   link is a bug.
4. **No invented scores.** Surface signals; don't composite them into
   a vanity number.
5. **Stale data is loudly marked stale.** The heartbeat block and the
   per-card freshness indicator are non-negotiable.
6. **No anti-pattern signals.** The explicit list lives in
   `docs/research/01-compliance-signal-inventory.md`. Highlights:
   no maintainer-identity (country, employer, real name), no raw test
   coverage above the fold, no GitHub stars.

If your change would surface something that doesn't pass these rules,
it doesn't belong here.

## How to contribute

### Reporting a discrepancy

If the dashboard surfaces a claim that doesn't match the underlying
public evidence (e.g., a green pill where the workflow actually
failed, a wheel platform listed that PyPI doesn't ship, a license
claim that the SBOM contradicts), please open an issue. Include:

- The URL on `https://273v.github.io/kaos-compliance/` exhibiting the
  claim.
- The public evidence URL that disagrees (workflow run, PyPI metadata,
  Rekor entry, etc.).
- A timestamp — the dashboard regenerates on a cron schedule
  ([`docs/METHODOLOGY.md#cadence`](docs/METHODOLOGY.md#cadence)) so
  the rendered HTML may briefly lag the underlying state.

### Proposing a new signal

New signals are welcome. Before opening a PR:

1. Map the signal to one of the anchor frameworks
   ([`docs/research/01`](docs/research/01-compliance-signal-inventory.md)):
   OpenSSF Scorecard, SLSA, NIST SSDF, CISA SBOM, PEP 740, CRA, or the
   legal-industry overlay.
2. Confirm the signal is extractable from a public source.
3. Confirm the signal is not on the anti-pattern list.
4. If it's a `Must` per the inventory, name which framework requires
   it. If it's `Nice`, justify the cost of adding it.

PRs that introduce signals outside any framework, or that surface
maintainer-identity signals, will be closed without merge.

### Code contributions

1. Fork + branch.
2. Run the local quality gate before pushing:

   ```bash
   uv sync --group dev
   uv run ruff format --check collector render tests
   uv run ruff check collector render tests
   uv run ty check collector render tests
   uv run pytest tests/ -q
   ```

3. The collector + renderer are deliberately stdlib-only (plus Jinja2
   for the renderer). Adding a runtime dependency requires a strong
   justification — the dashboard's threat surface should remain small.
4. New collector signals get a unit test that mocks the gh / urllib
   transport. Live-network tests belong in `tests/integration/` and
   must skip cleanly when the network is unavailable.
5. New renderer changes that affect the published HTML weight must
   keep each rendered page under 50 KB (compressed).
6. Sign commits with `git commit -s` for the Developer Certificate of
   Origin.
7. Use conventional-commit-style messages (`feat:`, `fix:`, `chore:`,
   `docs:`, `ci:`, `test:`).
8. PR descriptions: state what changed, why, how it was tested, and
   whether the published dashboard's claims, JSON schema, or
   methodology will change.

## Reviewing methodology changes

Material changes to `docs/METHODOLOGY.md` need a corresponding entry in
the [`CHANGELOG.md`](CHANGELOG.md) under a `### Methodology` section.
The methodology is the dashboard's contract with reviewers — silent
changes erode trust. If we tighten a claim, we want a paper trail; if
we relax one, even more so.

## Security disclosures

See [`SECURITY.md`](SECURITY.md). Do not open public issues for
suspected vulnerabilities — use the private reporting channel.

## License

By submitting a contribution, you agree to license it under the
project's Apache 2.0 license (see [`LICENSE`](LICENSE)) and certify
that you have the right to do so under the
[Developer Certificate of Origin](https://developercertificate.org/),
which is signaled by the `Signed-off-by` trailer added by
`git commit -s`.

---

*The dashboard makes maintainers slightly uncomfortable and procurement
slightly happier. If a contribution would reverse that ratio, it has
become marketing. Please reconsider.*
