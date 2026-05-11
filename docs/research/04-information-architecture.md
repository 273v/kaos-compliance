# kaos-compliance Dashboard — Information Architecture

Audience: a compliance officer or infosec auditor with 90 seconds for the rollup
and 5 minutes per package if they care. Not a marketing visitor. Page must
answer "do these packages clear our bar" without scrolling past trust signals.

## Page inventory

| Path | Question it answers | Above the fold (top 800px @ 1280) | Behind a click |
|---|---|---|---|
| `index.html` | Is the KAOS org healthy at a glance? | Org rollup card (composite score, last-audit timestamp, build/test/sec strip), 16-package grid (one row per package, 4-state pill per column) | Per-package detail pages; methodology footnote anchors |
| `package/<name>.html` | Does this specific package meet bar? | Identity block (name, version triple, license, last release), trust scorecard (8 checks with state + 1-line evidence) | CI matrix, CVE table, SBOM artifact links, contributor velocity chart, raw JSON snapshot |
| `security.html` | Are there open advisories across the org? | Headline counters (open/fixed/total by severity), advisory table sorted by severity desc | Per-CVE detail, GHSA links, fix-version timeline |
| `supply-chain.html` | What's the dependency + license risk? | License distribution stacked bar, transitive-dep counter, SBOM download links (CycloneDX + SPDX) per package | Full dep tree, license obligations matrix, copyleft callouts |
| `governance.html` | Who runs this, on what cadence, with what controls? | Maintainer list with commit-share, release cadence chart, branch-protection state per repo | CODEOWNERS, SECURITY.md presence, signing key fingerprints |
| `diary.html` | What changed since the last audit? | Reverse-chronological event feed (releases, CVEs filed, CVEs fixed, maintainer adds) | Filter by package/event type |
| `methodology.html` | How are these signals computed? | Plain-English description of each of the 8 scorecard checks; source links; collection cadence; known gaps | Raw collector script, GitHub Action workflow |

## Wireframe — `index.html`

```
+--------------------------------------------------------------------------+
|  KAOS Compliance Dashboard                Generated 2026-05-11 14:02 UTC |
|  273 Ventures open-source packages — auditor view                        |
+--------------------------------------------------------------------------+
|  ORG ROLLUP                                                              |
|  +------------------------------------------------------------------+    |
|  | Composite Trust    14 / 16 packages green   [============----]   |    |
|  | Build passing      15/16        Tests passing      14/16         |    |
|  | Open advisories    0 critical   2 high   5 moderate              |    |
|  | Signed releases    11/16        License clean      16/16         |    |
|  +------------------------------------------------------------------+    |
+--------------------------------------------------------------------------+
|  HEADLINE METRIC STRIP                                                   |
|  [ 16 pkgs ] [ 2,341 commits 90d ] [ 8 maintainers ] [ 0 CVE critical ]  |
+--------------------------------------------------------------------------+
|  PACKAGE GRID (16 rows, sortable headers)                                |
|  Package        Ver       Build  Tests  Sec  Sign  Lic  Dep  Last release|
|  kaos-core      1.4.2     [G]    [G]    [G]  [G]   [G]  [Y]  3 days ago  |
|  kaos-cli       0.9.1     [G]    [G]    [G]  [R]   [G]  [G]  11 days ago |
|  kaos-eval      0.3.0     [G]    [Y]    [G]  [-]   [G]  [G]  46 days ago |
|  ... 13 more rows ...                                                    |
+--------------------------------------------------------------------------+
|  Footer: source repo | methodology | snapshot.json                       |
+--------------------------------------------------------------------------+
```

Pills `[G][Y][R][-]` are colored squares plus an inline glyph (check / warn /
x / dash) so the signal survives a grayscale print.

## Wireframe — `package/kaos-core.html`

```
+--------------------------------------------------------------------------+
|  kaos-core 1.4.2                                  back to org rollup     |
|  Apache-2.0  |  released 2026-05-08  |  Python 3.10+                     |
+--------------------------------------------------------------------------+
|  TRUST SCORECARD                              Composite: 7/8 green        |
|  +-----------------------------+  +-----------------------------+         |
|  | [G] Build passing           |  | [G] Tests > 80% coverage    |         |
|  | main green for 14 days      |  | 87% line, 81% branch        |         |
|  +-----------------------------+  +-----------------------------+         |
|  | [G] No critical CVEs        |  | [G] Signed release artifacts|         |
|  | 0 open, 1 fixed 30d         |  | sigstore + GPG since 1.3.0  |         |
|  +-----------------------------+  +-----------------------------+         |
|  | [G] License clean Apache-2.0|  | [Y] SBOM present (SPDX only)|         |
|  | no copyleft transitive deps |  | CycloneDX not generated     |         |
|  +-----------------------------+  +-----------------------------+         |
|  | [G] Branch protection on    |  | [G] SECURITY.md + CODEOWNERS|         |
|  +-----------------------------+  +-----------------------------+         |
+--------------------------------------------------------------------------+
|  CI MATRIX     OS x Python      pytest  ruff  ty  bandit  pip-audit       |
|  ubuntu/3.10   [G][G][G][G][G]    ...                                    |
|  ubuntu/3.11   [G][G][G][G][G]                                           |
|  macos/3.12    [G][G][G][G][G]                                           |
|  windows/3.12  [G][G][G][Y][G]    bandit B404 informational              |
+--------------------------------------------------------------------------+
|  SECURITY     Open: 0   Fixed (90d): 1   Dependabot alerts: 0            |
|  SUPPLY CHAIN 14 direct deps, 87 transitive; SBOM: spdx.json (link)      |
|  GOVERNANCE   3 maintainers; 42 commits/90d (sparkline); 6 releases/90d  |
|  EVIDENCE     repo | releases | actions | sbom.json | snapshot.json      |
+--------------------------------------------------------------------------+
|  Methodology callout: how these eight checks are scored                  |
+--------------------------------------------------------------------------+
```

## URL structure + relative-link policy

GitHub Pages serves under `/kaos-compliance/`. All internal links are
**root-relative without the prefix** and resolved via a single `<base href>`
tag emitted by the template. Examples: `package/kaos-core.html`,
`security.html`, `assets/snapshot.json`. No absolute URLs to the site itself —
this lets the same build serve from `kaos-compliance.273v.com` later without
a rewrite.

## 4-state color semantics

| State | Meaning | When to use |
|---|---|---|
| Green  | Signal collected AND passes bar | Build green, no open critical CVEs, license SPDX-valid |
| Yellow | Signal collected AND below bar but non-blocking | Stale release, partial SBOM, B-level bandit findings |
| Red    | Signal collected AND blocking | Open critical CVE, unsigned release where signing was previously present, license violation |
| Gray   | No signal yet — NOT bad news | Package <30 days old, check not yet implemented, repo private during collection window |

Gray exists specifically so the collector can ship before every check is wired
up. A page full of red because a check is missing trains auditors to ignore red.

## Sparkline placement strategy

**Show** sparklines for time-series signals where the trend is the point:
commits/week, release cadence, open-CVE count over 90 days. SVG path,
inline, no library.

**Skip** sparklines for point-in-time states (license, branch protection,
current build status). A sparkline of a boolean is noise.

Cap: one sparkline per card, max four per page. They are decoration without
the underlying number; always pair with the current value.
