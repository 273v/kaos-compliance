# kaos-compliance Style Guide

## Typography stack (system fonts only — zero network fetches)

- Body / UI: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`
- Monospace (versions, hashes, paths): `ui-monospace, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace`
- Sizes (rem, base 16px): 0.75 (caption) / 0.875 (table cell) / 1 (body) / 1.125 (card title) / 1.5 (section h2) / 2 (page h1)
- Weight scale: 400 body, 600 headings + scorecard labels, 700 only for the org-rollup composite number
- Line height: 1.5 body, 1.25 headings, 1.1 numerals in metric strip

## Spacing scale (8px grid, CSS custom properties)

```
--s-1: 4px    tight inline
--s-2: 8px    icon-to-label gap
--s-3: 12px   intra-card padding
--s-4: 16px   card body padding
--s-5: 24px   inter-card gap
--s-6: 32px   section separation
--s-7: 48px   page-level breathing room (top/bottom)
```

Max content width 1200px, centered, with 24px gutter on viewports >720px and
16px gutter below. Card grid uses `display: grid; gap: var(--s-5)`.

## 4-color semantic palette

Light mode is the default since auditors print on white paper. Dark via
`prefers-color-scheme`. All four states ALSO carry an icon and a word —
never color-only.

| State    | Light bg | Light fg/border | Dark bg  | Dark fg/border | Contrast (text on bg) |
|----------|----------|-----------------|----------|----------------|-----------------------|
| Green    | #E6F4EA  | #1E7E34         | #14271B  | #4ADE80        | 7.3:1 light / 9.1:1 dark |
| Yellow   | #FFF8E1  | #8A6D00         | #2A2410  | #FACC15        | 6.4:1 light / 10.2:1 dark |
| Red      | #FDECEA  | #B42318         | #2A1414  | #F87171        | 6.9:1 light / 6.7:1 dark |
| Gray     | #F3F4F6  | #4B5563         | #1F2937  | #9CA3AF        | 7.5:1 light / 6.2:1 dark |

Neutral surfaces (non-state):
- Page bg light `#FFFFFF`, dark `#0B0F14`
- Card bg light `#FAFBFC`, dark `#11161D`
- Border light `#E5E7EB`, dark `#1F2937`
- Body text light `#111827`, dark `#E5E7EB`
- Muted text light `#6B7280`, dark `#9CA3AF`

## Iconography (no SVG sprites, no icon font)

Inline Unicode + accessible label, one glyph per state:

| State  | Glyph | aria-label / word |
|--------|-------|-------------------|
| Green  | `✓`  | "Pass" |
| Yellow | `⚠`  | "Warn" |
| Red    | `✗`  | "Fail" |
| Gray   | `—`  | "No signal" |

Pills render as a 16x16 colored square with the glyph centered and the word
beside it in body text. Never a bare colored dot.

## Accessibility

- Target WCAG 2.2 AA: text on state backgrounds verified at 4.5:1 minimum (numbers above all meet it).
- Focus ring: 2px solid `#2563EB` (light) / `#60A5FA` (dark), 2px offset.
- All interactive elements reachable by keyboard; tab order matches visual order.
- `prefers-reduced-motion: reduce` disables the one transition we have (card hover).
- Tables: every cell has either text or `aria-label="No signal"` on the gray pill.
- The state column header is text ("Build", "Tests"), the cell is `<pill> <word>` — never icon alone.
- Print stylesheet (`@media print`) flattens the dark-mode rules and forces black text on white, drops the page header link bar, and renders pills with borders not fills.

## Component conventions

- Cards: 1px border, 6px corner radius, no shadow (shadows print poorly).
- Tables: zebra rows at 2% darken in light, 4% lighten in dark. No vertical rules.
- Metric strip: 4 to 6 large numerals (1.75rem, weight 700) with caption below. No gradient, no animation.
- Sparklines: 80x20px inline SVG, 1.5px stroke, current-color, no axes, no tooltip.
- Activity bars: inline SVG only, paired with the numeric value they visualize.
  Use them for cardinality distributions such as commits, releases, and code
  surface area; never use them as a substitute for pill state.
- Footer: 0.75rem muted, single line where viewport allows, wraps gracefully.

## What we deliberately do NOT use

- No web fonts. No Google Fonts. No CDN.
- No emoji as state signal (rendering is inconsistent across OS/browsers and prints poorly).
- No JS frameworks. No JS at all in the v1 templates.
- No gradients, no shadows, no rounded-pill buttons. This is a compliance document, not a SaaS landing page.
