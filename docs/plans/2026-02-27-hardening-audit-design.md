# clawfidence Hardening & Security Audit Design

**Date:** 2026-02-27
**Status:** Approved
**Approach:** Layered TDD hardening (red-green-refactor per bypass vector)

## Context

Security audit of all scanner/sanitiser modules revealed 17 issues across
5 severity tiers. All fixes will follow strict TDD: write a failing test
for the bypass vector first, then fix the code.

## Critical (1 issue)

### C1. `looksEducational` bypass in injection.ts

**Vector:** Attacker prepends "this is a tutorial" to skip ALL injection
detection. The function returns early with empty findings when any
educational keyword appears anywhere in the text.

**Fix:** Remove the global educational bypass. Instead, apply educational
context checking per-finding: when a pattern matches, check whether it
appears inside a code fence or within clearly educational prose structure
(e.g., preceded by "example of", "how to write", etc.) within a narrow
window around the match. Never skip the entire scan.

## High (4 issues)

### H1. `SYSTEM:` only matches uppercase (injection.ts)

**Vector:** `system:` or `System:` bypasses the check.
**Fix:** Add `i` flag to the regex.

### H2. `display:none` regex only matches double-quoted style (injection.ts)

**Vector:** `<div style='display:none'>injection payload</div>` evades.
**Fix:** Update regex to accept single-quoted, double-quoted, and unquoted
style attribute values.

### H3. IDN check only examines leftmost hostname label (url.ts)

**Vector:** `http://safe.xn--evil.com` passes because hostname starts with
`safe.`, not `xn--`.
**Fix:** Split hostname by `.` and check if ANY label starts with `xn--`.

### H4. Single-pass percent decoding in normaliseUri (3 files)

**Vector:** Double-encoding `j%2561vascript:` decodes once to `ja%61vascript:`
which doesn't match `javascript:`.
**Fix:** Loop `decodeURIComponent` until stable (max 3 iterations) to handle
multi-layer encoding. Apply to the shared `normaliseUri` (see R1 below).

## Medium (6 issues)

### M1. Angle-bracket link ref definitions not matched (markdown-xss.ts)

**Vector:** `[foo]: <javascript:alert(1)>` bypasses raw line scanner.
**Fix:** Extend link ref definition regex to match angle-bracket URL syntax.

### M2. Unclosed `<script>` tag survives (md-to-md.ts)

**Vector:** `<script>evil` (no closing tag) passes pair-matching regex.
**Fix:** Add a second pass that removes unpaired opening tags for dangerous
elements.

### M3. IP detection misses IPv6, octal, hex, decimal (url.ts)

**Vector:** `http://0xC0A80101/`, `http://[::1]/` evade IP check.
**Fix:** Add patterns for IPv6 (bracket-enclosed), decimal-integer hostnames,
and octal/hex IP notation.

### M4. HTML entity-encoded `=` in event handlers (md-to-md.ts)

**Vector:** `onerror&#61;alert(1)` bypasses event handler regex.
**Fix:** Decode common HTML entities (`&#61;`, `&#x3d;`, `&equals;`) before
event handler matching.

### M5. Prefix allowlist is case-sensitive (url.ts)

**Vector:** `HTTPS://TRUSTED.COM` fails when allowlist has `https://trusted.com`.
**Fix:** Lowercase both URL and prefix before comparison.

### M6. SVG/MathML in DOMPurify allowlist (sanitise.ts)

**Vector:** `<svg><animate onbegin="alert(1)">` — broad SVG attack surface.
**Fix:** Remove SVG and MathML from the allowed tags list. If SVG support is
needed later, add it behind a flag.

## Low (5 issues)

### L1. Injection patterns easily evaded with paraphrasing

**Limitation acknowledged.** Pattern-matching cannot catch novel phrasings.
Document this in the report output as a known limitation. Consider adding
a heuristic confidence score that flags text with high instructional tone
even without exact pattern matches.

### L2. No homoglyph/confusable detection (unicode.ts)

**Fix:** Add detection for mixed-script text (Latin + Cyrillic in same word)
as a suspicious_unicode finding. Full confusable detection is out of scope.

### L3. Missing variation selector detection (unicode.ts)

**Fix:** Add U+FE00-FE0F and U+E0100-E01EF to the zero-width character list.

### L4. Tilde fences not tracked (markdown-xss.ts, md-to-md.ts)

**Fix:** Extend code fence tracking regexes to match `~~~` in addition to
backtick fences.

### L5. Event handler checks limited to 4 handlers (md-to-md.ts)

**Fix:** Use a general `on[a-z]+` pattern instead of listing specific handlers.
The allowlist approach (only check known handlers) is backwards — deny any
`on*` attribute.

## Refactoring

### R1. Extract shared `normaliseUri` to a utility module

`normaliseUri` is duplicated across `markdown-xss.ts`, `url.ts`, and
`md-to-md.ts`. Extract to `src/utils/normalise-uri.ts` with the
multi-pass decoding fix (H4).

## Test Coverage

- Install `@vitest/coverage-v8` dev dependency
- Target: 90%+ line coverage
- Add bypass-vector tests for every fix above (one or more per issue)
- Refresh vendor XSS payload lists from upstream repos
- Add new CVE reproduction tests if any have been published since initial build

## Order of Work

1. Install coverage tooling, establish baseline
2. Critical fix (C1) — most impactful
3. High fixes (H1-H4) — including R1 refactor for H4
4. Medium fixes (M1-M6)
5. Low fixes (L1-L5)
6. Refresh vendor payloads
7. Final coverage report and regression verification
