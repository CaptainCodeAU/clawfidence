# Hardening Implementation Progress

Tracking 17 tasks across 6 batches fixing security bypass vectors discovered during audit.

**Branch:** Merged to `master`

---

## Batch 1 — Coverage + Critical ✅

| Task | ID    | Severity | Description                                                             | Status |
| ---- | ----- | -------- | ----------------------------------------------------------------------- | ------ |
| 1    | —     | —        | Install @vitest/coverage-v8, establish baseline (95.98% stmts)          | ✅     |
| 2    | R1/H4 | Refactor | Extract shared `normaliseUri` with multi-pass decoding                  | ✅     |
| 3    | C1    | CRITICAL | Replace global `looksEducational` bypass with per-finding context check | ✅     |

## Batch 2 — High Severity ✅

| Task | ID  | Severity | Description                                                    | Status |
| ---- | --- | -------- | -------------------------------------------------------------- | ------ |
| 4    | H1  | HIGH     | Make SYSTEM: prefix detection case-insensitive                 | ✅     |
| 5    | H2  | HIGH     | Handle single-quoted style attrs in hidden content detection   | ✅     |
| 6    | H3  | HIGH     | Check all hostname labels for IDN homograph, not just leftmost | ✅     |

## Batch 3 — Medium Severity (part 1) ✅

| Task | ID  | Severity | Description                                                                         | Status |
| ---- | --- | -------- | ----------------------------------------------------------------------------------- | ------ |
| 7    | M6  | MEDIUM   | Remove SVG and MathML from DOMPurify allowed tags                                   | ✅     |
| 8    | M1  | MEDIUM   | Detect angle-bracket link ref definitions (already handled, added regression tests) | ✅     |
| 9    | M2  | MEDIUM   | Remove unclosed dangerous HTML tags with content                                    | ✅     |

## Batch 4 — Medium Severity (part 2) ✅

| Task | ID  | Severity | Description                                               | Status |
| ---- | --- | -------- | --------------------------------------------------------- | ------ |
| 10   | M3  | MEDIUM   | Detect IPv6, hex, decimal, and octal IP addresses in URLs | ✅     |
| 11   | M5  | MEDIUM   | Case-insensitive prefix allowlist matching                | ✅     |
| 12   | M4  | MEDIUM   | Detect HTML entity-encoded event handlers                 | ✅     |

## Batch 5 — Low Severity (part 1) ✅

| Task | ID  | Severity | Description                                           | Status |
| ---- | --- | -------- | ----------------------------------------------------- | ------ |
| 13   | L4  | LOW      | Track tilde code fences (`~~~`) in all scanners       | ✅     |
| 14   | L5  | LOW      | Broaden event handler detection to `on[a-z]+` pattern | ✅     |
| 15   | L3  | LOW      | Detect variation selectors in unicode scanner         | ✅     |

## Batch 6 — Low Severity (part 2) + Final

| Task | ID  | Severity | Description                                                   | Status |
| ---- | --- | -------- | ------------------------------------------------------------- | ------ |
| 16   | L2  | LOW      | Detect mixed Latin-Cyrillic homoglyph attacks                 | ⬜     |
| 17   | —   | —        | Run final coverage report, full regression, XSS payload suite | ⬜     |

---

## Test Count Progression

| After Batch | Tests Passing |
| ----------- | ------------- |
| Baseline    | 150           |
| Batch 1     | 162           |
| Batch 2     | 168           |
| Batch 3     | 174           |
| Batch 4     | 183           |
| Batch 5     | 199           |
