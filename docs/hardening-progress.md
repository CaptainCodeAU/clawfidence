# Hardening Progress

## Tasks

| # | ID | Severity | Description | Status |
|---|-----|----------|-------------|--------|
| 1 | — | — | Install coverage tooling and establish baseline | ✅ |
| 2 | R1 | — | Extract shared normaliseUri utility | ✅ |
| 3 | C1 | Critical | Fix looksEducational bypass | ✅ |
| 4 | H1 | High | Fix SYSTEM: case sensitivity | ✅ |
| 5 | H2 | High | Fix display:none single-quote bypass | ✅ |
| 6 | H3 | High | Fix IDN check only examines leftmost label | ✅ |
| 7 | M6 | Medium | Remove SVG/MathML from DOMPurify allowlist | ✅ |
| 8 | M1 | Medium | Angle-bracket link ref definitions | ✅ |
| 9 | M2 | Medium | Unclosed script tags | ✅ |
| 10 | M3 | Medium | IP detection for IPv6/octal/hex/decimal | ✅ |
| 11 | M5 | Medium | Prefix allowlist case sensitivity | ✅ |
| 12 | M4 | Medium | HTML entity-encoded event handlers | ✅ |
| 13 | L4 | Low | Tilde fence tracking | ⬜ |
| 14 | L5 | Low | Broaden event handler detection | ⬜ |
| 15 | L3 | Low | Variation selector detection | ⬜ |
| 16 | L2 | Low | Mixed-script homoglyph detection | ⬜ |
| 17 | — | — | Final coverage report and full regression | ⬜ |

## Test Count Progression

| Batch | Tests | Notes |
|-------|-------|-------|
| Baseline | 150 | Initial test suite |
| Batch 1 (Tasks 1-4) | 159 | Coverage tooling, normaliseUri, C1, H1 |
| Batch 2 (Tasks 5-7) | 165 | H2, H3, M6 |
| Batch 3 (Tasks 8-9) | 174 | M1, M2 |
| Batch 4 (Tasks 10-12) | 183 | M3, M5, M4 |
