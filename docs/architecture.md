# clawfidence Architecture Overview

A TypeScript CLI tool that acts as a **security first-responder for Markdown pipelines**. It takes untrusted HTML or Markdown, runs it through a multi-stage security pipeline, and outputs clean, safe Markdown. Designed for pipelines where content is fed to LLMs, rendered in browsers, or stored for display.

_"Your LLM reads everything... so this tool reads it first."_

---

## Pipeline Architecture

```
stdin/file -> Detect -> Extract (defuddle) -> Sanitise (DOMPurify) -> Convert (Turndown) -> Scan -> Output
```

Six stages, each independently bypassable:

| Stage              | Module                  | Library              | What it does                                                                                                                             |
| ------------------ | ----------------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Detect**      | `detect.ts`             | --                   | Auto-detects HTML vs Markdown (or binary/empty -> exit 3)                                                                                |
| **2. Extract**     | `extract.ts`            | defuddle             | Strips boilerplate (nav, ads, footers), extracts article content + metadata, demotes H1->H2, adaptive retry for thin content             |
| **3. Sanitise**    | `convert/sanitise.ts`   | DOMPurify + jsdom    | Strict HTML allowlist, strips scripts/iframes/forms/events/dangerous URIs, records findings                                              |
| **4. Convert**     | `convert/html-to-md.ts` | Turndown + GFM       | Converts clean HTML to Markdown with fenced code blocks, proper heading styles                                                           |
| **5. MD Sanitise** | `convert/md-to-md.ts`   | regex-based          | 17+ regex passes on Markdown: dangerous links, image breakouts, entity-encoded events, autolinks, reference defs -- all code-block-aware |
| **6. Scan**        | `scanner/*`             | markdown-it + custom | Four scanners run in sequence (see below)                                                                                                |

---

## Four Security Scanners

### XSS Scanner (`scanner/markdown-xss.ts`)

- **Token walk** via markdown-it: checks link/image hrefs for dangerous schemes
- **Raw line scan**: catches link reference abuse, autolink abuse, whitespace-obfuscated `javascript:`, nested parser confusion, event handler injection in alt text/URLs

### URL Scanner (`scanner/url.ts`)

- **Scheme allowlist**: only `http:`, `https:`, `mailto:`, `tel:` permitted -- everything else flagged
- **IDN homograph detection**: flags Punycode (`xn--`) domains
- **IP address detection**: dotted-quad, hex, octal, decimal, IPv6
- **Prefix allowlists**: `--allowed-link-prefixes` / `--allowed-image-prefixes` for domain-level control

### Unicode Scanner (`scanner/unicode.ts`)

- **Zero-width characters**: U+200B, U+200C (ZWNJ), U+200D (ZWJ), U+FEFF, U+2060-2064, U+180E
- **BiDi overrides**: U+202A-202E, U+2066-2069
- **Variation selectors**: U+FE00-FE0F, supplementary U+E0100-E01EF
- **Tag characters**: U+E0001-E007F
- **Mixed-script homoglyphs**: detects words mixing Latin + Cyrillic (e.g. "paypal" with Cyrillic "a")
- Smart exception: legitimate ZWNJ in Arabic/Persian text is not flagged

### Injection Scanner (`scanner/injection.ts`)

- **Pattern matching**: "ignore previous instructions", "SYSTEM:", "you are now", "### NEW INSTRUCTIONS", etc.
- **HTML comments & Markdown comment abuse**: `<!-- -->` and `[//]: # ()` payloads
- **Base64-encoded instructions**: decodes blobs >20 chars and checks for injection keywords
- **Hidden content**: `display:none`, `font-size:0` containing injection keywords
- **Frontmatter injection**: YAML frontmatter with injection patterns
- **Context guards**: skips matches inside code fences or educational context ("here's how to write a system prompt...")

---

## Key Design Principles

1. **Safe by default** -- all sanitisation is on; users opt _out_ of safety, not in
2. **Allowlist over denylist** -- URI schemes, HTML tags, attributes use strict allowlists
3. **Pipeline composability** -- each stage independently bypassable (`--no-extract`, etc.)
4. **Report everything** -- every finding logged with category, severity, confidence, and action taken

---

## CLI Features

- **Exit codes**: 0 (clean), 1 (findings sanitised), 2 (strict mode critical), 3 (bad input)
- **`--llm-safe`**: aggressive mode enabling `--strip-js`, `--strip-html`, `--frontmatter`
- **`--strict`**: exit 2 and suppress output if critical findings found
- **`--report`**: JSON findings report to stderr or file
- **`--frontmatter`**: prepends extracted metadata as YAML
- **`--no-extract`**: skip defuddle for fragments/pre-cleaned HTML
- **`--no-images`**: strip all images

---

## Test Suite

- **150 tests across 12+ files**, all passing
- **5 vendor XSS payload corpora** (cujanovic, HackTricks, Kevil-hui, 666reda, jaydeepnasit)
- **CVE regression tests** (CVE-2024-41662 iframe RCE)
- **False positive suite**: security tutorials, legitimate Unicode, code examples -- ensures they aren't flagged
- **TDD methodology**: all tests written before implementation

---

## URI Normalisation (`normalise-uri.ts`)

The `isDangerousScheme()` function is the core safety gate used across multiple modules. It multi-pass decodes URIs (up to 3 rounds of `decodeURIComponent`), strips whitespace/control chars, lowercases, then checks against the allowlist. This defeats obfuscations like `java%20script:`, `j%61vascript:`, double-encoding, etc.

---

## Module Map

```
stdin/file
     |
     v
  src/index.ts  (CLI, commander)
     |
     v
  src/pipeline.ts  (runPipeline)
     |
     +--[HTML]--> src/detect.ts
     |                |
     |            src/extract.ts  (defuddle)
     |                |
     |            src/convert/sanitise.ts  (DOMPurify)
     |                |
     |            src/convert/html-to-md.ts  (Turndown)
     |                |
     +--[MD]----------+
     |
     v
  src/convert/md-to-md.ts  (regex sanitiser, code-block-aware)
     |
     v
  src/scanner/markdown-xss.ts  (markdown-it token walk + raw line scan)
     |
     v
  src/scanner/url.ts  (URL extraction, scheme/IP/IDN/prefix checks)
     |
     v
  src/scanner/unicode.ts  (zero-width, BiDi, variation selectors, homoglyphs)
     |
     v
  src/scanner/injection.ts  (prompt injection, hidden content, base64, comments)
     |
     v
  [optional] src/frontmatter.ts
     |
     v
  src/reporter.ts  (JSON/text findings report)
     |
     v
  stdout (clean Markdown) + stderr (findings count or report)
  exit code: 0 (clean) | 1 (issues sanitised) | 2 (strict+critical) | 3 (error)
```

---

## Dependencies

| Library                        | Role                                               |
| ------------------------------ | -------------------------------------------------- |
| **defuddle** (`defuddle/node`) | Content extraction, HTML standardisation, metadata |
| **DOMPurify** + **jsdom**      | HTML sanitisation (XSS, script injection)          |
| **Turndown** + GFM plugin      | HTML -> Markdown conversion                        |
| **markdown-it**                | Markdown parsing and AST for scanning              |
| **commander**                  | CLI argument parsing                               |
