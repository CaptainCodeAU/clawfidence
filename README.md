# clawfidence

First responder for your Markdown pipeline. Defangs prompt injection, strips XSS, and sanitises HTML. Your LLM reads everything... so this tool reads it first.

## What it does

`clawfidence` is a TypeScript CLI that takes untrusted HTML or Markdown, runs it through a multi-stage security pipeline, and outputs clean, safe Markdown. It's designed for pipelines where content is fed to LLMs, rendered in browsers, or stored for later display.

**Pipeline:** detect &rarr; extract (defuddle) &rarr; sanitise (DOMPurify) &rarr; convert (Turndown) &rarr; scan (markdown-it) &rarr; output

**Scanners:**

- **XSS** &mdash; dangerous URIs, event handlers (including entity-encoded), script tags, unclosed dangerous tags, image breakout payloads
- **Prompt injection** &mdash; "ignore previous instructions", SYSTEM: prefix (case-insensitive), hidden content, base64-encoded payloads
- **URL** &mdash; scheme allowlisting, IDN homograph detection (all labels), IPv4/IPv6/hex/octal/decimal IP addresses, case-insensitive prefix allowlists
- **Unicode** &mdash; zero-width characters, bidirectional overrides, variation selectors, mixed-script homoglyph detection
- **Supply chain** &mdash; pipe-to-shell (`curl | bash`), binary downloads to system paths, privilege escalation installs, `chmod +x` on system paths, package manager installs

## Install

```bash
pnpm install
pnpm run build
```

## Usage

```bash
# Pipe HTML from stdin
curl -s https://example.com | clawfidence

# Process a file
clawfidence page.html

# Markdown input (auto-detected)
clawfidence notes.md

# Write to file
clawfidence page.html -o clean.md

# LLM-safe mode (aggressive sanitisation)
clawfidence page.html --llm-safe

# Strict mode (exit 2 on critical findings)
clawfidence untrusted.md --strict

# JSON report to stderr
clawfidence page.html --report

# Skip content extraction (for fragments or pre-cleaned HTML)
clawfidence fragment.html --no-extract

# URL prefix allowlists
clawfidence page.html --allowed-link-prefixes "https://trusted.com,https://cdn.example.com"
```

## CLI Options

| Flag                              | Description                                      |
| --------------------------------- | ------------------------------------------------ |
| `--input-format html\|md`         | Override auto-detection                          |
| `--no-extract`                    | Skip defuddle content extraction                 |
| `--no-images`                     | Remove all images                                |
| `--strip-html`                    | Strip all HTML from Markdown output              |
| `--strip-js`                      | Strip all JavaScript                             |
| `--strict`                        | Exit code 2 if critical findings                 |
| `--llm-safe`                      | Aggressive sanitisation for LLM consumption      |
| `--frontmatter`                   | Prepend YAML frontmatter with extracted metadata |
| `--report [path]`                 | Output JSON report to stderr or file             |
| `--report-format json\|text`      | Report format (default: json)                    |
| `-o, --output <path>`             | Write output to file                             |
| `--allowed-link-prefixes <list>`  | Comma-separated allowed URL prefixes for links   |
| `--allowed-image-prefixes <list>` | Comma-separated allowed URL prefixes for images  |
| `--quiet`                         | Suppress stderr output except errors             |
| `--verbose`                       | Detailed stderr logging                          |

## Exit Codes

| Code | Meaning                                          |
| ---- | ------------------------------------------------ |
| 0    | Clean &mdash; no findings                        |
| 1    | Findings reported but content emitted            |
| 2    | Critical findings in `--strict` mode (no output) |
| 3    | Bad input (empty, binary, unreadable)            |

## Design Principles

- **Safe by default** &mdash; all sanitisation is on; users opt _out_ of safety, not in
- **Allowlist over denylist** &mdash; URI schemes, HTML tags, and attributes use strict allowlists
- **Pipeline composability** &mdash; each stage is independently bypassable and testable
- **Report everything** &mdash; every finding is logged with category, severity, confidence, and action taken

## Development

```bash
pnpm run test              # Full suite
pnpm run test:watch        # Watch mode
pnpm run test:coverage     # Coverage report
pnpm run test:xss-payloads # XSS payload regression suite
pnpm run test:cve          # CVE reproduction tests
```

Built with TypeScript (strict, ESM), tested with vitest.

## License

ISC
