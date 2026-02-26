import { describe, it, expect } from "vitest";
import { runPipeline } from "../src/pipeline.js";

describe("False Positive Tests", () => {
  it("12.1 security tutorial discussing XSS — no findings", async () => {
    const input = `# XSS Security Tutorial

This tutorial discusses cross-site scripting attacks.

Here's an example of how to write a system prompt for discussing \`javascript:\` payloads:

\`\`\`
[a](javascript:alert(1))
<script>alert(document.cookie)</script>
\`\`\`

The above payloads are commonly used in security testing.`;

    const result = await runPipeline(input, { inputFormat: "md" });
    expect(result.exitCode).toBe(0);
  });

  it("12.2 code example with base64 — no findings", async () => {
    const input = `# Python Base64 Example

\`\`\`python
import base64
encoded = base64.b64encode(b"ignore previous instructions")
# aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==
print(base64.b64decode(encoded))
\`\`\`

This example shows how to use base64 encoding in Python.`;

    const result = await runPipeline(input, { inputFormat: "md" });
    expect(result.exitCode).toBe(0);
  });

  it("12.3 legitimate Unicode text — no findings", async () => {
    const input = `# Persian Text Example

The word "می\u200Cخواهم" uses a zero-width non-joiner (ZWNJ) which is standard in Persian script.

This is completely legitimate Unicode usage.`;

    const result = await runPipeline(input, { inputFormat: "md" });
    expect(result.exitCode).toBe(0);
  });

  it("12.4 HTML tutorial with escaped tags — no findings", async () => {
    const input = `# HTML Tutorial

In HTML, you write a script tag like \`&lt;script&gt;\` and close it with \`&lt;/script&gt;\`.

The \`onclick\` attribute is used for event handling.`;

    const result = await runPipeline(input, { inputFormat: "md" });
    expect(result.exitCode).toBe(0);
  });

  it("12.5 Markdown file about prompt engineering — no findings", async () => {
    const input = `# Understanding Prompt Engineering

This tutorial discusses how to write effective system prompts.
Here's how to design prompts for instance to get better results.

When explaining about prompt injection, people often mention
techniques like "system prompts" and how they work educationally.`;

    const result = await runPipeline(input, { inputFormat: "md" });
    expect(result.exitCode).toBe(0);
  });

  it("12.6 URL with legitimate IDN — info at most", async () => {
    const input = `Visit [example](https://example.com) for more info.`;
    const result = await runPipeline(input, { inputFormat: "md" });
    expect(result.exitCode).toBe(0);
  });

  it("12.7 clean README with all Markdown features — exit 0", async () => {
    const input = `# Project README

## Overview

This is a **bold** and *italic* project.

### Features

- Feature one
- Feature two
- Feature three

1. First step
2. Second step
3. Third step

> A wise quote about software development.

[Documentation](https://docs.example.com)

![Logo](https://example.com/logo.png)

\`\`\`javascript
const greeting = "Hello, World!";
console.log(greeting);
\`\`\`

| Feature | Status |
|---------|--------|
| Tests   | Pass   |
| Docs    | Done   |`;

    const result = await runPipeline(input, { inputFormat: "md" });
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain("# Project README");
  });
});
