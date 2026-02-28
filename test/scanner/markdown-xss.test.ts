import { describe, it, expect } from "vitest";
import { scanMarkdownXss } from "../../src/scanner/markdown-xss.js";

describe("scanMarkdownXss", () => {
  it("5.1 detects javascript: in link", () => {
    const findings = scanMarkdownXss("[a](javascript:alert(1))");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.2 detects case-variant javascript:", () => {
    const findings = scanMarkdownXss("[a](JaVaScRiPt:alert(1))");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.3 detects whitespace-inserted javascript:", () => {
    const findings = scanMarkdownXss("[a](j a v a s c r i p t:prompt(1))");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.4 detects data:text/html in link", () => {
    const findings = scanMarkdownXss(
      "[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)",
    );
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.5 detects image onerror breakout", () => {
    const findings = scanMarkdownXss('![a"onerror="alert(1)](x)');
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.6 detects image onload breakout", () => {
    const findings = scanMarkdownXss('![a](url"onload="alert(1))');
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.7 detects link ref definition abuse", () => {
    const findings = scanMarkdownXss("[lol]: (javascript:prompt(1))");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.8 detects autolink protocol abuse", () => {
    const findings = scanMarkdownXss("<javascript:alert('XSS')>");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.9 detects nested parser confusion", () => {
    const findings = scanMarkdownXss(
      `[x](y '<style>')<!--</style><div id="x--><img src=1 onerror=alert(1)>">`,
    );
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.10 detects raw <script> in Markdown", () => {
    const findings = scanMarkdownXss("Hello <script>alert(1)</script>");
    expect(findings.some((f) => f.category === "html_injection")).toBe(true);
  });

  it("5.11 detects gopher: protocol", () => {
    const findings = scanMarkdownXss("![a](gopher://127.0.0.1:1337/test)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("5.12 detects vbscript: protocol", () => {
    const findings = scanMarkdownXss("[a](vbscript:alert(1))");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("5.14 detects angle-bracket link ref definition abuse", () => {
    const findings = scanMarkdownXss("[foo]: <javascript:alert(1)>");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("L4: does not flag content inside tilde code fences", () => {
    const md = "~~~\n<script>alert(1)</script>\n~~~";
    const findings = scanMarkdownXss(md);
    expect(findings).toHaveLength(0);
  });

  it("L4: still flags content after tilde code fence closes", () => {
    const md = "~~~\nsafe code\n~~~\n<script>alert(1)</script>";
    const findings = scanMarkdownXss(md);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("L5: detects exotic event handlers in image breakout", () => {
    const md = '![a"onanimationstart="alert(1)](x)';
    const findings = scanMarkdownXss(md);
    expect(findings.some(f => f.category === "script_injection")).toBe(true);
  });

  it("L5: detects onpointerover in nested parser confusion", () => {
    const md = '<style><!--</style><img src=x onpointerover=alert(1)>-->';
    const findings = scanMarkdownXss(md);
    expect(findings.some(f => f.category === "script_injection")).toBe(true);
  });

  it("5.13 non-allowlisted scheme passes clean", () => {
    const findings = scanMarkdownXss("[a](https://example.com)");
    expect(findings.length).toBe(0);
  });
});
