import { describe, it, expect } from "vitest";
import { sanitiseHtml } from "../src/convert/sanitise.js";

describe("sanitiseHtml", () => {
  it("3.1 strips <script> tags", () => {
    const { clean, findings } = sanitiseHtml(
      "<p>Hi</p><script>alert(1)</script>",
    );
    expect(clean).not.toContain("<script");
    expect(clean).toContain("<p>Hi</p>");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("3.2 strips event handlers", () => {
    const { clean, findings } = sanitiseHtml(
      '<img src="x" onerror="alert(1)">',
    );
    expect(clean).not.toContain("onerror");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("3.3 strips javascript: hrefs (href removed entirely)", () => {
    const { clean } = sanitiseHtml('<a href="javascript:alert(1)">click</a>');
    expect(clean).not.toContain("javascript:");
    expect(clean).toContain("<a>click</a>");
  });

  it("3.4 strips data:text/html hrefs", () => {
    const { clean } = sanitiseHtml(
      '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">x</a>',
    );
    expect(clean).not.toContain("data:text/html");
    expect(clean).toContain("<a>x</a>");
  });

  it("3.5 strips <iframe>", () => {
    const { clean, findings } = sanitiseHtml(
      '<iframe src="https://evil.com"></iframe>',
    );
    expect(clean).not.toContain("iframe");
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it("3.6 strips <iframe> with local path", () => {
    const { clean } = sanitiseHtml(
      '<iframe src="../../../../cmd.exe"></iframe>',
    );
    expect(clean).not.toContain("iframe");
  });

  it("3.7 strips <object>, <embed>, <form>", () => {
    const { clean } = sanitiseHtml(
      "<object><embed></embed></object><form><input></form>",
    );
    expect(clean).not.toContain("object");
    expect(clean).not.toContain("embed");
    expect(clean).not.toContain("form");
  });

  it("3.8 strips SVG script injection", () => {
    const { clean } = sanitiseHtml('<svg onload="alert(1)"></svg>');
    expect(clean).not.toContain("onload");
  });

  it("3.9 preserves safe HTML", () => {
    const { clean, findings } = sanitiseHtml("<p><strong>bold</strong></p>");
    expect(clean).toBe("<p><strong>bold</strong></p>");
    // No critical/warning findings for safe HTML
    const serious = findings.filter((f) => f.severity !== "info");
    expect(serious.length).toBe(0);
  });

  it("3.10 strips CSS expression()", () => {
    const { clean } = sanitiseHtml(
      '<div style="width:expression(alert(1))">text</div>',
    );
    expect(clean).not.toContain("expression");
  });
});
