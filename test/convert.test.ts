import { describe, it, expect } from "vitest";
import { htmlToMarkdown } from "../src/convert/html-to-md.js";
import { sanitiseMarkdown } from "../src/convert/md-to-md.js";

describe("htmlToMarkdown", () => {
  it("4.1 converts headings", () => {
    expect(htmlToMarkdown("<h2>Title</h2>")).toBe("## Title");
  });

  it("4.2 converts paragraphs", () => {
    expect(htmlToMarkdown("<p>Hello world</p>")).toBe("Hello world");
  });

  it("4.3 converts bold/italic", () => {
    const md = htmlToMarkdown("<strong>b</strong> <em>i</em>");
    expect(md).toContain("**b**");
    expect(md).toContain("*i*");
  });

  it("4.4 converts links", () => {
    const md = htmlToMarkdown('<a href="https://x.com">link</a>');
    expect(md).toBe("[link](https://x.com)");
  });

  it("4.5 converts images", () => {
    const md = htmlToMarkdown('<img src="img.png" alt="pic">');
    expect(md).toBe("![pic](img.png)");
  });

  it("4.6 converts fenced code blocks with language", () => {
    const md = htmlToMarkdown(
      '<pre><code class="language-js">const x = 1;</code></pre>',
    );
    expect(md).toContain("```js");
    expect(md).toContain("const x = 1;");
    expect(md).toContain("```");
  });

  it("4.7 converts tables", () => {
    const html = `<table>
      <thead><tr><th>A</th><th>B</th></tr></thead>
      <tbody><tr><td>1</td><td>2</td></tr></tbody>
    </table>`;
    const md = htmlToMarkdown(html);
    expect(md).toContain("| A | B |");
    expect(md).toContain("| 1 | 2 |");
  });

  it("4.8 converts ordered/unordered lists", () => {
    const ulMd = htmlToMarkdown("<ul><li>item</li></ul>");
    expect(ulMd).toMatch(/^-\s+item$/m);

    const olMd = htmlToMarkdown("<ol><li>item</li></ol>");
    expect(olMd).toMatch(/^1\.\s+item$/m);
  });

  it("4.9 converts blockquotes", () => {
    const md = htmlToMarkdown("<blockquote><p>quote</p></blockquote>");
    expect(md).toContain("> quote");
  });

  it("4.11 sanitiseMarkdown strips angle-bracket link ref definition", () => {
    const { clean } = sanitiseMarkdown("[foo]: <javascript:alert(1)>");
    expect(clean).not.toContain("javascript:");
  });

  it("4.12 sanitiseMarkdown strips unclosed script tags", () => {
    const { clean } = sanitiseMarkdown("<script>evil code here");
    expect(clean).not.toContain("<script");
    expect(clean).not.toContain("evil code here");
  });

  it("4.13 sanitiseMarkdown strips unclosed iframe tags", () => {
    const { clean } = sanitiseMarkdown("<iframe src=evil.com>content after");
    expect(clean).not.toContain("<iframe");
  });

  it("4.14 sanitiseMarkdown strips entity-encoded event handler (decimal)", () => {
    const { clean, findings } = sanitiseMarkdown("<img src=x onerror&#61;alert(1)>");
    expect(clean).not.toContain("onerror");
    expect(clean).not.toContain("alert");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("4.15 sanitiseMarkdown strips entity-encoded event handler (hex)", () => {
    const { clean, findings } = sanitiseMarkdown("<img src=x onerror&#x3d;alert(1)>");
    expect(clean).not.toContain("onerror");
    expect(clean).not.toContain("alert");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("4.16 sanitiseMarkdown strips entity-encoded event handler (named)", () => {
    const { clean, findings } = sanitiseMarkdown("<img src=x onerror&equals;alert(1)>");
    expect(clean).not.toContain("onerror");
    expect(clean).not.toContain("alert");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("4.10 --no-images strips images", () => {
    const md = htmlToMarkdown(
      '<p>text</p><img src="img.png" alt="pic"><p>more</p>',
      { noImages: true },
    );
    expect(md).not.toContain("![");
    expect(md).not.toContain("img.png");
    expect(md).toContain("text");
  });
});
