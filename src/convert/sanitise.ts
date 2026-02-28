import { JSDOM } from "jsdom";
import DOMPurify from "dompurify";
import type { Finding } from "../types.js";

let findingCounter = 0;

function makeFinding(
  category: Finding["category"],
  severity: Finding["severity"],
  snippet: string,
  description: string,
): Finding {
  findingCounter++;
  return {
    id: `f-${String(findingCounter).padStart(3, "0")}`,
    category,
    severity,
    confidence: "confirmed",
    snippet: snippet.slice(0, 100),
    description,
    action: "removed",
  };
}

export function sanitiseHtml(html: string): {
  clean: string;
  findings: Finding[];
} {
  findingCounter = 0;
  const findings: Finding[] = [];

  const window = new JSDOM("").window;
  const purify = DOMPurify(window as unknown as Window);

  // Track what gets removed
  purify.addHook("uponSanitizeElement", (node, data) => {
    if (
      data.allowedTags[data.tagName] === false ||
      !data.allowedTags[data.tagName]
    ) {
      const tagName = data.tagName;
      if (
        [
          "script",
          "iframe",
          "object",
          "embed",
          "form",
          "base",
          "meta",
        ].includes(tagName)
      ) {
        findings.push(
          makeFinding(
            "script_injection",
            "critical",
            (node as Element).outerHTML || `<${tagName}>`,
            `Dangerous <${tagName}> element removed`,
          ),
        );
      }
    }
  });

  purify.addHook("uponSanitizeAttribute", (node, data) => {
    // Event handlers
    if (data.attrName.startsWith("on")) {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          `${data.attrName}="${data.attrValue}"`,
          `Event handler attribute '${data.attrName}' removed`,
        ),
      );
    }
    // javascript: or data:text/html hrefs
    if (
      (data.attrName === "href" || data.attrName === "src") &&
      data.attrValue
    ) {
      const val = data.attrValue.toLowerCase().replace(/\s/g, "");
      if (val.startsWith("javascript:") || val.startsWith("data:text/html")) {
        findings.push(
          makeFinding(
            "script_injection",
            "critical",
            `${data.attrName}="${data.attrValue}"`,
            `Dangerous URI scheme in ${data.attrName} removed`,
          ),
        );
      }
    }
    // CSS expression()
    if (data.attrName === "style" && data.attrValue) {
      if (/expression\s*\(/i.test(data.attrValue)) {
        findings.push(
          makeFinding(
            "script_injection",
            "critical",
            `style="${data.attrValue}"`,
            "CSS expression() removed",
          ),
        );
      }
    }
  });

  const clean = purify.sanitize(html, {
    ALLOW_TAGS: [
      "p",
      "br",
      "hr",
      "h1",
      "h2",
      "h3",
      "h4",
      "h5",
      "h6",
      "strong",
      "b",
      "em",
      "i",
      "u",
      "s",
      "del",
      "ins",
      "a",
      "img",
      "ul",
      "ol",
      "li",
      "dl",
      "dt",
      "dd",
      "table",
      "thead",
      "tbody",
      "tfoot",
      "tr",
      "th",
      "td",
      "caption",
      "blockquote",
      "pre",
      "code",
      "span",
      "div",
      "section",
      "article",
      "figure",
      "figcaption",
      "details",
      "summary",
      "sup",
      "sub",
      "abbr",
      "mark",
      "small",
      "cite",
      "q",
      "dfn",
      "var",
      "kbd",
      "samp",
      "ruby",
      "rt",
      "rp",
      "bdo",
      "wbr",
    ],
    ALLOW_ATTR: [
      "href",
      "src",
      "alt",
      "title",
      "class",
      "id",
      "colspan",
      "rowspan",
      "scope",
      "lang",
      "dir",
      "width",
      "height",
      "start",
      "reversed",
      "type",
      "cite",
      "datetime",
      "open",
    ],
    ALLOW_DATA_ATTR: false,
    FORBID_TAGS: [
      "script",
      "style",
      "iframe",
      "object",
      "embed",
      "form",
      "input",
      "textarea",
      "select",
      "button",
      "base",
      "link",
      "meta",
      "noscript",
      "template",
      "svg",
      "math",
    ],
    FORBID_ATTR: ["style"],
  });

  // Remove hooks to prevent leaking between calls
  purify.removeAllHooks();

  return { clean, findings };
}
