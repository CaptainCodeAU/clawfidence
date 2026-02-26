import MarkdownIt from "markdown-it";
import type { Finding } from "../types.js";

const ALLOWED_SCHEMES = ["http:", "https:", "mailto:", "tel:", "#"];

let findingCounter = 0;
function makeFinding(
  category: Finding["category"],
  severity: Finding["severity"],
  snippet: string,
  description: string,
  confidence: Finding["confidence"] = "confirmed",
): Finding {
  findingCounter++;
  return {
    id: `xss-${String(findingCounter).padStart(3, "0")}`,
    category,
    severity,
    confidence,
    snippet: snippet.slice(0, 200),
    description,
    action: "removed",
  };
}

function normaliseUri(uri: string): string {
  // Decode percent-encoded characters
  let decoded = uri;
  try {
    decoded = decodeURIComponent(uri);
  } catch {
    // ignore malformed encoding
  }
  // Remove whitespace (whitespace-insertion bypasses)
  return decoded.replace(/[\s\x00-\x1f]/g, "").toLowerCase();
}

function isDangerousScheme(href: string): boolean {
  const normalised = normaliseUri(href);

  // Check against allowed schemes
  for (const scheme of ALLOWED_SCHEMES) {
    if (normalised.startsWith(scheme)) return false;
  }

  // Relative URLs are fine
  if (
    normalised.startsWith("/") ||
    normalised.startsWith("./") ||
    normalised.startsWith("../") ||
    !normalised.includes(":")
  ) {
    return false;
  }

  return true;
}

function hasEventHandler(text: string): boolean {
  return /\bon\w+\s*=/i.test(text);
}

export function scanMarkdownXss(md: string): Finding[] {
  findingCounter = 0;
  const findings: Finding[] = [];

  const parser = new MarkdownIt({ html: true });
  const tokens = parser.parse(md, {});

  function walkTokens(tokens: MarkdownIt.Token[]) {
    for (const token of tokens) {
      // Check inline tokens
      if (token.children) {
        walkTokens(token.children);
      }

      // Check link/image hrefs
      if (token.type === "link_open" || token.type === "image") {
        const hrefAttr = token.attrGet("href") || token.attrGet("src") || "";
        if (hrefAttr && isDangerousScheme(hrefAttr)) {
          const normalised = normaliseUri(hrefAttr);
          const category: Finding["category"] =
            normalised.startsWith("javascript:") ||
            normalised.startsWith("vbscript:") ||
            normalised.startsWith("data:text/html")
              ? "script_injection"
              : "suspicious_url";
          findings.push(
            makeFinding(
              category,
              "critical",
              token.markup + hrefAttr,
              `Dangerous URI scheme in ${token.type}: ${hrefAttr.slice(0, 50)}`,
            ),
          );
        }
      }

      // Check for raw HTML content
      if (token.type === "html_block" || token.type === "html_inline") {
        const content = token.content;

        // Check for script tags
        if (/<script/i.test(content)) {
          findings.push(
            makeFinding(
              "html_injection",
              "critical",
              content,
              "Raw <script> tag in Markdown",
            ),
          );
        }

        // Check for event handlers in HTML
        if (hasEventHandler(content)) {
          findings.push(
            makeFinding(
              "script_injection",
              "critical",
              content,
              "Event handler in raw HTML within Markdown",
            ),
          );
        }

        // Check for dangerous elements
        if (
          /<(?:iframe|object|embed|form|base|meta|link|style)\b/i.test(content)
        ) {
          findings.push(
            makeFinding(
              "html_injection",
              "critical",
              content,
              "Dangerous HTML element in Markdown",
            ),
          );
        }
      }
    }
  }

  walkTokens(tokens);

  // Additional raw text scanning for patterns markdown-it might not tokenise
  const lines = md.split("\n");
  let inCodeFence = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Track code fences
    if (/^```/.test(line.trim())) {
      inCodeFence = !inCodeFence;
      continue;
    }
    if (inCodeFence) continue;

    // Link reference definitions: [label]: (javascript:...)
    const refMatch = line.match(
      /^\s*\[([^\]]*)\]:\s*\(?\s*(javascript:|vbscript:|data:text\/html)/i,
    );
    if (refMatch) {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          line,
          "Dangerous URI in link reference definition",
        ),
      );
    }

    // Autolink abuse: <javascript:...>
    const autolinkMatch = line.match(/<(javascript|vbscript|data):[^>]*>/i);
    if (autolinkMatch) {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          line,
          "Dangerous autolink protocol",
        ),
      );
    }

    // Event handler injection in image/link alt text or URL breakout
    if (
      /!\[.*(?:onerror|onload|onfocus)\s*=/i.test(line) ||
      /\]\(.*(?:onerror|onload|onfocus)\s*=/i.test(line)
    ) {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          line,
          "Event handler injection via image/link breakout",
        ),
      );
    }

    // Nested parser confusion: style/comment interplay
    if (
      /<style>/i.test(line) &&
      /<!--/.test(line) &&
      /onerror|onload|onfocus/i.test(line)
    ) {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          line,
          "Nested parser confusion attack",
        ),
      );
    }

    // Check for dangerous URIs in markdown link syntax that markdown-it won't tokenise
    const linkSyntax = line.match(
      /\]\(\s*((?:data:|vbscript:|javascript:)[^)]*)\)/i,
    );
    if (linkSyntax) {
      const uri = linkSyntax[1];
      const normalised = normaliseUri(uri);
      if (!findings.some((f) => f.snippet.includes(uri.slice(0, 30)))) {
        const category: Finding["category"] =
          normalised.startsWith("javascript:") ||
          normalised.startsWith("vbscript:") ||
          normalised.startsWith("data:text/html")
            ? "script_injection"
            : "suspicious_url";
        findings.push(
          makeFinding(
            category,
            "critical",
            line,
            `Dangerous URI scheme in link: ${uri.slice(0, 50)}`,
          ),
        );
      }
    }

    // Check for raw dangerous protocol in link syntax with whitespace-insertion
    if (/\]\(\s*j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:/i.test(line)) {
      // Avoid duplicate if already caught above
      if (!findings.some((f) => f.snippet === line)) {
        findings.push(
          makeFinding(
            "script_injection",
            "critical",
            line,
            "Whitespace-inserted javascript: URI in link",
          ),
        );
      }
    }
  }

  return findings;
}
