import MarkdownIt from "markdown-it";
import type { Finding } from "../types.js";

const ALLOWED_SCHEMES = ["https:", "http:", "mailto:", "tel:"];

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
    id: `url-${String(findingCounter).padStart(3, "0")}`,
    category,
    severity,
    confidence,
    snippet: snippet.slice(0, 200),
    description,
    action: "flagged",
  };
}

function normaliseUri(uri: string): string {
  let decoded = uri;
  try {
    decoded = decodeURIComponent(uri);
  } catch {
    // ignore
  }
  return decoded.replace(/[\s\x00-\x1f]/g, "").toLowerCase();
}

function isIpAddress(hostname: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

function isIdnHomograph(hostname: string): boolean {
  return hostname.startsWith("xn--");
}

function extractUrls(
  md: string,
): Array<{ url: string; type: "link" | "image"; line: string }> {
  const urls: Array<{ url: string; type: "link" | "image"; line: string }> = [];

  const parser = new MarkdownIt({ html: true });
  const tokens = parser.parse(md, {});

  function walkTokens(tokens: MarkdownIt.Token[]) {
    for (const token of tokens) {
      if (token.children) walkTokens(token.children);

      if (token.type === "link_open") {
        const href = token.attrGet("href");
        if (href) urls.push({ url: href, type: "link", line: href });
      }
      if (token.type === "image") {
        const src = token.attrGet("src");
        if (src) urls.push({ url: src, type: "image", line: src });
      }
    }
  }
  walkTokens(tokens);

  // Also scan raw text for URLs in markdown link/image syntax (skip code fences)
  const strippedMd = md
    .replace(/```[\s\S]*?```/g, "")
    .replace(/`[^`\n]+`/g, "");
  const linkRegex = /(!?)\[([^\]]*)\]\(([^)]+)\)/g;
  let match;
  while ((match = linkRegex.exec(strippedMd)) !== null) {
    const url = match[3].trim();
    const type = match[1] === "!" ? "image" : "link";
    if (!urls.some((u) => u.url === url)) {
      urls.push({ url, type, line: match[0] });
    }
  }

  return urls;
}

export function scanUrls(
  md: string,
  options?: {
    allowedLinkPrefixes?: string[];
    allowedImagePrefixes?: string[];
  },
): Finding[] {
  findingCounter = 0;
  const findings: Finding[] = [];
  const urls = extractUrls(md);

  for (const { url, type, line } of urls) {
    const normalised = normaliseUri(url);

    // Check for dangerous schemes (percent-encoded javascript: etc.)
    if (
      normalised.startsWith("javascript:") ||
      normalised.startsWith("vbscript:") ||
      normalised.startsWith("data:text/html")
    ) {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          line,
          `Dangerous URI scheme detected: ${url.slice(0, 50)}`,
        ),
      );
      continue;
    }

    // Check scheme allowlist
    let hasAllowedScheme = false;
    for (const scheme of ALLOWED_SCHEMES) {
      if (normalised.startsWith(scheme)) {
        hasAllowedScheme = true;
        break;
      }
    }

    // Relative URLs are fine
    if (
      !hasAllowedScheme &&
      !normalised.startsWith("/") &&
      !normalised.startsWith("./") &&
      !normalised.startsWith("../") &&
      !normalised.startsWith("#")
    ) {
      if (normalised.includes(":")) {
        findings.push(
          makeFinding(
            "suspicious_url",
            "warning",
            line,
            `Non-allowlisted URI scheme: ${url.slice(0, 50)}`,
          ),
        );
        continue;
      }
    }

    // Parse URL for further checks
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      continue;
    }

    // IDN homograph detection
    if (isIdnHomograph(parsed.hostname)) {
      findings.push(
        makeFinding(
          "suspicious_url",
          "warning",
          line,
          `Internationalised domain name (possible homograph attack): ${parsed.hostname}`,
          "suspicious",
        ),
      );
    }

    // IP address URL
    if (isIpAddress(parsed.hostname)) {
      findings.push(
        makeFinding(
          "suspicious_url",
          "warning",
          line,
          `IP address URL: ${parsed.hostname}`,
        ),
      );
    }

    // Prefix allowlists
    if (type === "link" && options?.allowedLinkPrefixes) {
      const allowed = options.allowedLinkPrefixes.some((prefix) =>
        url.startsWith(prefix),
      );
      if (!allowed) {
        findings.push(
          makeFinding(
            "suspicious_url",
            "warning",
            line,
            `Link does not match allowed prefixes: ${url.slice(0, 50)}`,
          ),
        );
      }
    }

    if (type === "image" && options?.allowedImagePrefixes) {
      const allowed = options.allowedImagePrefixes.some((prefix) =>
        url.startsWith(prefix),
      );
      if (!allowed) {
        findings.push(
          makeFinding(
            "suspicious_url",
            "warning",
            line,
            `Image does not match allowed prefixes: ${url.slice(0, 50)}`,
          ),
        );
      }
    }
  }

  return findings;
}
