import type { Finding } from "../types.js";

const ALLOWED_SCHEMES = ["https:", "http:", "mailto:", "tel:"];

let findingCounter = 0;
function makeFinding(
  category: Finding["category"],
  severity: Finding["severity"],
  snippet: string,
  description: string,
): Finding {
  findingCounter++;
  return {
    id: `md-${String(findingCounter).padStart(3, "0")}`,
    category,
    severity,
    confidence: "confirmed",
    snippet: snippet.slice(0, 200),
    description,
    action: "removed",
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

function isDangerousScheme(href: string): boolean {
  const normalised = normaliseUri(href);
  for (const scheme of ALLOWED_SCHEMES) {
    if (normalised.startsWith(scheme)) return false;
  }
  // Relative URLs
  if (
    normalised.startsWith("/") ||
    normalised.startsWith("./") ||
    normalised.startsWith("../") ||
    normalised.startsWith("#") ||
    !normalised.includes(":")
  ) {
    return false;
  }
  return true;
}

interface CodeBlock {
  start: number;
  end: number;
  placeholder: string;
  content: string;
}

function extractCodeBlocks(text: string): {
  stripped: string;
  blocks: CodeBlock[];
} {
  const blocks: CodeBlock[] = [];
  let idx = 0;
  const stripped = text.replace(
    /```[\s\S]*?```|`[^`\n]+`/g,
    (match, offset) => {
      const placeholder = `\x00CODEBLOCK${idx++}\x00`;
      blocks.push({
        start: offset,
        end: offset + match.length,
        placeholder,
        content: match,
      });
      return placeholder;
    },
  );
  return { stripped, blocks };
}

function restoreCodeBlocks(text: string, blocks: CodeBlock[]): string {
  let result = text;
  for (const block of blocks) {
    result = result.replace(block.placeholder, block.content);
  }
  return result;
}

export function sanitiseMarkdown(md: string): {
  clean: string;
  findings: Finding[];
} {
  findingCounter = 0;
  const findings: Finding[] = [];

  // Extract code blocks to protect them from sanitisation
  const { stripped, blocks } = extractCodeBlocks(md);
  let content = stripped;

  // Remove raw HTML tags that are dangerous (with closing tag)
  content = content.replace(
    /<(script|iframe|object|embed|form|base|meta|link|style)\b[^>]*>[\s\S]*?<\/\1>/gi,
    (match) => {
      findings.push(
        makeFinding(
          "html_injection",
          "critical",
          match,
          "Dangerous HTML element removed",
        ),
      );
      return "";
    },
  );

  // Self-closing dangerous tags
  content = content.replace(
    /<(script|iframe|object|embed|form|base|meta|link|style)\b[^>]*\/?>/gi,
    (match) => {
      findings.push(
        makeFinding(
          "html_injection",
          "critical",
          match,
          "Dangerous HTML element removed",
        ),
      );
      return "";
    },
  );

  // Strip dangerous href/src from inline HTML anchor/img tags
  content = content.replace(
    /<(a|img)\b([^>]*?)(?:href|src)\s*=\s*["']([^"']*)["']([^>]*)>/gi,
    (match, tag, before, url, after) => {
      if (isDangerousScheme(url)) {
        findings.push(
          makeFinding(
            "script_injection",
            "critical",
            match,
            `Dangerous URI in <${tag}> removed`,
          ),
        );
        return `<${tag}${before}${after}>`;
      }
      return match;
    },
  );

  // Remove event handlers from inline HTML (quoted values)
  content = content.replace(
    /<([a-z][a-z0-9]*)\b([^>]*)\bon\w+\s*=\s*["'][^"']*["']([^>]*)>/gi,
    (match, tag, before, after) => {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Event handler in HTML removed",
        ),
      );
      const cleaned = (before + after).replace(
        /\bon\w+\s*=\s*["'][^"']*["']/gi,
        "",
      );
      return `<${tag}${cleaned}>`;
    },
  );

  // Remove event handlers from inline HTML (unquoted values)
  content = content.replace(
    /<([a-z][a-z0-9]*)\b([^>]*)\bon\w+\s*=\s*[^\s>"']+([^>]*)>/gi,
    (match, tag, before, after) => {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Event handler in HTML removed",
        ),
      );
      const cleaned = (before + after).replace(/\bon\w+\s*=\s*[^\s>"']+/gi, "");
      return `<${tag}${cleaned}>`;
    },
  );

  // Handle image breakout payloads: event handlers in alt text or URL
  // e.g., ![a"onerror="alert(1)](x) or ![a](url"onload="alert(1))
  content = content.replace(
    /!\[([^\]]*(?:onerror|onload|onfocus|onmouseover)[^\]]*)\]\(([^)]*)\)/gi,
    (match) => {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Event handler in image alt text",
        ),
      );
      return "";
    },
  );
  content = content.replace(
    /!\[([^\]]*)\]\(([^)]*(?:onerror|onload|onfocus|onmouseover)[^)]*)\)/gi,
    (match) => {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Event handler in image URL",
        ),
      );
      return "";
    },
  );

  // Image tag with event handler in attributes (e.g. ![a](x onerror=alert(1)))
  content = content.replace(
    /!\[([^\]]*)\]\(([^)]*\s+(?:onerror|onload|onfocus|onmouseover)\s*=[^)]*)\)/gi,
    (match) => {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Event handler in image syntax",
        ),
      );
      return "";
    },
  );

  // Neutralise dangerous links: [text](javascript:...) → [text](#)
  content = content.replace(
    /(\[(?:[^\]]*)\])\(([^)]+)\)/g,
    (match, text, href) => {
      if (isDangerousScheme(href.trim())) {
        findings.push(
          makeFinding(
            "script_injection",
            "critical",
            match,
            `Dangerous URI neutralised: ${href.trim().slice(0, 50)}`,
          ),
        );
        return `${text}(#)`;
      }
      return match;
    },
  );

  // Neutralise dangerous image sources: ![alt](javascript:...) → removed
  content = content.replace(
    /!\[([^\]]*)\]\(([^)]+)\)/g,
    (_match, _alt, src) => {
      if (isDangerousScheme(src.trim())) {
        findings.push(
          makeFinding(
            "script_injection",
            "critical",
            _match,
            `Dangerous image URI removed: ${src.trim().slice(0, 50)}`,
          ),
        );
        return "";
      }
      return _match;
    },
  );

  // General pass: remove any image/link syntax containing event handler patterns
  // (catches HTML-encoded variants from DOMPurify output)
  content = content.replace(/!\[[^\]]*\]\([^)]*\)/g, (match) => {
    if (
      /on(?:error|load|focus|mouseover|click|blur)\s*=/i.test(match) ||
      /on(?:error|load|focus|mouseover|click|blur)(?:&\w+;)*\s*=/i.test(match)
    ) {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Event handler in image syntax",
        ),
      );
      return "";
    }
    return match;
  });
  content = content.replace(/\[[^\]]*\]\([^)]*\)/g, (match) => {
    if (/on(?:error|load|focus|mouseover|click|blur)\s*=/i.test(match)) {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Event handler in link syntax",
        ),
      );
      return match.replace(/\([^)]*\)$/, "(#)");
    }
    return match;
  });

  // Neutralise autolinks with dangerous schemes: <javascript:...>
  content = content.replace(
    /<((?:javascript|vbscript|data|gopher|file|ftp)[^>]*)>/gi,
    (match) => {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Dangerous autolink removed",
        ),
      );
      return "";
    },
  );

  // Neutralise link reference definitions with dangerous schemes
  content = content.replace(
    /^\s*\[([^\]]*)\]:\s*\(?\s*(javascript:|vbscript:|data:text\/html)[^)]*\)?\s*$/gim,
    (match) => {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Dangerous link reference definition removed",
        ),
      );
      return "";
    },
  );

  // Safety net: remove any remaining text containing event handler patterns
  // in image-like constructs (catches Turndown-escaped variants)
  content = content.replace(
    /!?\\\[.*?(?:onerror|onload|onfocus|onmouseover)\s*=.*?\\\]\(.*?\)/gi,
    (match) => {
      findings.push(
        makeFinding(
          "script_injection",
          "critical",
          match,
          "Event handler in escaped image/link syntax",
        ),
      );
      return "";
    },
  );

  // Restore code blocks
  content = restoreCodeBlocks(content, blocks);

  return { clean: content, findings };
}
