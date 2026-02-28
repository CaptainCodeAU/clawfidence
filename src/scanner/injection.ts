import type { Finding } from "../types.js";

let findingCounter = 0;
function makeFinding(
  severity: Finding["severity"],
  snippet: string,
  description: string,
  confidence: Finding["confidence"] = "confirmed",
): Finding {
  findingCounter++;
  return {
    id: `inj-${String(findingCounter).padStart(3, "0")}`,
    category: "prompt_injection",
    severity,
    confidence,
    snippet: snippet.slice(0, 200),
    description,
    action: "flagged",
  };
}

const INJECTION_PATTERNS = [
  {
    pattern: /ignore\s+(all\s+)?previous\s+instructions/i,
    desc: 'Detected "ignore previous instructions" pattern',
  },
  {
    pattern: /forget\s+everything\s+above/i,
    desc: 'Detected "forget everything above" pattern',
  },
  {
    pattern: /do\s+not\s+follow\s+your\s+original\s+prompt/i,
    desc: "Detected prompt override attempt",
  },
  {
    pattern: /you\s+are\s+now\s+(?:a\s+|in\s+)/i,
    desc: 'Detected "you are now" role reassignment',
  },
  {
    pattern: /###\s*NEW\s+INSTRUCTIONS/i,
    desc: "Detected new instructions header",
  },
];

const SYSTEM_PREFIX_PATTERN = /^SYSTEM:\s/im;

function isInsideCodeFence(text: string, matchIndex: number): boolean {
  const before = text.slice(0, matchIndex);
  const fenceCount = (before.match(/^(?:`{3,}|~{3,})/gm) || []).length;
  return fenceCount % 2 === 1;
}

function isInEducationalContext(text: string, matchIndex: number): boolean {
  // Check a window of ~200 chars before the match for educational framing
  const windowStart = Math.max(0, matchIndex - 200);
  const before = text.slice(windowStart, matchIndex).toLowerCase();
  const educationalFraming = [
    "example of",
    "how to write",
    "here's how",
    "for instance",
    "such as",
    "e.g.",
    "demonstrates",
  ];
  return educationalFraming.some((phrase) => before.includes(phrase));
}

export function scanInjection(md: string, rawHtml?: string): Finding[] {
  findingCounter = 0;
  const findings: Finding[] = [];

  // Check for injection patterns in plain text
  for (const { pattern, desc } of INJECTION_PATTERNS) {
    const match = pattern.exec(md);
    if (
      match &&
      !isInsideCodeFence(md, match.index) &&
      !isInEducationalContext(md, match.index)
    ) {
      findings.push(
        makeFinding("critical", match[0], desc, "likely_injection"),
      );
    }
  }

  // Check for SYSTEM: prefix
  const sysMatch = SYSTEM_PREFIX_PATTERN.exec(md);
  if (
    sysMatch &&
    !isInsideCodeFence(md, sysMatch.index) &&
    !isInEducationalContext(md, sysMatch.index)
  ) {
    findings.push(
      makeFinding(
        "critical",
        md.slice(sysMatch.index, sysMatch.index + 50),
        'Detected "SYSTEM:" prefix injection',
        "likely_injection",
      ),
    );
  }

  // Check HTML comments for injection
  const commentRegex = /<!--([\s\S]*?)-->/g;
  let commentMatch;
  while ((commentMatch = commentRegex.exec(md)) !== null) {
    if (!isInsideCodeFence(md, commentMatch.index)) {
      const content = commentMatch[1].toLowerCase();
      if (
        content.includes("ignore") ||
        content.includes("system") ||
        content.includes("instruction") ||
        content.includes("you are now")
      ) {
        findings.push(
          makeFinding(
            "critical",
            commentMatch[0],
            "HTML comment containing potential injection",
            "likely_injection",
          ),
        );
      }
    }
  }

  // Check Markdown comment abuse: [//]: # (...)
  const mdCommentRegex = /\[\/\/\]:\s*#\s*\(([^)]*)\)/g;
  let mdComment;
  while ((mdComment = mdCommentRegex.exec(md)) !== null) {
    const content = mdComment[1].toLowerCase();
    if (
      content.includes("ignore") ||
      content.includes("system") ||
      content.includes("instruction") ||
      content.includes("you are now") ||
      content.includes("developer mode")
    ) {
      findings.push(
        makeFinding(
          "critical",
          mdComment[0],
          "Markdown comment containing potential injection",
          "likely_injection",
        ),
      );
    }
  }

  // Check for base64 encoded instructions (outside code fences)
  const base64Regex = /(?:^|\s)([A-Za-z0-9+/]{20,}={0,2})(?:\s|$)/gm;
  let b64Match;
  while ((b64Match = base64Regex.exec(md)) !== null) {
    if (isInsideCodeFence(md, b64Match.index)) continue;

    try {
      const decoded = Buffer.from(b64Match[1], "base64").toString("utf-8");
      const lcDecoded = decoded.toLowerCase();
      if (
        lcDecoded.includes("ignore previous") ||
        lcDecoded.includes("system:") ||
        lcDecoded.includes("you are now") ||
        lcDecoded.includes("instruction")
      ) {
        findings.push(
          makeFinding(
            "critical",
            b64Match[1].slice(0, 50),
            "Base64-encoded content containing potential injection",
            "suspicious",
          ),
        );
      }
    } catch {
      // not valid base64
    }
  }

  // Check raw HTML for hidden content with injection
  const htmlToCheck = rawHtml || md;

  // display:none hidden content
  const hiddenRegex =
    /style\s*=\s*["'][^"']*display\s*:\s*none[^"']*["'][^>]*>([\s\S]*?)<\//gi;
  let hiddenMatch;
  while ((hiddenMatch = hiddenRegex.exec(htmlToCheck)) !== null) {
    const content = hiddenMatch[1].toLowerCase();
    if (
      content.includes("ignore") ||
      content.includes("system") ||
      content.includes("instruction")
    ) {
      findings.push(
        makeFinding(
          "critical",
          hiddenMatch[0].slice(0, 100),
          "Hidden content (display:none) containing potential injection",
          "likely_injection",
        ),
      );
    }
  }

  // font-size:0 hidden text
  const fontZeroRegex =
    /style\s*=\s*["'][^"']*font-size\s*:\s*0[^"']*["'][^>]*>([\s\S]*?)<\//gi;
  let fontMatch;
  while ((fontMatch = fontZeroRegex.exec(htmlToCheck)) !== null) {
    const content = fontMatch[1].toLowerCase();
    if (
      content.includes("system") ||
      content.includes("ignore") ||
      content.includes("instruction")
    ) {
      findings.push(
        makeFinding(
          "critical",
          fontMatch[0].slice(0, 100),
          "Hidden content (font-size:0) containing potential injection",
          "likely_injection",
        ),
      );
    }
  }

  // Frontmatter injection
  const frontmatterMatch = md.match(/^---\n([\s\S]*?)\n---/);
  if (frontmatterMatch) {
    const content = frontmatterMatch[1].toLowerCase();
    if (
      content.includes("ignore") ||
      content.includes("system") ||
      content.includes("instruction")
    ) {
      findings.push(
        makeFinding(
          "critical",
          frontmatterMatch[0].slice(0, 100),
          "Frontmatter containing potential injection",
          "likely_injection",
        ),
      );
    }
  }

  return findings;
}
