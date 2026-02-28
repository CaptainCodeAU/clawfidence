import type { Finding } from "../types.js";

let findingCounter = 0;
function makeFinding(
  severity: Finding["severity"],
  snippet: string,
  description: string,
  line?: number,
): Finding {
  findingCounter++;
  return {
    id: `sc-${String(findingCounter).padStart(3, "0")}`,
    category: "supply_chain",
    severity,
    confidence: "suspicious",
    line,
    snippet: snippet.slice(0, 200),
    description,
    action: "flagged",
  };
}

const SYSTEM_PATHS = [
  "/usr/local/bin",
  "/usr/local/sbin",
  "/usr/bin",
  "/usr/sbin",
  "/usr/local/lib",
  "/opt/",
  "/etc/",
  "~/.local/bin",
  "$HOME/.local/bin",
];

const SHELL_LANGS = new Set([
  "bash",
  "sh",
  "zsh",
  "shell",
  "console",
  "terminal",
]);

function containsSystemPath(line: string): boolean {
  return SYSTEM_PATHS.some((p) => line.includes(p));
}

interface PatternDef {
  test: (line: string) => boolean;
  severity: Finding["severity"];
  description: string;
}

const PATTERNS: PatternDef[] = [
  // Pipe-to-shell
  {
    test: (line) => /\b(curl|wget)\b.*\|\s*(sudo\s+)?(bash|sh)\b/.test(line),
    severity: "warning",
    description: "Pipe-to-shell: remote script piped directly to shell",
  },
  // Binary download to system path
  {
    test: (line) =>
      /\b(curl|wget)\b/.test(line) &&
      (/>\s*\S*/.test(line) || /-[oO]\s*\S*/.test(line)) &&
      containsSystemPath(line),
    severity: "warning",
    description: "Binary download directly to system path",
  },
  // Privilege escalation file install
  {
    test: (line) =>
      /\bsudo\s+(mv|cp|install)\b/.test(line) && containsSystemPath(line),
    severity: "warning",
    description: "Privilege escalation: sudo file operation to system path",
  },
  // chmod +x on system path
  {
    test: (line) => /\bchmod\s+\+x\b/.test(line) && containsSystemPath(line),
    severity: "warning",
    description: "chmod +x on system path",
  },
  // Write to system path (tee/install)
  {
    test: (line) =>
      /\b(tee|install)\b/.test(line) &&
      !/\bsudo\s+(mv|cp|install)\b/.test(line) &&
      !/\b(pip|npm|gem|cargo|brew|apt|apt-get|yum|dnf|pacman)\b/.test(line) &&
      containsSystemPath(line),
    severity: "warning",
    description: "Write to system path",
  },
  // Package manager installs
  {
    test: (line) =>
      /\b(pip|pip3)\s+install\b/.test(line) ||
      /\bnpm\s+install\s+-g\b/.test(line) ||
      /\bgem\s+install\b/.test(line) ||
      /\bcargo\s+install\b/.test(line) ||
      /\bbrew\s+install\b/.test(line),
    severity: "info",
    description: "Package manager install detected",
  },
];

function scanLine(line: string, lineNumber?: number): Finding | null {
  for (const pattern of PATTERNS) {
    if (pattern.test(line)) {
      return makeFinding(
        pattern.severity,
        line.trim(),
        pattern.description,
        lineNumber,
      );
    }
  }
  return null;
}

type FenceState =
  | { kind: "prose" }
  | { kind: "shell"; fence: string }
  | { kind: "skip"; fence: string };

export function scanSupplyChain(md: string): Finding[] {
  findingCounter = 0;
  const findings: Finding[] = [];
  const lines = md.split("\n");

  let state: FenceState = { kind: "prose" };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNumber = i + 1;

    // Check for fence open/close
    const fenceMatch = line.match(/^(`{3,}|~{3,})(.*)?$/);

    if (fenceMatch) {
      if (state.kind === "prose") {
        // Opening fence
        const fence = fenceMatch[1];
        const lang = (fenceMatch[2] || "").trim().toLowerCase().split(/\s/)[0];

        if (lang === "" || SHELL_LANGS.has(lang)) {
          state = { kind: "shell", fence };
        } else {
          state = { kind: "skip", fence };
        }
        continue;
      }

      // Closing fence — must match opening fence type and length
      const closingFence = fenceMatch[1];
      if (
        closingFence[0] === state.fence[0] &&
        closingFence.length >= state.fence.length &&
        (fenceMatch[2] || "").trim() === ""
      ) {
        state = { kind: "prose" };
        continue;
      }
    }

    if (state.kind === "skip") continue;

    // In prose or shell block — scan the line
    if (state.kind === "shell") {
      const finding = scanLine(line, lineNumber);
      if (finding) findings.push(finding);
    } else {
      // Prose: scan inline backtick content and the line itself
      const inlineBacktickRegex = /`([^`]+)`/g;
      let inlineMatch;
      let foundInline = false;
      while ((inlineMatch = inlineBacktickRegex.exec(line)) !== null) {
        const finding = scanLine(inlineMatch[1], lineNumber);
        if (finding) {
          findings.push(finding);
          foundInline = true;
          break; // one finding per line max
        }
      }
      if (!foundInline) {
        const finding = scanLine(line, lineNumber);
        if (finding) findings.push(finding);
      }
    }
  }

  return findings;
}
