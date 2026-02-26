import type { Finding } from "../types.js";

let findingCounter = 0;
function makeFinding(
  severity: Finding["severity"],
  snippet: string,
  description: string,
): Finding {
  findingCounter++;
  return {
    id: `uni-${String(findingCounter).padStart(3, "0")}`,
    category: "suspicious_unicode",
    severity,
    confidence: "confirmed",
    snippet: snippet.slice(0, 200),
    description,
    action: "flagged",
  };
}

// Zero-width and invisible characters
const ZERO_WIDTH_CHARS: Record<string, string> = {
  "\u200B": "Zero-width space (U+200B)",
  "\u200C": "Zero-width non-joiner (U+200C)",
  "\u200D": "Zero-width joiner (U+200D)",
  "\uFEFF": "Zero-width no-break space (U+FEFF)",
  "\u2060": "Word joiner (U+2060)",
  "\u2061": "Function application (U+2061)",
  "\u2062": "Invisible times (U+2062)",
  "\u2063": "Invisible separator (U+2063)",
  "\u2064": "Invisible plus (U+2064)",
  "\u180E": "Mongolian vowel separator (U+180E)",
};

// BiDi override characters
const BIDI_CHARS: Record<string, string> = {
  "\u202A": "Left-to-right embedding (U+202A)",
  "\u202B": "Right-to-left embedding (U+202B)",
  "\u202C": "Pop directional formatting (U+202C)",
  "\u202D": "Left-to-right override (U+202D)",
  "\u202E": "Right-to-left override (U+202E)",
  "\u2066": "Left-to-right isolate (U+2066)",
  "\u2067": "Right-to-left isolate (U+2067)",
  "\u2068": "First strong isolate (U+2068)",
  "\u2069": "Pop directional isolate (U+2069)",
};

// Arabic/Persian script range for checking legitimate ZWNJ usage
const ARABIC_PERSIAN_REGEX =
  /[\u0600-\u06FF\u0750-\u077F\uFB50-\uFDFF\uFE70-\uFEFF]/;

function isLegitimateZwnj(text: string, index: number): boolean {
  if (text[index] !== "\u200C") return false;

  // Check if surrounded by Arabic/Persian script
  const before = index > 0 ? text[index - 1] : "";
  const after = index < text.length - 1 ? text[index + 1] : "";

  return ARABIC_PERSIAN_REGEX.test(before) || ARABIC_PERSIAN_REGEX.test(after);
}

function isTagCharacter(codePoint: number): boolean {
  return codePoint >= 0xe0001 && codePoint <= 0xe007f;
}

export function scanUnicode(
  text: string,
  options?: { llmSafe?: boolean },
): { findings: Finding[]; cleaned?: string } {
  findingCounter = 0;
  const findings: Finding[] = [];
  let cleaned: string | undefined;

  // Check for tag characters (U+E0001–U+E007F)
  for (let i = 0; i < text.length; i++) {
    const codePoint = text.codePointAt(i);
    if (codePoint && isTagCharacter(codePoint)) {
      findings.push(
        makeFinding(
          "warning",
          text.slice(Math.max(0, i - 10), i + 10),
          `Tag character detected (U+${codePoint.toString(16).toUpperCase()})`,
        ),
      );
      // Skip surrogate pair
      if (codePoint > 0xffff) i++;
    }
  }

  // Check for zero-width characters
  for (const [char, desc] of Object.entries(ZERO_WIDTH_CHARS)) {
    let idx = text.indexOf(char);
    while (idx !== -1) {
      // Skip legitimate ZWNJ in Arabic/Persian context
      if (char === "\u200C" && isLegitimateZwnj(text, idx)) {
        idx = text.indexOf(char, idx + 1);
        continue;
      }

      findings.push(
        makeFinding(
          "warning",
          text.slice(Math.max(0, idx - 10), idx + 10),
          desc,
        ),
      );
      idx = text.indexOf(char, idx + 1);
    }
  }

  // Check for BiDi characters
  for (const [char, desc] of Object.entries(BIDI_CHARS)) {
    let idx = text.indexOf(char);
    while (idx !== -1) {
      findings.push(
        makeFinding(
          "warning",
          text.slice(Math.max(0, idx - 10), idx + 10),
          desc,
        ),
      );
      idx = text.indexOf(char, idx + 1);
    }
  }

  // --llm-safe: strip all zero-width and BiDi characters
  if (options?.llmSafe) {
    const allChars = [
      ...Object.keys(ZERO_WIDTH_CHARS),
      ...Object.keys(BIDI_CHARS),
    ];
    cleaned = text;
    for (const char of allChars) {
      cleaned = cleaned.split(char).join("");
    }
    // Also strip tag characters
    cleaned = cleaned.replace(/[\u{E0001}-\u{E007F}]/gu, "");
  }

  return { findings, cleaned };
}
