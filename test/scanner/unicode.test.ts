import { describe, it, expect } from "vitest";
import { scanUnicode } from "../../src/scanner/unicode.js";

describe("scanUnicode", () => {
  it("7.1 detects zero-width spaces", () => {
    const { findings } = scanUnicode("Hello\u200Bworld");
    expect(findings.some((f) => f.category === "suspicious_unicode")).toBe(
      true,
    );
  });

  it("7.2 detects zero-width joiners", () => {
    const { findings } = scanUnicode("Hello\u200Dworld");
    expect(findings.some((f) => f.category === "suspicious_unicode")).toBe(
      true,
    );
  });

  it("7.3 detects RTL override", () => {
    const { findings } = scanUnicode("Hello\u202Eworld");
    expect(findings.some((f) => f.category === "suspicious_unicode")).toBe(
      true,
    );
  });

  it("7.4 detects tag characters", () => {
    // U+E0001 is a tag character
    const { findings } = scanUnicode("Hello\u{E0001}world");
    expect(findings.some((f) => f.category === "suspicious_unicode")).toBe(
      true,
    );
  });

  it("7.5 allows legitimate ZWNJ in Persian/Arabic text", () => {
    // Persian word "می‌خواهم" uses ZWNJ legitimately
    const { findings } = scanUnicode("می\u200Cخواهم");
    // Should NOT flag ZWNJ between Arabic/Persian characters
    const zwnjFindings = findings.filter((f) =>
      f.description.includes("Zero-width non-joiner"),
    );
    expect(zwnjFindings.length).toBe(0);
  });

  it("7.6 --llm-safe strips all zero-width characters", () => {
    const { cleaned } = scanUnicode("He\u200Bll\u200Do\u200C world", {
      llmSafe: true,
    });
    expect(cleaned).toBe("Hello world");
  });

  it("L3: detects basic variation selectors (U+FE00-U+FE0F)", () => {
    const { findings } = scanUnicode("Hello\uFE0Fworld");
    expect(
      findings.some((f) => f.description.includes("presentation selector")),
    ).toBe(true);
  });

  it("L3: strips variation selectors in llmSafe mode", () => {
    const { cleaned } = scanUnicode("Hello\uFE0Fworld", { llmSafe: true });
    expect(cleaned).toBe("Helloworld");
  });

  it("L3: detects supplementary variation selectors (U+E0100-U+E01EF)", () => {
    const { findings } = scanUnicode("Hello\u{E0100}world");
    expect(
      findings.some((f) =>
        f.description.includes("Variation selector supplement"),
      ),
    ).toBe(true);
  });

  it("L3: strips supplementary variation selectors in llmSafe mode", () => {
    const { cleaned } = scanUnicode("Hello\u{E0100}world", { llmSafe: true });
    expect(cleaned).toBe("Helloworld");
  });

  it("L2: detects mixed Latin-Cyrillic word (Cyrillic а in Latin word)", () => {
    // "pаypal" — the а is Cyrillic U+0430, rest is Latin
    const { findings } = scanUnicode("Visit p\u0430ypal today");
    expect(
      findings.some((f) => f.description.includes("Mixed Latin-Cyrillic")),
    ).toBe(true);
  });

  it("L2: ignores pure Latin text", () => {
    const { findings } = scanUnicode("Hello world paypal");
    expect(
      findings.some((f) => f.description.includes("Mixed Latin-Cyrillic")),
    ).toBe(false);
  });

  it("L2: ignores pure Cyrillic text", () => {
    // "Привет мир" — all Cyrillic
    const { findings } = scanUnicode(
      "\u041F\u0440\u0438\u0432\u0435\u0442 \u043C\u0438\u0440",
    );
    expect(
      findings.some((f) => f.description.includes("Mixed Latin-Cyrillic")),
    ).toBe(false);
  });

  it("L2: detects multiple mixed-script words", () => {
    // Two words each mixing Latin + Cyrillic
    const { findings } = scanUnicode("p\u0430ypal and \u0430pple");
    const mixedFindings = findings.filter((f) =>
      f.description.includes("Mixed Latin-Cyrillic"),
    );
    expect(mixedFindings.length).toBe(2);
  });

  it("L2: skips mixed-script inside fenced code blocks", () => {
    const input = "```\np\u0430ypal\n```";
    const { findings } = scanUnicode(input);
    expect(
      findings.some((f) => f.description.includes("Mixed Latin-Cyrillic")),
    ).toBe(false);
  });

  it("L2: skips mixed-script inside tilde code fences", () => {
    const input = "~~~\np\u0430ypal\n~~~";
    const { findings } = scanUnicode(input);
    expect(
      findings.some((f) => f.description.includes("Mixed Latin-Cyrillic")),
    ).toBe(false);
  });

  it("L2: confidence is suspicious, not confirmed", () => {
    const { findings } = scanUnicode("p\u0430ypal");
    const mixed = findings.find((f) =>
      f.description.includes("Mixed Latin-Cyrillic"),
    );
    expect(mixed?.confidence).toBe("suspicious");
  });
});
