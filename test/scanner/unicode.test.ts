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
});
