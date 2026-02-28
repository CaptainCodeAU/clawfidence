import { describe, it, expect } from "vitest";
import {
  normaliseUri,
  isDangerousScheme,
} from "../../src/utils/normalise-uri.js";

describe("normaliseUri", () => {
  it("decodes percent-encoded characters", () => {
    expect(normaliseUri("java%73cript:alert(1)")).toBe("javascript:alert(1)");
  });

  it("removes whitespace and control characters", () => {
    expect(normaliseUri("j a v a s c r i p t:x")).toBe("javascript:x");
  });

  it("lowercases the result", () => {
    expect(normaliseUri("JaVaScRiPt:X")).toBe("javascript:x");
  });

  it("handles double percent-encoding", () => {
    expect(normaliseUri("j%2561vascript:alert(1)")).toBe("javascript:alert(1)");
  });

  it("handles triple percent-encoding", () => {
    expect(normaliseUri("j%252561vascript:alert(1)")).toBe(
      "javascript:alert(1)",
    );
  });

  it("caps decoding iterations to prevent infinite loops", () => {
    // A string that never stabilises (should not hang)
    const result = normaliseUri("%".repeat(100));
    expect(typeof result).toBe("string");
  });
});

describe("isDangerousScheme", () => {
  it("returns false for https:", () => {
    expect(isDangerousScheme("https://example.com")).toBe(false);
  });

  it("returns true for javascript:", () => {
    expect(isDangerousScheme("javascript:alert(1)")).toBe(true);
  });

  it("returns false for relative URLs", () => {
    expect(isDangerousScheme("/path/to/file")).toBe(false);
    expect(isDangerousScheme("./relative")).toBe(false);
    expect(isDangerousScheme("../parent")).toBe(false);
    expect(isDangerousScheme("#anchor")).toBe(false);
  });

  it("returns true for non-allowlisted scheme", () => {
    expect(isDangerousScheme("gopher://example.com")).toBe(true);
  });
});
