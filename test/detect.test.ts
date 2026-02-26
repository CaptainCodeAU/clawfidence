import { describe, it, expect } from "vitest";
import { detectFormat } from "../src/detect.js";

describe("detectFormat", () => {
  it("1.1 detects full HTML document", () => {
    const result = detectFormat("<html><body><p>Hello</p></body></html>");
    expect(result).toEqual({ format: "html" });
  });

  it("1.2 detects HTML fragment", () => {
    const result = detectFormat("<div><p>Hello</p></div>");
    expect(result).toEqual({ format: "html" });
  });

  it("1.3 detects Markdown", () => {
    const result = detectFormat("# Hello\n\nThis is **bold**.");
    expect(result).toEqual({ format: "md" });
  });

  it("1.4 detects Markdown with inline HTML", () => {
    const result = detectFormat("# Title\n<em>hi</em>");
    expect(result).toEqual({ format: "md" });
  });

  it("1.5 respects --input-format html override", () => {
    const result = detectFormat("# This is Markdown", "html");
    expect(result).toEqual({ format: "html" });
  });

  it("1.6 respects --input-format md override", () => {
    const result = detectFormat("<html><body>HTML</body></html>", "md");
    expect(result).toEqual({ format: "md" });
  });

  it("1.7 handles empty input", () => {
    const result = detectFormat("");
    expect(result).toEqual({ error: "Empty input", exitCode: 3 });
  });

  it("1.8 handles binary/non-text input", () => {
    // Generate string with lots of null/control bytes
    const binary = String.fromCharCode(0, 1, 2, 3, 4, 5, 0, 0, 0, 0);
    const result = detectFormat(binary);
    expect(result).toHaveProperty("exitCode", 3);
  });
});
