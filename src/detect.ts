import type { DetectionResult, DetectionError } from "./types.js";

export function detectFormat(
  input: string,
  override?: "html" | "md",
): DetectionResult | DetectionError {
  if (override) {
    return { format: override };
  }

  if (!input || input.trim().length === 0) {
    return { error: "Empty input", exitCode: 3 };
  }

  // Check for binary/non-text content: look for null bytes or high ratio of control chars
  const controlChars = input.split("").filter((c) => {
    const code = c.charCodeAt(0);
    return (
      code === 0 || (code < 32 && code !== 9 && code !== 10 && code !== 13)
    );
  }).length;

  if (controlChars / input.length > 0.1) {
    return { error: "Binary or non-text input detected", exitCode: 3 };
  }

  const trimmed = input.trim();

  // Check for full HTML document
  if (/<html[\s>]/i.test(trimmed) || /<!doctype\s+html/i.test(trimmed)) {
    return { format: "html" };
  }

  // Check for HTML fragment: starts with a block-level HTML tag
  if (
    /^<(?:div|p|section|article|main|table|ul|ol|dl|nav|header|footer|aside|form|fieldset|details|figure|figcaption|blockquote|pre|hr|br|span|a|img|iframe|object|embed|style|link|meta|head|body)\b/i.test(
      trimmed,
    )
  ) {
    return { format: "html" };
  }

  // Default: treat as Markdown
  return { format: "md" };
}
