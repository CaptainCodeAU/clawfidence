import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { runPipeline } from "../src/pipeline.js";

const FIXTURES = join(
  "/Users/fonzarelli/CODE/Tools/clawfidence",
  "test/fixtures",
);
const VENDOR = join(FIXTURES, "vendor");
const CVE = join(FIXTURES, "cve");

const EXECUTABLE_PATTERNS =
  /javascript:|onerror\s*=|onload\s*=|onfocus\s*=|<script|data:text\/html|vbscript:/i;

function loadPayloads(filename: string): string[] {
  const content = readFileSync(join(VENDOR, filename), "utf-8");
  return content
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#") && !l.startsWith("//"));
}

async function assertPayloadNeutralised(payload: string) {
  // Test as Markdown input
  const mdResult = await runPipeline(payload, {
    inputFormat: "md",
    noExtract: true,
  });
  expect(EXECUTABLE_PATTERNS.test(mdResult.output)).toBe(false);

  // Test as HTML input
  const htmlResult = await runPipeline(payload, {
    inputFormat: "html",
    noExtract: true,
  });
  expect(EXECUTABLE_PATTERNS.test(htmlResult.output)).toBe(false);
}

describe("XSS Payload Regression", () => {
  describe("11.1 cujanovic payloads neutralised", () => {
    const payloads = loadPayloads("markdown-xss-payloads.txt");
    it.each(payloads)("neutralises: %s", async (payload) => {
      await assertPayloadNeutralised(payload);
    });
  });

  describe("11.2 HackTricks payloads neutralised", () => {
    const payloads = loadPayloads("hacktricks-markdown-xss.txt");
    it.each(payloads)("neutralises: %s", async (payload) => {
      await assertPayloadNeutralised(payload);
    });
  });

  describe("11.3 Kevil-hui payloads neutralised", () => {
    const payloads = loadPayloads("kevil-hui-payloads.txt");
    it.each(payloads)("neutralises: %s", async (payload) => {
      await assertPayloadNeutralised(payload);
    });
  });

  describe("11.4 666reda payloads neutralised", () => {
    const payloads = loadPayloads("666reda-payloads.txt");
    it.each(payloads)("neutralises: %s", async (payload) => {
      await assertPayloadNeutralised(payload);
    });
  });

  describe("11.5 jaydeepnasit payloads neutralised", () => {
    const payloads = loadPayloads("jaydeepnasit-payloads.txt");
    it.each(payloads)("neutralises: %s", async (payload) => {
      await assertPayloadNeutralised(payload);
    });
  });

  describe("11.6 CVE-2024-41662 reproduction", () => {
    it("neutralises iframe to local file path", async () => {
      const payload = readFileSync(join(CVE, "CVE-2024-41662.md"), "utf-8");
      const result = await runPipeline(payload, {
        inputFormat: "md",
        noExtract: true,
      });
      expect(result.output).not.toContain("<iframe");
      expect(result.findings.length).toBeGreaterThan(0);
    });
  });
});
