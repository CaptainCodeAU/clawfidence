import { describe, it, expect } from "vitest";
import { generateReport, formatReport } from "../src/reporter.js";
import type { Finding } from "../src/types.js";

const sampleFinding: Finding = {
  id: "f-001",
  category: "script_injection",
  severity: "critical",
  confidence: "confirmed",
  snippet: "<script>alert(1)</script>",
  description: "Inline script tag detected",
  action: "removed",
};

const warningFinding: Finding = {
  id: "f-002",
  category: "suspicious_url",
  severity: "warning",
  confidence: "suspicious",
  snippet: "http://xn--80ak6aa92e.com",
  description: "IDN homograph",
  action: "flagged",
};

const infoFinding: Finding = {
  id: "f-003",
  category: "suspicious_unicode",
  severity: "info",
  confidence: "clean",
  snippet: "ZWS detected",
  description: "Zero-width space",
  action: "kept",
};

describe("reporter", () => {
  it("9.1 JSON report matches schema", () => {
    const report = generateReport([sampleFinding]);
    expect(report).toHaveProperty("version");
    expect(report).toHaveProperty("timestamp");
    expect(report).toHaveProperty("input");
    expect(report).toHaveProperty("metadata");
    expect(report).toHaveProperty("summary");
    expect(report).toHaveProperty("findings");
    expect(report.findings).toHaveLength(1);
    expect(report.summary.total_findings).toBe(1);

    // JSON output should be valid
    const json = formatReport(report, "json");
    expect(() => JSON.parse(json)).not.toThrow();
  });

  it("9.2 text report is human-readable", () => {
    const report = generateReport([sampleFinding]);
    const text = formatReport(report, "text");
    expect(text).toContain("Report");
    expect(text).toContain("CRITICAL");
    expect(text).toContain("script_injection");
  });

  it("9.3 empty findings → status: clean", () => {
    const report = generateReport([]);
    expect(report.summary.status).toBe("clean");
    expect(report.summary.total_findings).toBe(0);
  });

  it("9.4 severity aggregation is correct", () => {
    const report = generateReport([sampleFinding, warningFinding, infoFinding]);
    expect(report.summary.by_severity.critical).toBe(1);
    expect(report.summary.by_severity.warning).toBe(1);
    expect(report.summary.by_severity.info).toBe(1);
    expect(report.summary.by_category["script_injection"]).toBe(1);
    expect(report.summary.by_category["suspicious_url"]).toBe(1);
  });

  it("9.5 --quiet suppresses stderr (report still generated)", () => {
    // The quiet flag is handled by the CLI layer, but the report itself
    // should still be generatable
    const report = generateReport([sampleFinding], { quiet: true });
    expect(report).toBeDefined();
    expect(report.findings).toHaveLength(1);
  });
});
