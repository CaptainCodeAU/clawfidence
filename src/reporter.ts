import type {
  Finding,
  Metadata,
  Report,
  ReportOptions,
  Severity,
} from "./types.js";

export function generateReport(
  findings: Finding[],
  options?: ReportOptions & {
    inputFormat?: "html" | "md";
    inputSize?: number;
    inputSource?: string;
    metadata?: Metadata;
  },
): Report {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    warning: 0,
    info: 0,
  };
  const byCategory: Record<string, number> = {};

  for (const f of findings) {
    bySeverity[f.severity]++;
    byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  }

  return {
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    input: {
      format: options?.inputFormat || "md",
      size_bytes: options?.inputSize || 0,
      source: options?.inputSource || "stdin",
    },
    metadata: options?.metadata || {},
    summary: {
      status: findings.length === 0 ? "clean" : "issues_found",
      total_findings: findings.length,
      by_severity: bySeverity,
      by_category: byCategory,
    },
    findings,
  };
}

export function formatReport(
  report: Report,
  format: "json" | "text" = "json",
): string {
  if (format === "json") {
    return JSON.stringify(report, null, 2);
  }

  // Text format
  const lines: string[] = [];
  lines.push(`clawfidence Report v${report.version}`);
  lines.push(`Status: ${report.summary.status}`);
  lines.push(`Total findings: ${report.summary.total_findings}`);
  lines.push("");

  if (report.summary.total_findings > 0) {
    lines.push("Severity breakdown:");
    for (const [sev, count] of Object.entries(report.summary.by_severity)) {
      if (count > 0) lines.push(`  ${sev}: ${count}`);
    }
    lines.push("");

    lines.push("Findings:");
    for (const f of report.findings) {
      lines.push(
        `  [${f.severity.toUpperCase()}] ${f.category}: ${f.description}`,
      );
      lines.push(`    Snippet: ${f.snippet.slice(0, 80)}`);
      lines.push(`    Action: ${f.action}`);
    }
  }

  return lines.join("\n");
}
