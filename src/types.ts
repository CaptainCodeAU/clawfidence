export type Severity = "critical" | "warning" | "info";
export type Confidence =
  | "confirmed"
  | "likely_injection"
  | "suspicious"
  | "clean";
export type FindingCategory =
  | "script_injection"
  | "html_injection"
  | "prompt_injection"
  | "suspicious_url"
  | "suspicious_unicode";
export type ActionTaken = "removed" | "flagged" | "kept";

export interface Finding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  line?: number;
  column?: number;
  snippet: string;
  description: string;
  action: ActionTaken;
}

export interface DetectionResult {
  format: "html" | "md";
}

export interface DetectionError {
  error: string;
  exitCode: 3;
}

export interface Metadata {
  title?: string;
  author?: string;
  published?: string;
  description?: string;
  site?: string;
  domain?: string;
  image?: string;
  favicon?: string;
  wordCount?: number;
}

export interface ScanResult {
  clean: string;
  findings: Finding[];
}

export interface ExtractOptions {
  noExtract?: boolean;
  noImages?: boolean;
  debug?: boolean;
}

export interface PipelineOptions {
  inputFormat?: "html" | "md";
  noExtract?: boolean;
  noImages?: boolean;
  noLinks?: boolean;
  stripJs?: boolean;
  stripHtml?: boolean;
  strict?: boolean;
  llmSafe?: boolean;
  frontmatter?: boolean;
  report?: boolean | string;
  reportFormat?: "json" | "text";
  output?: string;
  quiet?: boolean;
  verbose?: boolean;
  debug?: boolean;
  allowedLinkPrefixes?: string[];
  allowedImagePrefixes?: string[];
}

export interface PipelineResult {
  output: string;
  findings: Finding[];
  metadata: Metadata;
  exitCode: 0 | 1 | 2 | 3;
}

export interface ReportOptions {
  format?: "json" | "text";
  quiet?: boolean;
}

export interface Report {
  version: string;
  timestamp: string;
  input: {
    format: "html" | "md";
    size_bytes: number;
    source: string;
  };
  metadata: Metadata;
  summary: {
    status: "clean" | "issues_found";
    total_findings: number;
    by_severity: Record<Severity, number>;
    by_category: Record<string, number>;
  };
  findings: Finding[];
}
