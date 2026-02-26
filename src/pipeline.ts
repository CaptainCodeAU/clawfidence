import type {
  Finding,
  Metadata,
  PipelineOptions,
  PipelineResult,
} from "./types.js";
import { detectFormat } from "./detect.js";
import { extractContent } from "./extract.js";
import { sanitiseHtml } from "./convert/sanitise.js";
import { htmlToMarkdown } from "./convert/html-to-md.js";
import { sanitiseMarkdown } from "./convert/md-to-md.js";
import { scanMarkdownXss } from "./scanner/markdown-xss.js";
import { scanUrls } from "./scanner/url.js";
import { scanUnicode } from "./scanner/unicode.js";
import { scanInjection } from "./scanner/injection.js";
import { generateFrontmatter } from "./frontmatter.js";

export async function runPipeline(
  input: string,
  options: PipelineOptions = {},
): Promise<PipelineResult> {
  const allFindings: Finding[] = [];
  let metadata: Metadata = {};

  // Expand --llm-safe shorthand
  if (options.llmSafe) {
    options.stripJs = true;
    options.stripHtml = true;
    options.frontmatter = true;
  }

  // Step 1: Detect input format
  const detection = detectFormat(input, options.inputFormat);
  if ("error" in detection) {
    return {
      output: "",
      findings: [],
      metadata: {},
      exitCode: 3,
    };
  }

  const format = detection.format;
  let content = input;
  let rawHtml: string | undefined;

  // Step 2: Process based on format
  if (format === "html") {
    rawHtml = input;

    // Extract content (defuddle)
    const extracted = await extractContent(input, {
      noExtract: options.noExtract,
      noImages: options.noImages,
      debug: options.debug,
    });
    content = extracted.content;
    metadata = extracted.metadata;

    // Sanitise HTML
    const { clean, findings: sanitiseFindings } = sanitiseHtml(content);
    content = clean;
    allFindings.push(...sanitiseFindings);

    // Convert HTML to Markdown
    content = htmlToMarkdown(content, { noImages: options.noImages });
  }

  // Step 3: Sanitise and scan Markdown (both paths converge here)

  // Sanitise Markdown: strip dangerous HTML, neutralise dangerous URIs
  const { clean: sanitisedMd, findings: mdSanitiseFindings } =
    sanitiseMarkdown(content);
  content = sanitisedMd;
  allFindings.push(...mdSanitiseFindings);

  // Markdown XSS scan (on already-sanitised content, catches anything we missed)
  const xssFindings = scanMarkdownXss(content);
  allFindings.push(...xssFindings);

  // URL scan
  const urlFindings = scanUrls(content, {
    allowedLinkPrefixes: options.allowedLinkPrefixes,
    allowedImagePrefixes: options.allowedImagePrefixes,
  });
  allFindings.push(...urlFindings);

  // Unicode scan
  const { findings: unicodeFindings, cleaned: unicodeCleaned } = scanUnicode(
    content,
    { llmSafe: options.llmSafe },
  );
  allFindings.push(...unicodeFindings);
  if (unicodeCleaned) {
    content = unicodeCleaned;
  }

  // Injection scan
  const injectionFindings = scanInjection(content, rawHtml);
  allFindings.push(...injectionFindings);

  // Step 4: Post-processing

  // Strip remaining HTML if requested
  if (options.stripHtml) {
    content = content.replace(/<[^>]+>/g, "");
  }

  // Prepend frontmatter if requested
  if (options.frontmatter && Object.values(metadata).some(Boolean)) {
    content = generateFrontmatter(metadata) + content;
  }

  // Determine exit code
  let exitCode: 0 | 1 | 2 | 3;
  if (options.strict && allFindings.some((f) => f.severity === "critical")) {
    exitCode = 2;
    content = "";
  } else if (allFindings.length > 0) {
    exitCode = 1;
  } else {
    exitCode = 0;
  }

  return { output: content, findings: allFindings, metadata, exitCode };
}
