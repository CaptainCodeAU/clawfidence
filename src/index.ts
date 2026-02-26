#!/usr/bin/env node

import { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import { runPipeline } from "./pipeline.js";
import { generateReport, formatReport } from "./reporter.js";
import type { PipelineOptions } from "./types.js";

const program = new Command();

program
  .name("clawfidence")
  .description(
    "First responder for your Markdown pipeline. Defangs prompt injection, strips XSS, and sanitises HTML.",
  )
  .version("1.0.0")
  .argument("[file]", "Input file path")
  .option("--input-format <format>", "Override input format (html|md)")
  .option("--no-extract", "Skip content extraction (defuddle)")
  .option("--no-images", "Remove all images")
  .option("--no-links", "Convert links to plain text")
  .option("--strip-js", "Strip all JavaScript")
  .option("--strip-html", "Strip all HTML from Markdown output")
  .option("--strict", "Exit code 2 if high-severity issues found")
  .option("--llm-safe", "Aggressive sanitisation for LLM consumption")
  .option("--frontmatter", "Prepend YAML frontmatter with metadata")
  .option("--report [path]", "Output JSON report to stderr or file")
  .option("--report-format <format>", "Report format (json|text)", "json")
  .option("-o, --output <path>", "Write output to file")
  .option("--quiet", "Suppress stderr output except errors")
  .option("--verbose", "Detailed stderr logging")
  .option("--debug", "Enable debug mode")
  .option(
    "--allowed-link-prefixes <list>",
    "Comma-separated allowed URL prefixes for links",
  )
  .option(
    "--allowed-image-prefixes <list>",
    "Comma-separated allowed URL prefixes for images",
  )
  .action(async (file: string | undefined, opts: Record<string, unknown>) => {
    try {
      let input: string;

      if (file) {
        try {
          input = readFileSync(file, "utf-8");
        } catch {
          if (!opts.quiet) {
            process.stderr.write(`Error: Cannot read file '${file}'\n`);
          }
          process.exit(3);
        }
      } else {
        // Read from stdin
        input = await readStdin();
      }

      const pipelineOpts: PipelineOptions = {
        inputFormat: opts.inputFormat as "html" | "md" | undefined,
        noExtract: opts.extract === false,
        noImages: opts.images === false,
        noLinks: opts.links === false,
        stripJs: opts.stripJs as boolean | undefined,
        stripHtml: opts.stripHtml as boolean | undefined,
        strict: opts.strict as boolean | undefined,
        llmSafe: opts.llmSafe as boolean | undefined,
        frontmatter: opts.frontmatter as boolean | undefined,
        quiet: opts.quiet as boolean | undefined,
        verbose: opts.verbose as boolean | undefined,
        debug: opts.debug as boolean | undefined,
        allowedLinkPrefixes: opts.allowedLinkPrefixes
          ? (opts.allowedLinkPrefixes as string).split(",")
          : undefined,
        allowedImagePrefixes: opts.allowedImagePrefixes
          ? (opts.allowedImagePrefixes as string).split(",")
          : undefined,
      };

      const result = await runPipeline(input, pipelineOpts);

      // Output report if requested
      if (opts.report !== undefined) {
        const report = generateReport(result.findings, {
          inputFormat: result.metadata ? "html" : "md",
          inputSize: Buffer.byteLength(input),
          inputSource: file || "stdin",
          metadata: result.metadata,
          format: opts.reportFormat as "json" | "text",
        });

        const reportStr = formatReport(
          report,
          opts.reportFormat as "json" | "text",
        );

        if (typeof opts.report === "string" && opts.report !== "") {
          writeFileSync(opts.report, reportStr);
        } else if (!opts.quiet) {
          process.stderr.write(reportStr + "\n");
        }
      }

      // Write output
      if (result.exitCode !== 2) {
        if (opts.output) {
          writeFileSync(opts.output as string, result.output);
        } else {
          process.stdout.write(result.output);
        }
      }

      // Report findings on stderr (if not quiet and not suppressed)
      if (
        !opts.quiet &&
        result.findings.length > 0 &&
        opts.report === undefined
      ) {
        process.stderr.write(
          `clawfidence: ${result.findings.length} issue(s) found and cleaned\n`,
        );
      }

      process.exit(result.exitCode);
    } catch (err) {
      if (!opts.quiet) {
        process.stderr.write(
          `Error: ${err instanceof Error ? err.message : String(err)}\n`,
        );
      }
      process.exit(3);
    }
  });

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk) => chunks.push(chunk));
    process.stdin.on("end", () =>
      resolve(Buffer.concat(chunks).toString("utf-8")),
    );
    process.stdin.on("error", reject);

    // If stdin is a TTY (no pipe), resolve with empty string after timeout
    if (process.stdin.isTTY) {
      resolve("");
    }
  });
}

program.parse();
