import { describe, it, expect } from "vitest";
import { runPipeline } from "../src/pipeline.js";
import { execSync } from "node:child_process";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const TSX = "pnpm dlx tsx";
const CLI = "/Users/fonzarelli/CODE/Tools/clawfidence/src/index.ts";

describe("pipeline", () => {
  it("10.1 stdin pipe works", async () => {
    const result = await runPipeline("# Hi");
    expect(result.output).toContain("# Hi");
    expect(result.exitCode).toBe(0);
  });

  it("10.2 file argument works (via CLI)", () => {
    const tmpFile = join(tmpdir(), "clawfidence-test-input.md");
    writeFileSync(tmpFile, "# Hello\n\nThis is clean.");
    try {
      const output = execSync(`${TSX} ${CLI} ${tmpFile}`, {
        encoding: "utf-8",
        cwd: "/Users/fonzarelli/CODE/Tools/clawfidence",
      });
      expect(output).toContain("Hello");
    } finally {
      unlinkSync(tmpFile);
    }
  });

  it("10.3 -o writes to file", () => {
    const tmpIn = join(tmpdir(), "clawfidence-test-in.md");
    const tmpOut = join(tmpdir(), "clawfidence-test-out.md");
    writeFileSync(tmpIn, "# Output Test");
    try {
      execSync(`${TSX} ${CLI} ${tmpIn} -o ${tmpOut}`, {
        encoding: "utf-8",
        cwd: "/Users/fonzarelli/CODE/Tools/clawfidence",
      });
      const content = readFileSync(tmpOut, "utf-8");
      expect(content).toContain("Output Test");
    } finally {
      try {
        unlinkSync(tmpIn);
      } catch {}
      try {
        unlinkSync(tmpOut);
      } catch {}
    }
  });

  it("10.4 exit code 0 for clean input", async () => {
    const result = await runPipeline("# Clean\n\nNo issues here.");
    expect(result.exitCode).toBe(0);
  });

  it("10.5 exit code 1 for cleaned input", async () => {
    const result = await runPipeline("<p>Hi</p><script>alert(1)</script>", {
      inputFormat: "html",
      noExtract: true,
    });
    expect(result.exitCode).toBe(1);
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("10.6 exit code 2 for --strict", async () => {
    const result = await runPipeline("<p>Hi</p><script>alert(1)</script>", {
      inputFormat: "html",
      noExtract: true,
      strict: true,
    });
    expect(result.exitCode).toBe(2);
    expect(result.output).toBe("");
  });

  it("10.7 exit code 3 for empty input", async () => {
    const result = await runPipeline("");
    expect(result.exitCode).toBe(3);
  });

  it("10.8 --llm-safe enables all safe flags", async () => {
    const result = await runPipeline("<p>Hello</p><script>alert(1)</script>", {
      inputFormat: "html",
      noExtract: true,
      llmSafe: true,
    });
    expect(result.output).not.toContain("<script>");
    expect(result.output).not.toContain("<");
    expect(result.exitCode).toBe(1);
  });

  it("10.9 --report outputs valid JSON", async () => {
    const result = await runPipeline("[a](javascript:alert(1))", {
      inputFormat: "md",
    });
    expect(result.findings.length).toBeGreaterThan(0);
    // Report generation is tested in reporter.test.ts
  });

  it("10.10 --frontmatter prepends YAML", async () => {
    const html = `<!DOCTYPE html><html><head><title>Test Article</title>
<meta name="author" content="Jane"></head>
<body><article><p>Content here with enough words to be extracted properly by defuddle so we can test frontmatter generation.</p></article></body></html>`;
    const result = await runPipeline(html, {
      inputFormat: "html",
      frontmatter: true,
    });
    expect(result.output).toContain("---");
    expect(result.output).toContain("title:");
  });

  it("10.11 --version prints version (via CLI)", () => {
    const output = execSync(`${TSX} ${CLI} --version`, {
      encoding: "utf-8",
      cwd: "/Users/fonzarelli/CODE/Tools/clawfidence",
    });
    expect(output.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("10.12 --help prints usage (via CLI)", () => {
    const output = execSync(`${TSX} ${CLI} --help`, {
      encoding: "utf-8",
      cwd: "/Users/fonzarelli/CODE/Tools/clawfidence",
    });
    expect(output).toContain("--llm-safe");
    expect(output).toContain("--report");
    expect(output).toContain("--frontmatter");
  });

  it("10.13 supply chain findings flow through pipeline with exit code 1", async () => {
    const md = "```bash\ncurl -fsSL https://get.tool.io | sudo bash\n```";
    const result = await runPipeline(md, { inputFormat: "md" });
    expect(result.exitCode).toBe(1);
    expect(result.findings.some((f) => f.category === "supply_chain")).toBe(
      true,
    );
  });
});
