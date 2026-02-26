import TurndownService from "turndown";
import { gfm } from "turndown-plugin-gfm";

export function htmlToMarkdown(
  html: string,
  options?: { noImages?: boolean },
): string {
  const turndown = new TurndownService({
    headingStyle: "atx",
    codeBlockStyle: "fenced",
    bulletListMarker: "-",
    emDelimiter: "*",
  });

  // Add GFM support (tables, strikethrough, task lists)
  turndown.use(gfm);

  // Custom rule for fenced code blocks with language
  turndown.addRule("fencedCodeBlock", {
    filter: (node) => {
      return (
        node.nodeName === "PRE" &&
        node.firstChild !== null &&
        node.firstChild.nodeName === "CODE"
      );
    },
    replacement: (_content, node) => {
      const code = (node as HTMLElement).querySelector("code");
      if (!code) return _content;

      const className = code.getAttribute("class") || "";
      const langMatch = className.match(/(?:language-|lang-)(\S+)/);
      const lang = langMatch ? langMatch[1] : "";
      const text = code.textContent || "";

      return `\n\n\`\`\`${lang}\n${text}\n\`\`\`\n\n`;
    },
  });

  // Handle --no-images
  if (options?.noImages) {
    turndown.addRule("removeImages", {
      filter: "img",
      replacement: () => "",
    });
  }

  let md = turndown.turndown(html);

  // Clean up excessive blank lines
  md = md.replace(/\n{3,}/g, "\n\n").trim();

  return md;
}
