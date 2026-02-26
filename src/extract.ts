import type { Metadata, ExtractOptions } from "./types.js";

interface ExtractResult {
  content: string;
  metadata: Metadata;
}

export async function extractContent(
  html: string,
  options?: ExtractOptions,
): Promise<ExtractResult> {
  if (options?.noExtract) {
    return { content: html, metadata: {} };
  }

  try {
    const { Defuddle } = await import("defuddle/node");
    const result = await Defuddle(html, undefined, {
      debug: options?.debug,
      removeImages: options?.noImages,
    });

    let content = result.content;
    const metadata: Metadata = {
      title: result.title || undefined,
      author: result.author || undefined,
      published: result.published || undefined,
      description: result.description || undefined,
      site: result.site || undefined,
      domain: result.domain || undefined,
      image: result.image || undefined,
      favicon: result.favicon || undefined,
      wordCount: result.wordCount || undefined,
    };

    // Remove first H1/H2 if it duplicates the title
    if (metadata.title) {
      const titlePattern = new RegExp(
        `<h[12][^>]*>\\s*${escapeRegex(metadata.title)}\\s*</h[12]>`,
        "i",
      );
      content = content.replace(titlePattern, "");
    }

    // Demote H1s to H2s
    content = content.replace(/<h1(\s[^>]*)?>/gi, "<h2$1>");
    content = content.replace(/<\/h1>/gi, "</h2>");

    // Strip anchor links from headings
    content = content.replace(
      /(<h[1-6][^>]*>)\s*<a[^>]*>\s*([\s\S]*?)\s*<\/a>\s*(<\/h[1-6]>)/gi,
      "$1$2$3",
    );

    // Remove hidden elements
    content = content.replace(
      /<[^>]+(?:display\s*:\s*none|aria-hidden\s*=\s*"true"|hidden)[^>]*>[\s\S]*?<\/[^>]+>/gi,
      "",
    );

    // Adaptive retry: if too few words, retry with relaxed settings
    const wordCount = content.split(/\s+/).filter(Boolean).length;
    if (wordCount < 200) {
      try {
        const retryResult = await Defuddle(html, undefined, {
          debug: options?.debug,
          removeImages: options?.noImages,
        });

        const retryWordCount = retryResult.content
          .split(/\s+/)
          .filter(Boolean).length;
        if (retryWordCount > wordCount) {
          content = retryResult.content;
        }
      } catch {
        // Use original result
      }
    }

    return { content, metadata };
  } catch {
    // If defuddle fails, return raw HTML with empty metadata
    return { content: html, metadata: {} };
  }
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
