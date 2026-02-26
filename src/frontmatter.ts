import type { Metadata } from "./types.js";

export function generateFrontmatter(metadata: Metadata): string {
  const entries: string[] = [];

  if (metadata.title)
    entries.push(`title: "${metadata.title.replace(/"/g, '\\"')}"`);
  if (metadata.author)
    entries.push(`author: "${metadata.author.replace(/"/g, '\\"')}"`);
  if (metadata.published) entries.push(`date: "${metadata.published}"`);
  if (metadata.description)
    entries.push(`description: "${metadata.description.replace(/"/g, '\\"')}"`);
  if (metadata.site)
    entries.push(`site: "${metadata.site.replace(/"/g, '\\"')}"`);
  if (metadata.domain) entries.push(`domain: "${metadata.domain}"`);
  if (metadata.image) entries.push(`image: "${metadata.image}"`);

  if (entries.length === 0) return "";

  return `---\n${entries.join("\n")}\n---\n\n`;
}
