const ALLOWED_SCHEMES = ["https:", "http:", "mailto:", "tel:", "#"];

export function normaliseUri(uri: string): string {
  let decoded = uri;
  // Multi-pass decoding to defeat double/triple encoding
  for (let i = 0; i < 3; i++) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch {
      break;
    }
  }
  return decoded.replace(/[\s\x00-\x1f]/g, "").toLowerCase();
}

export function isDangerousScheme(href: string): boolean {
  const normalised = normaliseUri(href);
  for (const scheme of ALLOWED_SCHEMES) {
    if (normalised.startsWith(scheme)) return false;
  }
  if (
    normalised.startsWith("/") ||
    normalised.startsWith("./") ||
    normalised.startsWith("../") ||
    !normalised.includes(":")
  ) {
    return false;
  }
  return true;
}
