import { describe, it, expect } from "vitest";
import { scanUrls } from "../../src/scanner/url.js";

describe("scanUrls", () => {
  it("6.1 allows https://", () => {
    const findings = scanUrls("[link](https://safe.com)");
    expect(findings.length).toBe(0);
  });

  it("6.2 allows mailto:", () => {
    const findings = scanUrls("[email](mailto:a@b.com)");
    expect(findings.length).toBe(0);
  });

  it("6.3 blocks file://", () => {
    const findings = scanUrls("[x](file:///etc/passwd)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.4 detects IDN homograph", () => {
    const findings = scanUrls("[x](http://xn--80ak6aa92e.com)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
    expect(findings.some((f) => f.confidence === "suspicious")).toBe(true);
  });

  it("6.5 detects IP-address URL", () => {
    const findings = scanUrls("[x](http://192.168.1.1/path)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.6 --allowed-link-prefixes blocks non-matching", () => {
    const findings = scanUrls("[x](https://other.com)", {
      allowedLinkPrefixes: ["https://trusted.com"],
    });
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.7 --allowed-link-prefixes allows matching", () => {
    const findings = scanUrls("[x](https://trusted.com/page)", {
      allowedLinkPrefixes: ["https://trusted.com"],
    });
    expect(findings.length).toBe(0);
  });

  it("6.8 --allowed-image-prefixes blocks non-matching", () => {
    const findings = scanUrls("![img](https://other.com/pic.png)", {
      allowedImagePrefixes: ["https://trusted.com"],
    });
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.9 detects percent-encoded javascript:", () => {
    const findings = scanUrls("[x](java%73cript:alert(1))");
    expect(findings.some((f) => f.category === "script_injection")).toBe(true);
  });

  it("6.10 detects IDN homograph in parent domain label", () => {
    const findings = scanUrls("[x](http://safe.xn--80ak6aa92e.com/path)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.11 detects IDN homograph in any subdomain label", () => {
    const findings = scanUrls("[x](http://a.b.xn--nxasmq6b.c.com/path)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.12 detects IPv6 address URL", () => {
    const findings = scanUrls("[x](http://[::1]/admin)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.13 detects hex IP address URL", () => {
    const findings = scanUrls("[x](http://0xC0A80101/)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.14 detects decimal IP address URL", () => {
    const findings = scanUrls("[x](http://3232235777/)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });

  it("6.14b detects octal IP address URL", () => {
    const findings = scanUrls("[x](http://0300.0250.0001.0001/)");
    expect(findings.some((f) => f.category === "suspicious_url")).toBe(true);
  });
});
