import { describe, it, expect } from "vitest";
import { scanSupplyChain } from "../../src/scanner/supply-chain.js";

describe("supply-chain scanner", () => {
  describe("detection — pipe-to-shell", () => {
    it("detects curl piped to bash", () => {
      const md = "```bash\ncurl -fsSL https://get.tool.io | bash\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
      expect(findings[0].severity).toBe("warning");
      expect(findings[0].action).toBe("flagged");
    });

    it("detects wget piped to sh", () => {
      const md = "```bash\nwget -qO- https://example.com/install.sh | sh\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });

    it("detects curl piped to sudo bash", () => {
      const md = "```bash\ncurl -fsSL https://get.tool.io | sudo bash\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
      expect(findings[0].severity).toBe("warning");
    });
  });

  describe("detection — binary download to system path", () => {
    it("detects curl redirect to /usr/local/bin/", () => {
      const md =
        "```bash\ncurl -L https://github.com/org/tool/releases/download/v1.0/tool > /usr/local/bin/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });

    it("detects wget -O to /usr/local/bin/", () => {
      const md =
        "```bash\nwget -O /usr/local/bin/tool https://example.com/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });
  });

  describe("detection — privilege escalation file install", () => {
    it("detects sudo mv to system path", () => {
      const md = "```bash\nsudo mv ./tool /usr/local/bin/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });

    it("detects sudo cp to system path", () => {
      const md = "```bash\nsudo cp ./tool /usr/local/bin/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });

    it("detects sudo install to system path", () => {
      const md = "```bash\nsudo install ./tool /usr/local/bin/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });
  });

  describe("detection — chmod +x on system path", () => {
    it("detects chmod +x on /usr/local/bin/", () => {
      const md = "```bash\nchmod +x /usr/local/bin/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });

    it("detects chmod +x on /usr/bin/", () => {
      const md = "```bash\nchmod +x /usr/bin/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });
  });

  describe("detection — multi-step install sequence", () => {
    it("detects full supply chain install in single code block", () => {
      const md = [
        "```bash",
        "curl -L https://github.com/org/tool/releases/download/v1.0/tool -o /tmp/tool",
        "sudo mv /tmp/tool /usr/local/bin/tool",
        "chmod +x /usr/local/bin/tool",
        "```",
      ].join("\n");
      const findings = scanSupplyChain(md);
      // sudo mv + chmod = 2 findings (curl to /tmp is not a system path)
      expect(findings.length).toBe(2);
      expect(findings.every((f) => f.category === "supply_chain")).toBe(true);
    });
  });

  describe("detection — untagged code blocks", () => {
    it("scans untagged code blocks", () => {
      const md = "```\ncurl -fsSL https://get.tool.io | bash\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });
  });

  describe("detection — bare prose commands", () => {
    it("detects pipe-to-shell in prose", () => {
      const md =
        "To install, run curl -fsSL https://get.tool.io | bash on your terminal.";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });
  });

  describe("detection — inline backtick commands", () => {
    it("detects pipe-to-shell inside inline backticks", () => {
      const md = "Run `curl -fsSL https://get.tool.io | bash` to install.";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });
  });

  describe("detection — package manager installs", () => {
    it("detects pip install at info severity", () => {
      const md = "```bash\npip install sometool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe("info");
    });

    it("detects npm install -g at info severity", () => {
      const md = "```bash\nnpm install -g sometool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe("info");
    });

    it("detects gem install at info severity", () => {
      const md = "```bash\ngem install sometool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe("info");
    });

    it("detects cargo install at info severity", () => {
      const md = "```bash\ncargo install sometool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe("info");
    });

    it("detects brew install at info severity", () => {
      const md = "```bash\nbrew install sometool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe("info");
    });
  });

  describe("detection — home local bin paths", () => {
    it("detects write to ~/.local/bin", () => {
      const md = "```bash\nsudo mv ./tool ~/.local/bin/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });

    it("detects write to $HOME/.local/bin", () => {
      const md = "```bash\nsudo cp ./tool $HOME/.local/bin/tool\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
      expect(findings[0].category).toBe("supply_chain");
    });
  });

  describe("false positives — should produce zero findings", () => {
    it("ignores shell commands inside python code blocks", () => {
      const md =
        '```python\nimport subprocess\nsubprocess.run("curl | bash", shell=True)\n```';
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(0);
    });

    it("ignores shell commands inside js code blocks", () => {
      const md =
        "```js\nconst cmd = 'curl -fsSL https://example.com | bash';\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(0);
    });

    it("ignores chmod +x on local path", () => {
      const md = "```bash\nchmod +x ./local-script.sh\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(0);
    });

    it("ignores curl to /tmp path", () => {
      const md = "```bash\ncurl -o /tmp/file.tar.gz https://example.com/f\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(0);
    });

    it("ignores sudo apt-get install", () => {
      const md = "```bash\nsudo apt-get install vim\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(0);
    });

    it("ignores mv without sudo to non-system path", () => {
      const md = "```bash\nmv ./build/app ./dist/app\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(0);
    });
  });

  describe("finding properties", () => {
    it("has correct confidence and action", () => {
      const md = "```bash\ncurl -fsSL https://get.tool.io | bash\n```";
      const findings = scanSupplyChain(md);
      expect(findings[0].confidence).toBe("suspicious");
      expect(findings[0].action).toBe("flagged");
    });

    it("produces one finding per line max", () => {
      // Line has both pipe-to-shell AND downloads — only first match should win
      const md = "```bash\ncurl -fsSL https://get.tool.io | sudo bash\n```";
      const findings = scanSupplyChain(md);
      expect(findings.length).toBe(1);
    });
  });
});
