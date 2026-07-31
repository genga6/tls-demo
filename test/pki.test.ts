import { beforeAll, describe, expect, it } from "vitest";
import { generateSigningKeyPair } from "../src/lib/crypto";
import {
  type CertificateAuthority,
  createIntermediateCa,
  createRootCa,
  issueCertificate,
  matchesHostname,
  verifyCertificateChain,
} from "../src/lib/pki";

describe("ホスト名照合", () => {
  it("完全一致を受け入れる", () => {
    expect(matchesHostname("bank.example.com", "bank.example.com")).toBe(true);
  });

  it("大文字小文字を区別しない", () => {
    expect(matchesHostname("Bank.Example.COM", "bank.example.com")).toBe(true);
  });

  it("別ドメインを拒否する", () => {
    expect(matchesHostname("evil.example.net", "bank.example.com")).toBe(false);
  });

  it("ワイルドカードは 1 ラベルだけに一致する", () => {
    expect(matchesHostname("*.example.com", "api.example.com")).toBe(true);
    expect(matchesHostname("*.example.com", "a.b.example.com")).toBe(false);
    expect(matchesHostname("*.example.com", "example.com")).toBe(false);
  });

  it("ワイルドカードは接尾辞の偽装に騙されない", () => {
    expect(matchesHostname("*.example.com", "evil.example.com.attacker.net")).toBe(false);
  });
});

describe("証明書チェーンの検証", () => {
  const now = new Date("2026-01-15T00:00:00Z");
  let root: CertificateAuthority;
  let intermediate: CertificateAuthority;
  let rogue: CertificateAuthority;

  beforeAll(async () => {
    root = await createRootCa("Test Root CA", now);
    intermediate = await createIntermediateCa(root, "Test Intermediate CA", now);
    rogue = await createRootCa("Rogue CA", now);
  });

  const allChecks = { chain: true, hostname: true, validity: true };

  async function leafFrom(ca: CertificateAuthority, sans: string[], options = {}) {
    const keys = await generateSigningKeyPair();
    const { certificate } = await issueCertificate(
      ca,
      { subject: sans[0], subjectAltNames: sans, publicKeyJwk: keys.publicKeyJwk, ...options },
      now,
    );
    return certificate;
  }

  it("信頼ストアまで辿れる正しいチェーンを受け入れる", async () => {
    const leaf = await leafFrom(intermediate, ["bank.example.com"]);
    const result = await verifyCertificateChain([leaf, intermediate.certificate], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      enable: allChecks,
    });
    expect(result.ok).toBe(true);
  });

  it("信頼ストアにない CA が発行した証明書を拒否する", async () => {
    const leaf = await leafFrom(rogue, ["bank.example.com"]);
    const result = await verifyCertificateChain([leaf, rogue.certificate], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      enable: allChecks,
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("信頼されていない発行者");
  });

  it("チェーン検証を切ると偽 CA の証明書が通ってしまう", async () => {
    const leaf = await leafFrom(rogue, ["bank.example.com"]);
    const result = await verifyCertificateChain([leaf, rogue.certificate], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      enable: { ...allChecks, chain: false },
    });
    expect(result.ok).toBe(true);
  });

  it("証明書の中身を書き換えると署名検証に失敗する", async () => {
    const leaf = await leafFrom(intermediate, ["bank.example.com"]);
    const tampered = {
      ...leaf,
      body: { ...leaf.body, subjectAltNames: ["evil.example.net", "bank.example.com"] },
    };
    const result = await verifyCertificateChain([tampered, intermediate.certificate], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      enable: allChecks,
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("署名が不正");
  });

  it("ホスト名が一致しなければ拒否する", async () => {
    const leaf = await leafFrom(intermediate, ["evil.example.net"]);
    const result = await verifyCertificateChain([leaf, intermediate.certificate], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      enable: allChecks,
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("ホスト名不一致");
  });

  it("期限切れを拒否する", async () => {
    const leaf = await leafFrom(intermediate, ["bank.example.com"], {
      notBefore: new Date("2024-01-01T00:00:00Z"),
      notAfter: new Date("2025-01-01T00:00:00Z"),
    });
    const result = await verifyCertificateChain([leaf, intermediate.certificate], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      enable: allChecks,
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("期限切れ");
  });

  it("失効済みを拒否する", async () => {
    const leaf = await leafFrom(intermediate, ["bank.example.com"]);
    const result = await verifyCertificateChain([leaf, intermediate.certificate], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      revokedSerials: new Set([leaf.body.serialNumber]),
      enable: allChecks,
    });
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("失効");
  });

  it("CA でない証明書を発行者にできない", async () => {
    const notCa = await leafFrom(intermediate, ["middle.example.com"]);
    const leaf = await leafFrom(intermediate, ["bank.example.com"]);
    // issuer 名だけ notCa に合わせた、繋がらないチェーン。
    const forged = { ...leaf, body: { ...leaf.body, issuer: "middle.example.com" } };
    const result = await verifyCertificateChain([forged, notCa], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      enable: allChecks,
    });
    expect(result.ok).toBe(false);
  });

  it("各チェックの結果が個別に記録される", async () => {
    const leaf = await leafFrom(intermediate, ["bank.example.com"]);
    const result = await verifyCertificateChain([leaf, intermediate.certificate], {
      trustedRoots: [root.certificate],
      hostname: "bank.example.com",
      now,
      enable: { chain: true, hostname: false, validity: true },
    });
    expect(result.checks.some((c) => c.status === "skipped")).toBe(true);
    expect(result.ok).toBe(true);
  });
});
