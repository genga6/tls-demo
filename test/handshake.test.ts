import { beforeAll, describe, expect, it } from "vitest";
import { type DemoWorld, LEGIT_HOSTNAME, buildWorld } from "../src/lib/server";
import { runSession } from "../src/lib/session";
import { ALL_DEFENSES_ON, type Defenses } from "../src/lib/types";

const NOW = new Date("2026-01-15T00:00:00Z");

let world: DemoWorld;
beforeAll(async () => {
  world = await buildWorld(NOW);
});

function base(overrides: Partial<Defenses> = {}) {
  return {
    defenses: { ...ALL_DEFENSES_ON, ...overrides },
    hostname: LEGIT_HOSTNAME,
    server: world.legitServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: NOW,
  };
}

describe("正常なハンドシェイク", () => {
  it("すべての防御が有効なら成立する", async () => {
    const session = await runSession(base());
    expect(session.established).toBe(true);
    expect(session.abortReason).toBeUndefined();
  });

  it("TLS 1.3 の AEAD スイートが選ばれる", async () => {
    const session = await runSession(base());
    expect(session.cipherSuite).toBe("TLS_AES_128_GCM_SHA256");
    expect(session.downgraded).toBe(false);
  });

  it("ECDHE の使い捨て鍵が使われる", async () => {
    const session = await runSession(base());
    expect(session.keyExchange).toContain("ECDHE");
    expect(session.trace?.serverUsedEphemeralKey).toBe(true);
  });

  it("ツリーの 5 層すべてを通る", async () => {
    const session = await runSession(base());
    const phases = new Set(session.steps.map((s) => s.phase));
    expect(phases).toEqual(
      new Set(["handshake", "certificate", "key-exchange", "encryption", "https"]),
    );
  });

  it("HTTP のやり取りが往復する", async () => {
    const session = await runSession(base());
    expect(session.httpRequest).toContain("POST /api/transfer HTTP/1.1");
    expect(session.httpResponse).toContain("HTTP/1.1 200 OK");
  });

  it("接続ごとに鍵が変わる", async () => {
    const a = await runSession(base());
    const b = await runSession(base());
    expect(a.secrets["ECDHE 共有秘密"]).not.toBe(b.secrets["ECDHE 共有秘密"]);
    expect(a.secrets["Master Secret"]).not.toBe(b.secrets["Master Secret"]);
  });

  it("失敗したステップがひとつもない", async () => {
    const session = await runSession(base());
    expect(session.steps.filter((s) => s.status === "failed")).toHaveLength(0);
  });
});

describe("レコード層の暗号化", () => {
  it("有効なら盗聴者にアプリケーションデータが読めない", async () => {
    const session = await runSession(base());
    const appData = session.wiretap.filter((w) => w.label.startsWith("HTTP"));
    expect(appData.length).toBeGreaterThan(0);
    expect(appData.every((w) => !w.readable)).toBe(true);
  });

  it("暗号化していても SNI は平文で漏れる", async () => {
    const session = await runSession(base());
    const hello = session.wiretap.find((w) => w.label === "ClientHello");
    expect(hello?.readable).toBe(true);
    expect(hello?.visible).toContain(LEGIT_HOSTNAME);
  });

  it("無効にすると Cookie と Authorization がそのまま見える", async () => {
    const session = await runSession(base({ recordEncryption: false }));
    expect(session.established).toBe(true);
    const request = session.wiretap.find((w) => w.label === "HTTP リクエスト");
    expect(request?.readable).toBe(true);
    expect(request?.visible).toContain("Cookie:");
    expect(request?.visible).toContain("Authorization: Bearer");
  });
});

describe("防御を省略したときのステップ表示", () => {
  it("CertificateVerify を切ると該当ステップが skipped になる", async () => {
    const session = await runSession(base({ certificateVerify: false }));
    const step = session.steps.find((s) => s.title.includes("CertificateVerify"));
    expect(step?.status).toBe("skipped");
  });

  it("Finished を切ると該当ステップが skipped になる", async () => {
    const session = await runSession(base({ finishedVerify: false }));
    const step = session.steps.find((s) => s.title.includes("Finished"));
    expect(step?.status).toBe("skipped");
  });

  it("前方秘匿性を切ると鍵交換ステップが危険表示になる", async () => {
    const session = await runSession(base({ forwardSecrecy: false }));
    const step = session.steps.find((s) => s.title.includes("ECDHE"));
    expect(step?.status).toBe("danger");
    expect(session.keyExchange).toContain("静的");
  });
});

describe("ハンドシェイクの改ざん検出", () => {
  it("ClientHello を書き換えると transcript hash が食い違って失敗する", async () => {
    const session = await runSession({
      ...base(),
      tamperClientHello: (hello) => ({
        ...hello,
        cipherSuites: hello.cipherSuites.filter((s) => s.includes("RC4")),
      }),
    });
    expect(session.established).toBe(false);
    expect(session.abortReason).toBeTruthy();
  });

  it("Finished 照合を切ると書き換えが通ってしまう", async () => {
    const session = await runSession({
      ...base({ finishedVerify: false }),
      tamperClientHello: (hello) => ({
        ...hello,
        cipherSuites: hello.cipherSuites.filter((s) => s.includes("RC4")),
      }),
    });
    expect(session.established).toBe(true);
    expect(session.downgraded).toBe(true);
    expect(session.cipherSuite).toContain("RC4");
  });
});
