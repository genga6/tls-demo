import { describe, expect, it } from "vitest";
import { fromHex, hex, utf8, zeros } from "../src/lib/bytes";
import {
  HASH_LEN,
  aeadOpen,
  aeadSeal,
  deriveSecret,
  ecdhSharedSecret,
  generateEcdhKeyPair,
  hkdfExpand,
  hkdfExpandLabel,
  hkdfExtract,
  importAeadKey,
  recordNonce,
  sha256,
} from "../src/lib/crypto";
import { computeEarlySecret } from "../src/lib/key-schedule";

describe("HKDF (RFC 5869 テストベクタ)", () => {
  // RFC 5869 Appendix A.1 — SHA-256 の基本ケース。
  const ikm = fromHex("0b".repeat(22));
  const salt = fromHex("000102030405060708090a0b0c");
  const info = fromHex("f0f1f2f3f4f5f6f7f8f9");

  it("Extract が仕様どおりの PRK を返す", async () => {
    const prk = await hkdfExtract(salt, ikm);
    expect(hex(prk)).toBe("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
  });

  it("Expand が仕様どおりの OKM を返す", async () => {
    const prk = await hkdfExtract(salt, ikm);
    const okm = await hkdfExpand(prk, info, 42);
    expect(hex(okm)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("要求した長さちょうどを返す", async () => {
    const prk = await hkdfExtract(salt, ikm);
    for (const length of [1, 16, 32, 33, 64, 100]) {
      expect((await hkdfExpand(prk, info, length)).length).toBe(length);
    }
  });
});

describe("TLS 1.3 の鍵スケジュール", () => {
  it("PSK なしの Early Secret が RFC 8446 の既知の定数になる", async () => {
    // HKDF-Extract(salt=0, ikm=0) は定数。TLS 1.3 のトレース例に必ず現れる値。
    const early = await computeEarlySecret();
    expect(hex(early)).toBe("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
  });

  it("HKDF-Expand-Label はラベルが違えば必ず別の鍵になる", async () => {
    const secret = zeros(HASH_LEN);
    const empty = new Uint8Array(0);
    const key = await hkdfExpandLabel(secret, "key", empty, 16);
    const iv = await hkdfExpandLabel(secret, "iv", empty, 16);
    expect(hex(key)).not.toBe(hex(iv));
  });

  it("Derive-Secret は transcript hash が違えば別の鍵になる", async () => {
    const secret = zeros(HASH_LEN);
    const a = await deriveSecret(secret, "c hs traffic", await sha256(utf8("transcript-A")));
    const b = await deriveSecret(secret, "c hs traffic", await sha256(utf8("transcript-B")));
    expect(hex(a)).not.toBe(hex(b));
  });
});

describe("ECDHE", () => {
  it("両者が同じ共有秘密に辿り着く", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();

    const fromAlice = await ecdhSharedSecret(alice.privateKey, bob.publicKeyRaw);
    const fromBob = await ecdhSharedSecret(bob.privateKey, alice.publicKeyRaw);

    expect(hex(fromAlice)).toBe(hex(fromBob));
    expect(fromAlice.length).toBe(32);
  });

  it("別の鍵ペアなら別の共有秘密になる", async () => {
    const alice = await generateEcdhKeyPair();
    const bob = await generateEcdhKeyPair();
    const eve = await generateEcdhKeyPair();

    const real = await ecdhSharedSecret(alice.privateKey, bob.publicKeyRaw);
    const forged = await ecdhSharedSecret(eve.privateKey, bob.publicKeyRaw);

    expect(hex(real)).not.toBe(hex(forged));
  });
});

describe("AEAD (AES-128-GCM)", () => {
  const plaintext = utf8("GET /secret HTTP/1.1");
  const aad = fromHex("1703030014");

  it("封をして開けると元に戻る", async () => {
    const key = await importAeadKey(fromHex("00".repeat(16)));
    const nonce = fromHex("00".repeat(12));
    const sealed = await aeadSeal(key, nonce, plaintext, aad);
    const opened = await aeadOpen(key, nonce, sealed, aad);
    expect(opened && hex(opened)).toBe(hex(plaintext));
  });

  it("暗号文を 1 バイト書き換えると開封に失敗する", async () => {
    const key = await importAeadKey(fromHex("00".repeat(16)));
    const nonce = fromHex("00".repeat(12));
    const sealed = await aeadSeal(key, nonce, plaintext, aad);
    sealed[0] ^= 0x01;
    expect(await aeadOpen(key, nonce, sealed, aad)).toBeNull();
  });

  it("追加認証データ（レコードヘッダ）を書き換えても失敗する", async () => {
    const key = await importAeadKey(fromHex("00".repeat(16)));
    const nonce = fromHex("00".repeat(12));
    const sealed = await aeadSeal(key, nonce, plaintext, aad);
    expect(await aeadOpen(key, nonce, sealed, fromHex("1703030015"))).toBeNull();
  });

  it("鍵が違えば開封できない", async () => {
    const key = await importAeadKey(fromHex("00".repeat(16)));
    const otherKey = await importAeadKey(fromHex("ff".repeat(16)));
    const nonce = fromHex("00".repeat(12));
    const sealed = await aeadSeal(key, nonce, plaintext, aad);
    expect(await aeadOpen(otherKey, nonce, sealed, aad)).toBeNull();
  });
});

describe("レコード nonce", () => {
  it("連番ごとに必ず異なる nonce になる", () => {
    const iv = fromHex("0102030405060708090a0b0c");
    const nonces = new Set([0, 1, 2, 255, 256, 65535].map((n) => hex(recordNonce(iv, n))));
    expect(nonces.size).toBe(6);
  });

  it("連番 0 のときは IV そのもの", () => {
    const iv = fromHex("0102030405060708090a0b0c");
    expect(hex(recordNonce(iv, 0))).toBe(hex(iv));
  });
});
