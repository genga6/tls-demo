import { beforeAll, describe, expect, it } from "vitest";
import { type AttackId, runAllAttacks } from "../src/lib/attacks";
import { type DemoWorld, buildWorld } from "../src/lib/server";
import { ALL_DEFENSES_ON, DEFENSE_KEYS, type DefenseKey, type Defenses } from "../src/lib/types";

const NOW = new Date("2026-01-15T00:00:00Z");

let world: DemoWorld;
beforeAll(async () => {
  world = await buildWorld(NOW);
});

/** 各攻撃と、それを止める唯一の防御。 */
const ATTACK_DEFENSE: Record<AttackId, DefenseKey> = {
  mitm: "certificateChain",
  "wrong-hostname": "hostnameCheck",
  "expired-cert": "validityCheck",
  "revoked-cert": "validityCheck",
  "cert-copy": "certificateVerify",
  downgrade: "finishedVerify",
  "retrospective-decrypt": "forwardSecrecy",
  eavesdrop: "recordEncryption",
};

const ATTACK_IDS = Object.keys(ATTACK_DEFENSE) as AttackId[];

function without(...keys: DefenseKey[]): Defenses {
  const defenses = { ...ALL_DEFENSES_ON };
  for (const key of keys) defenses[key] = false;
  return defenses;
}

describe("防御がすべて有効なとき", () => {
  it("どの攻撃も成立しない", async () => {
    const results = await runAllAttacks(world, ALL_DEFENSES_ON);
    for (const result of results) {
      expect(result.succeeded, `${result.name} が成立してしまった`).toBe(false);
    }
  });

  it("阻止された理由が記録されている", async () => {
    const results = await runAllAttacks(world, ALL_DEFENSES_ON);
    for (const result of results) {
      expect(result.outcome.length).toBeGreaterThan(0);
      expect(result.loot).toBeUndefined();
    }
  });
});

describe("対応する防御を外すと攻撃が成立する", () => {
  for (const id of ATTACK_IDS) {
    it(`${id}: ${ATTACK_DEFENSE[id]} を OFF にすると成立する`, async () => {
      const results = await runAllAttacks(world, without(ATTACK_DEFENSE[id]));
      const target = results.find((r) => r.id === id);
      expect(target?.succeeded, target?.outcome).toBe(true);
    });
  }
});

describe("攻撃と防御が 1 対 1 で対応している", () => {
  for (const key of DEFENSE_KEYS) {
    it(`${key} を OFF にしても、対応しない攻撃は成立しない`, async () => {
      const results = await runAllAttacks(world, without(key));
      for (const result of results) {
        if (ATTACK_DEFENSE[result.id] === key) continue;
        expect(result.succeeded, `${result.name} が ${key} の OFF で成立した`).toBe(false);
      }
    });
  }

  it("無関係な防御をすべて外しても、対応する防御が有効なら阻止される", async () => {
    // certificateChain だけを残し、他をすべて OFF にする。
    const onlyChain = { ...ALL_DEFENSES_ON };
    for (const key of DEFENSE_KEYS) if (key !== "certificateChain") onlyChain[key] = false;

    const results = await runAllAttacks(world, onlyChain);
    const mitm = results.find((r) => r.id === "mitm");
    expect(mitm?.succeeded).toBe(false);
  });
});

describe("攻撃者が実際に得るもの", () => {
  it("中間者攻撃が成立すると HTTP リクエストの中身が読める", async () => {
    const results = await runAllAttacks(world, without("certificateChain"));
    const mitm = results.find((r) => r.id === "mitm");
    expect(mitm?.loot).toContain("Authorization: Bearer");
  });

  it("盗聴が成立すると Cookie が読める", async () => {
    const results = await runAllAttacks(world, without("recordEncryption"));
    const eavesdrop = results.find((r) => r.id === "eavesdrop");
    expect(eavesdrop?.loot).toContain("Cookie:");
  });

  it("前方秘匿性がないと、長期鍵の入手で記録済みの通信を復号できる", async () => {
    const results = await runAllAttacks(world, without("forwardSecrecy"));
    const attack = results.find((r) => r.id === "retrospective-decrypt");
    expect(attack?.succeeded).toBe(true);
    expect(attack?.loot).toContain("POST /api/transfer");
    expect(attack?.loot).toContain("Authorization: Bearer");
  });

  it("ECDHE なら長期鍵を入手しても復号できない", async () => {
    const results = await runAllAttacks(world, ALL_DEFENSES_ON);
    const attack = results.find((r) => r.id === "retrospective-decrypt");
    expect(attack?.succeeded).toBe(false);
    // セッション自体は正常に成立している（防げたのは遡及復号だけ）。
    expect(attack?.session?.established).toBe(true);
  });

  it("ダウングレードが成立すると弱いスイートが選ばれる", async () => {
    const results = await runAllAttacks(world, without("finishedVerify"));
    const attack = results.find((r) => r.id === "downgrade");
    expect(attack?.session?.cipherSuite).toContain("RC4");
  });
});
