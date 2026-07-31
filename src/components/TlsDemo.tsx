/**
 * 画面全体の組み立て。
 *
 *   ステータスバー          … いまの状態だけを短く
 *   盤面 ＋ 守りのラック    … 見る場所と、いじる場所を隣に置く
 *   攻撃スロット            … いじった結果が出る場所
 *
 * 守りを切り替えるたびに、正常フローと 8 つの攻撃をすべて計算し直す。表示用に用意した
 * 結果ではなく、その場で Web Crypto を回した実際の結果を出している。
 */

import { useEffect, useState } from "react";
import { type AttackResult, runAllAttacks } from "../lib/attacks";
import { type DemoWorld, LEGIT_HOSTNAME, buildWorld } from "../lib/server";
import { type SessionResult, runSession } from "../lib/session";
import { ALL_DEFENSES_ON, DEFENSE_KEYS, type DefenseKey, type Defenses } from "../lib/types";
import { AttackBoard } from "./Attacks";
import { DefenseRack } from "./Defenses";
import { Stage } from "./Stage";
import { IconGear, IconLock, IconLockOpen, IconShield, IconShieldBroken } from "./icons";
import { Pill } from "./ui";

export function TlsDemo() {
  const [world, setWorld] = useState<DemoWorld | null>(null);
  const [defenses, setDefenses] = useState<Defenses>(ALL_DEFENSES_ON);
  const [session, setSession] = useState<SessionResult | null>(null);
  const [attacks, setAttacks] = useState<AttackResult[]>([]);
  const [running, setRunning] = useState(true);

  // PKI の構築は鍵生成を何度も伴うので、一度だけ作って使い回す。
  useEffect(() => {
    let alive = true;
    buildWorld().then((built) => {
      if (alive) setWorld(built);
    });
    return () => {
      alive = false;
    };
  }, []);

  // 守りを切り替えるたびに、正常フローと全攻撃を計算し直す。
  useEffect(() => {
    if (!world) return;
    let alive = true;
    setRunning(true);

    (async () => {
      const [nextSession, nextAttacks] = await Promise.all([
        runSession({
          defenses,
          hostname: LEGIT_HOSTNAME,
          server: world.legitServer,
          trustedRoots: world.trustedRoots,
          revokedSerials: world.revokedSerials,
          now: world.now,
        }),
        runAllAttacks(world, defenses),
      ]);
      if (!alive) return;
      setSession(nextSession);
      setAttacks(nextAttacks);
      setRunning(false);
    })();

    return () => {
      alive = false;
    };
  }, [world, defenses]);

  if (!world) {
    return (
      <p className="panel flex items-center justify-center gap-2 px-5 py-12 text-sm text-ink-soft">
        <span className="cranking flex text-accent">
          <IconGear size={20} />
        </span>
        認証局と鍵ペアを生成中…
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <StatusBar
        session={session}
        defenses={defenses}
        attacks={attacks}
        running={running}
        onReset={() => setDefenses(ALL_DEFENSES_ON)}
      />

      <div className="grid items-start gap-3 lg:grid-cols-[minmax(0,1fr)_19rem]">
        {session && <Stage session={session} />}
        <DefenseRack defenses={defenses} onChange={setDefenses} />
      </div>

      <AttackBoard
        attacks={attacks}
        defenses={defenses}
        onToggleDefense={(key: DefenseKey, next: boolean) =>
          setDefenses((current) => ({ ...current, [key]: next }))
        }
      />
    </div>
  );
}

/**
 * いまの状態を 1 段で。
 *
 * 「接続できたか」「守りがいくつ立っているか」「攻撃がいくつ通ったか」の 3 つだけ。
 * 盾を 7 個並べるのは、数字より欠けが目に入るから。
 */
function StatusBar({
  session,
  defenses,
  attacks,
  running,
  onReset,
}: {
  session: SessionResult | null;
  defenses: Defenses;
  attacks: AttackResult[];
  running: boolean;
  onReset: () => void;
}) {
  const onCount = DEFENSE_KEYS.filter((key) => defenses[key]).length;
  const broken = attacks.filter((a) => a.succeeded).length;
  const established = session?.established ?? false;

  return (
    <div className="panel flex flex-wrap items-center gap-x-4 gap-y-2 px-3.5 py-2.5">
      <span className="flex items-center gap-1.5">
        <span className={established ? "text-safe" : "text-alarm"}>
          {established ? <IconLock size={18} /> : <IconLockOpen size={18} />}
        </span>
        <span className="text-xs font-bold">{established ? "接続確立" : "接続中止"}</span>
        <span className="font-mono text-[11px] text-ink-faint">{session?.cipherSuite ?? "—"}</span>
      </span>

      <span className="flex items-center gap-1.5">
        <span className="text-[10px] font-bold tracking-wider text-ink-faint uppercase">守り</span>
        <span className="flex gap-0.5">
          {DEFENSE_KEYS.map((key) => (
            <span key={key} className={defenses[key] ? "text-safe" : "text-alarm"}>
              {defenses[key] ? <IconShield size={15} /> : <IconShieldBroken size={15} />}
            </span>
          ))}
        </span>
        <span className="font-mono text-[11px] text-ink-faint">{onCount}/7</span>
      </span>

      <span className="flex items-center gap-1.5">
        <span className="text-[10px] font-bold tracking-wider text-ink-faint uppercase">突破</span>
        {broken > 0 ? <Pill tone="alarm">{broken} / 8</Pill> : <Pill tone="safe">0 / 8</Pill>}
      </span>

      <span className="ml-auto flex items-center gap-2">
        {running && <Pill tone="muted">計算中…</Pill>}
        {onCount < DEFENSE_KEYS.length && (
          <button
            type="button"
            onClick={onReset}
            className="text-[11px] font-bold text-accent underline underline-offset-2 hover:text-accent-deep"
          >
            全部 ON に戻す
          </button>
        )}
      </span>
    </div>
  );
}
