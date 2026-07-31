import { useEffect, useMemo, useState } from "react";
import { type AttackResult, lootPreview, runAllAttacks } from "../lib/attacks";
import { type DemoWorld, LEGIT_HOSTNAME, buildWorld } from "../lib/server";
import { type SessionResult, runSession } from "../lib/session";
import {
  ACTOR_LABELS,
  ALL_DEFENSES_ON,
  DEFENSE_INFO,
  DEFENSE_KEYS,
  type DefenseKey,
  type Defenses,
  type FlowStep,
  PHASE_LABELS,
  PHASE_SUMMARIES,
  type Phase,
  type StepStatus,
} from "../lib/types";
import { Arrow, Badge, DataList, Mono, Panel, PhaseBadge, Toggle } from "./ui";

const PHASE_ORDER: Phase[] = ["handshake", "certificate", "key-exchange", "encryption", "https"];

const STATUS_TONE: Record<StepStatus, "ok" | "warn" | "danger" | "muted"> = {
  ok: "ok",
  skipped: "warn",
  failed: "danger",
  danger: "danger",
};

const STATUS_LABEL: Record<StepStatus, string> = {
  ok: "OK",
  skipped: "省略",
  failed: "失敗",
  danger: "危険",
};

const PROTECTION_LABEL: Record<FlowStep["protection"], string> = {
  plaintext: "平文",
  "handshake-encrypted": "ハンドシェイク鍵で暗号化",
  "application-encrypted": "アプリ鍵で暗号化",
  internal: "—",
};

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

  // 防御を切り替えるたびに、正常フローと全攻撃を計算し直す。
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

  const disabledCount = DEFENSE_KEYS.filter((key) => !defenses[key]).length;
  const succeededCount = attacks.filter((a) => a.succeeded).length;

  if (!world) {
    return (
      <p className="rounded-xl border border-slate-800 bg-slate-900/40 px-5 py-8 text-center text-sm text-slate-400">
        認証局と鍵ペアを生成中…
      </p>
    );
  }

  return (
    <div className="space-y-6">
      <DefensePanel defenses={defenses} onChange={setDefenses} disabledCount={disabledCount} />
      {session && <FlowPanel session={session} running={running} />}
      {session && <WiretapPanel session={session} />}
      <AttackPanel attacks={attacks} succeededCount={succeededCount} running={running} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// 防御トグル
// ---------------------------------------------------------------------------

function DefensePanel({
  defenses,
  onChange,
  disabledCount,
}: {
  defenses: Defenses;
  onChange: (next: Defenses) => void;
  disabledCount: number;
}) {
  const byPhase = useMemo(() => {
    const map = new Map<Phase, DefenseKey[]>();
    for (const key of DEFENSE_KEYS) {
      const phase = DEFENSE_INFO[key].phase;
      map.set(phase, [...(map.get(phase) ?? []), key]);
    }
    return map;
  }, []);

  return (
    <Panel
      title="防御トグル"
      subtitle="TLS の各層が担っている防御。OFF にすると、対応する攻撃だけがちょうど 1 つ成立する。"
      actions={
        <div className="flex items-center gap-3">
          {disabledCount > 0 ? (
            <Badge tone="danger">{disabledCount} 個 OFF</Badge>
          ) : (
            <Badge tone="ok">すべて有効</Badge>
          )}
          <button
            type="button"
            onClick={() => onChange(ALL_DEFENSES_ON)}
            disabled={disabledCount === 0}
            className="rounded-md border border-slate-700 px-3 py-1.5 text-xs text-slate-300 transition hover:border-slate-600 hover:text-slate-100 disabled:cursor-not-allowed disabled:opacity-40"
          >
            すべて ON に戻す
          </button>
        </div>
      }
    >
      <div className="space-y-5">
        {PHASE_ORDER.map((phase) => {
          const keys = byPhase.get(phase) ?? [];
          return (
            <div key={phase}>
              <div className="flex items-center gap-2">
                <PhaseBadge phase={phase} />
                <span className="text-xs text-slate-500">{PHASE_SUMMARIES[phase]}</span>
              </div>
              {keys.length > 0 ? (
                <div className="mt-2 grid gap-2 md:grid-cols-2">
                  {keys.map((key) => (
                    <Toggle
                      key={key}
                      checked={defenses[key]}
                      onChange={(next) => onChange({ ...defenses, [key]: next })}
                      label={DEFENSE_INFO[key].label}
                      description={DEFENSE_INFO[key].what}
                      attack={DEFENSE_INFO[key].attack}
                    />
                  ))}
                </div>
              ) : (
                <p className="mt-2 text-xs leading-relaxed text-slate-500">
                  HTTPS 固有の防御はない。HTTP を TLS の上に流しているだけなので、 安全性は下の 4
                  層がそのまま決める。
                </p>
              )}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// 正常フローの可視化
// ---------------------------------------------------------------------------

function FlowPanel({ session, running }: { session: SessionResult; running: boolean }) {
  return (
    <Panel
      title="正常フローの段階可視化"
      subtitle={`${LEGIT_HOSTNAME} への接続を、現在の防御設定で最初から最後まで実行した記録。`}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          {running && <Badge tone="muted">計算中…</Badge>}
          {session.established ? (
            <Badge tone="ok">接続確立</Badge>
          ) : (
            <Badge tone="danger">中断</Badge>
          )}
          <Badge tone="info">{session.cipherSuite}</Badge>
        </div>
      }
    >
      {!session.established && session.abortReason && (
        <p className="mb-4 rounded-md border border-rose-900/60 bg-rose-950/20 px-3 py-2 text-sm text-rose-200">
          中断理由: {session.abortReason}
        </p>
      )}

      <div className="mb-4 grid gap-2 sm:grid-cols-2">
        <InfoRow label="鍵交換" value={session.keyExchange} />
        <InfoRow label="暗号スイート" value={session.cipherSuite} />
      </div>

      <ol className="space-y-2">
        {session.steps.map((step) => (
          <StepCard key={step.index} step={step} />
        ))}
      </ol>

      {Object.keys(session.secrets).length > 0 && (
        <details className="mt-4 rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-3">
          <summary className="cursor-pointer text-sm text-slate-300">
            導出された鍵素材をすべて見る
          </summary>
          <DataList data={session.secrets} />
        </details>
      )}
    </Panel>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-slate-800 bg-slate-950/40 px-3 py-2">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="mt-0.5 font-mono text-xs text-slate-300">{value}</div>
    </div>
  );
}

function StepCard({ step }: { step: FlowStep }) {
  const borderByStatus: Record<StepStatus, string> = {
    ok: "border-slate-800",
    skipped: "border-amber-900/60 bg-amber-950/10",
    failed: "border-rose-900/60 bg-rose-950/10",
    danger: "border-amber-900/60 bg-amber-950/10",
  };

  return (
    <li className={`rounded-lg border bg-slate-950/40 px-4 py-3 ${borderByStatus[step.status]}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs text-slate-600">
          {String(step.index).padStart(2, "0")}
        </span>
        <PhaseBadge phase={step.phase} />
        <span className="text-sm font-medium text-slate-100">{step.title}</span>
        <Badge tone={STATUS_TONE[step.status]}>{STATUS_LABEL[step.status]}</Badge>
      </div>

      <div className="mt-1.5 flex flex-wrap items-center gap-3">
        <Arrow from={ACTOR_LABELS[step.from]} to={ACTOR_LABELS[step.to]} />
        {step.protection !== "internal" && (
          <span
            className={`font-mono text-[11px] ${
              step.protection === "plaintext" ? "text-amber-400" : "text-emerald-400"
            }`}
          >
            {PROTECTION_LABEL[step.protection]}
          </span>
        )}
      </div>

      <p className="mt-2 text-sm leading-relaxed text-slate-400">{step.detail}</p>
      {step.data && <DataList data={step.data} />}
    </li>
  );
}

// ---------------------------------------------------------------------------
// 盗聴者ビュー
// ---------------------------------------------------------------------------

function WiretapPanel({ session }: { session: SessionResult }) {
  // ClientHello / ServerHello は暗号化していても必ず平文なので、漏洩とは数えない。
  // 本当に問題なのは、アプリケーションデータが読めてしまっているかどうか。
  const leaked = session.wiretap.filter(
    (entry) => entry.readable && entry.label.startsWith("HTTP"),
  ).length;

  return (
    <Panel
      title="経路上の盗聴者に見えているもの"
      subtitle="同じ Wi-Fi や中継機器からパケットを眺めているだけの第三者の視点。"
      actions={
        leaked > 0 ? (
          <Badge tone="danger">HTTP {leaked} 件が平文で読める</Badge>
        ) : (
          <Badge tone="ok">アプリデータは暗号文のみ</Badge>
        )
      }
    >
      <ul className="space-y-3">
        {session.wiretap.map((entry) => (
          <li key={entry.label}>
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-slate-200">{entry.label}</span>
              {entry.readable ? (
                <Badge tone="danger">読める</Badge>
              ) : (
                <Badge tone="ok">暗号文</Badge>
              )}
            </div>
            <Mono tone={entry.readable ? "danger" : "muted"}>{entry.visible}</Mono>
            <p className="mt-1 text-xs leading-relaxed text-slate-500">{entry.note}</p>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// 攻撃マトリクス
// ---------------------------------------------------------------------------

function AttackPanel({
  attacks,
  succeededCount,
  running,
}: {
  attacks: AttackResult[];
  succeededCount: number;
  running: boolean;
}) {
  return (
    <Panel
      title="攻撃マトリクス"
      subtitle="各攻撃は、対応する防御 1 つだけで結果が決まる。他の防御を切っても結果は変わらない。"
      actions={
        running ? (
          <Badge tone="muted">計算中…</Badge>
        ) : succeededCount > 0 ? (
          <Badge tone="danger">{succeededCount} 件が成立</Badge>
        ) : (
          <Badge tone="ok">すべて阻止</Badge>
        )
      }
    >
      <ul className="space-y-2">
        {attacks.map((attack) => (
          <li
            key={attack.id}
            className={`rounded-lg border px-4 py-3 ${
              attack.succeeded
                ? "border-rose-900/60 bg-rose-950/20"
                : "border-slate-800 bg-slate-950/40"
            }`}
          >
            <div className="flex flex-wrap items-center gap-2">
              <PhaseBadge phase={attack.phase} />
              <span className="text-sm font-medium text-slate-100">{attack.name}</span>
              {attack.succeeded ? (
                <Badge tone="danger">攻撃成立</Badge>
              ) : (
                <Badge tone="ok">防御で阻止</Badge>
              )}
            </div>

            <p className="mt-2 text-sm leading-relaxed text-slate-400">{attack.premise}</p>

            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
              <span className="text-slate-500">成否を決める防御:</span>
              <span className="font-mono text-slate-300">{DEFENSE_INFO[attack.defense].label}</span>
            </div>

            <p
              className={`mt-2 text-sm leading-relaxed ${
                attack.succeeded ? "text-rose-200" : "text-emerald-200"
              }`}
            >
              {attack.outcome}
            </p>

            {attack.succeeded && attack.loot && (
              <>
                <div className="mt-3 text-xs text-slate-500">攻撃者が手にしたもの:</div>
                <Mono tone="danger">{lootPreview(attack.loot)}</Mono>
              </>
            )}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

/** ヘッダーで使う TLS のツリー表示。 */
export function TlsTree() {
  return (
    <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-950/60 px-4 py-3 font-mono text-xs leading-relaxed text-slate-400">
      {`TLS
├── ${PHASE_LABELS.handshake.padEnd(13)}# ${PHASE_SUMMARIES.handshake}
├── ${PHASE_LABELS.certificate.padEnd(13)}# ${PHASE_SUMMARIES.certificate}
├── ${PHASE_LABELS["key-exchange"].padEnd(13)}# ${PHASE_SUMMARIES["key-exchange"]}
├── ${PHASE_LABELS.encryption.padEnd(13)}# ${PHASE_SUMMARIES.encryption}
└── ${PHASE_LABELS.https.padEnd(13)}# ${PHASE_SUMMARIES.https}`}
    </pre>
  );
}
