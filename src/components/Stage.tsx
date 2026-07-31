/**
 * 盤面。
 *
 * 全部の手を一度に並べると読む前に諦めてしまうので、**いま何が起きているか 1 手だけ**を出す。
 * 左がクライアント、右がサーバー、その間が経路。通信なら封筒が経路を渡っていき、
 * 手元の計算なら歯車が回る。
 *
 * 経路のすぐ下に盗聴者の窓を置いてあるのが肝。手を進めると、最初の 2 通は中身が読めていて、
 * 鍵ができた瞬間から読めなくなる、という切り替わりが同じ場所で目に入る。
 */

import { useEffect, useMemo, useState } from "react";
import { PHASE_NOTE, STEP_COPY } from "../lib/plain";
import type { SessionResult, WiretapEntry } from "../lib/session";
import {
  type FlowStep,
  PHASE_LABELS,
  type Phase,
  type StepId,
  type StepStatus,
} from "../lib/types";
import {
  IconBrowser,
  IconCertificate,
  IconEnvelope,
  IconEye,
  IconGear,
  IconGlobe,
  IconHandshake,
  IconKey,
  IconLock,
  IconLockOpen,
  IconMask,
  IconNext,
  IconPause,
  IconPlay,
  IconPrev,
  IconReset,
  IconServer,
} from "./icons";
import { Button, DataList, More, Panel, Pill, Wire } from "./ui";

const PHASE_ORDER: Phase[] = ["handshake", "certificate", "key-exchange", "encryption", "https"];

const PHASE_ICON: Record<Phase, () => React.ReactElement> = {
  handshake: () => <IconHandshake size={16} />,
  certificate: () => <IconCertificate size={16} />,
  "key-exchange": () => <IconKey size={16} />,
  encryption: () => <IconLock size={16} />,
  https: () => <IconGlobe size={16} />,
};

/** 自動再生で 1 手にかける時間。封筒が渡り切る 1.05 秒 + 読む時間。 */
const STEP_MS = 2500;

const STATUS_PILL: Record<StepStatus, { tone: "safe" | "open" | "alarm"; text: string }> = {
  ok: { tone: "safe", text: "OK" },
  skipped: { tone: "open", text: "省略" },
  failed: { tone: "alarm", text: "中止" },
  danger: { tone: "alarm", text: "危険" },
};

export function Stage({ session }: { session: SessionResult }) {
  const steps = session.steps;
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(true);

  // 守りを切り替えると手順そのものが変わるので、頭から見せ直す。
  // 描画中にその場で直す形にしてあるのは、副作用で戻すと 1 度古い手を描いてしまうため。
  const [shown, setShown] = useState(session);
  if (shown !== session) {
    setShown(session);
    setCursor(0);
  }

  useEffect(() => {
    if (!playing || steps.length === 0) return;
    if (cursor >= steps.length - 1) {
      setPlaying(false);
      return;
    }
    const timer = setTimeout(() => setCursor((c) => c + 1), STEP_MS);
    return () => clearTimeout(timer);
  }, [playing, cursor, steps.length]);

  const wiretapByLabel = useMemo(() => {
    const map = new Map<string, WiretapEntry>();
    for (const entry of session.wiretap) map.set(entry.label, entry);
    return map;
  }, [session.wiretap]);

  if (steps.length === 0) return null;

  const index = Math.min(cursor, steps.length - 1);
  const step = steps[index];
  const copy = STEP_COPY[step.id];
  const atEnd = index === steps.length - 1;
  const entry = copy.wiretapLabel ? wiretapByLabel.get(copy.wiretapLabel) : undefined;

  const jump = (to: number) => {
    setPlaying(false);
    setCursor(Math.max(0, Math.min(steps.length - 1, to)));
  };

  return (
    <Panel
      title="ハンドシェイクの再生"
      hint="1 手ずつ進む"
      actions={
        <span className="font-mono text-xs text-ink-faint">
          {index + 1} / {steps.length}
        </span>
      }
    >
      <PhaseTrack steps={steps} current={step} onJump={jump} />

      <Board step={step} steps={steps} entry={entry} wiretap={session.wiretap} onJump={jump} />

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <Button
          tone="accent"
          onClick={() => {
            if (atEnd && !playing) setCursor(0);
            setPlaying(!playing);
          }}
          label={playing ? "一時停止" : atEnd ? "もう一度再生" : "再生"}
        >
          {playing ? <IconPause size={16} /> : <IconPlay size={16} />}
          <span>{playing ? "一時停止" : atEnd ? "もう一度" : "再生"}</span>
        </Button>
        <Button onClick={() => jump(index - 1)} disabled={index === 0} label="前の手へ">
          <IconPrev size={16} />
        </Button>
        <Button onClick={() => jump(index + 1)} disabled={atEnd} label="次の手へ">
          <IconNext size={16} />
        </Button>
        <Button onClick={() => jump(0)} disabled={index === 0} label="最初から">
          <IconReset size={16} />
        </Button>

        <StepDots steps={steps} index={index} onSelect={jump} />
      </div>

      <Caption step={step} />

      {!session.established && atEnd && session.abortReason && (
        <p className="mt-2.5 rounded-xl border-[1.5px] border-alarm/40 bg-alarm-soft px-3 py-2 text-xs leading-relaxed text-alarm">
          <strong className="font-bold">接続中止。</strong>
          実際のブラウザなら警告画面が出る場面。
          <span className="mt-1 block font-mono text-[11px] break-all opacity-80">
            {session.abortReason}
          </span>
        </p>
      )}

      <div className="mt-3 border-t border-line-soft pt-2.5">
        <More summary="盗聴者が最後まで記録したものを見る">
          <ul className="space-y-2">
            {session.wiretap.map((item) => (
              <li key={item.label}>
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="text-xs font-semibold">{item.label}</span>
                  {item.readable ? (
                    <Pill tone="alarm">読める</Pill>
                  ) : (
                    <Pill tone="safe">読めない</Pill>
                  )}
                </div>
                <div className="mt-1">
                  <Wire tone={item.readable ? "alarm" : "muted"}>{item.visible}</Wire>
                </div>
                <p className="mt-0.5 text-[11px] leading-relaxed text-ink-faint">{item.note}</p>
              </li>
            ))}
          </ul>
        </More>
      </div>
    </Panel>
  );
}

// ---------------------------------------------------------------------------
// 5 つの層
// ---------------------------------------------------------------------------

/**
 * どの層の話かを示す 5 つの札。
 *
 * **進捗バーではない。** この 5 つは順番に実行される工程ではなく、1 回のハンドシェイクの中で
 * 絡み合う 5 つの関心事なので、時間順には並ばない。鍵交換の材料は最初の ClientHello に
 * 乗っているから鍵づくりが先に終わり (3〜4 手)、証明書はその鍵で暗号化された中を通る (5〜7 手)。
 * Handshake は 8〜9 手にもう一度戻ってくる。
 *
 * だから札には「その層が何手目を担当しているか」を出す。並び順で誤解させないため。
 *
 * 並べる順も、ツリーの順ではなく**最初に出てくる手が早い順**にしてある（盤面は時間の話をして
 * いる場所なので）。守りのラック側はツリーの順のまま。あちらは時間ではなく関心事の並びだから。
 */
function PhaseTrack({
  steps,
  current,
  onJump,
}: {
  steps: FlowStep[];
  current: FlowStep;
  onJump: (index: number) => void;
}) {
  const order = [...PHASE_ORDER].sort((a, b) => firstIndexOf(steps, a) - firstIndexOf(steps, b));

  return (
    <ol className="flex gap-1">
      {order.map((phase) => {
        const owned = steps.filter((s) => s.phase === phase);
        const active = current.phase === phase;

        return (
          <li key={phase} className="min-w-0 flex-1">
            <button
              type="button"
              disabled={owned.length === 0}
              onClick={() => owned[0] && onJump(owned[0].index - 1)}
              title={`${PHASE_NOTE[phase]}（${
                owned.length > 0
                  ? `${owned.map((s) => s.index).join("・")} 手目`
                  : "この設定では出番なし"
              }）`}
              className={`w-full rounded-lg border-[1.5px] px-1 py-1.5 transition disabled:opacity-30 ${
                active
                  ? "border-accent bg-accent text-white"
                  : "border-line-soft bg-paper text-ink-faint hover:border-line"
              }`}
            >
              <span className="flex items-center justify-center gap-1.5">
                {PHASE_ICON[phase]()}
                <span className="hidden truncate text-[11px] font-bold sm:inline">
                  {PHASE_LABELS[phase]}
                </span>
              </span>

              {/* その層が担当する手番。時間順に並んでいないことがここで分かる。 */}
              <span className="mt-0.5 hidden justify-center gap-1 font-mono text-[9px] sm:flex">
                {owned.length === 0
                  ? "—"
                  : owned.map((s) => (
                      <span
                        key={s.index}
                        className={
                          s.index === current.index
                            ? "font-bold"
                            : active
                              ? "opacity-70"
                              : "opacity-60"
                        }
                      >
                        {s.index}
                      </span>
                    ))}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

/** その層が最初に登場する手番。出番がなければ末尾に回す。 */
function firstIndexOf(steps: FlowStep[], phase: Phase): number {
  const first = steps.find((s) => s.phase === phase);
  return first ? first.index : Number.MAX_SAFE_INTEGER;
}

// ---------------------------------------------------------------------------
// 盤面（クライアント ─ 経路 ─ サーバー ＋ 盗聴者）
// ---------------------------------------------------------------------------

function Board({
  step,
  steps,
  entry,
  wiretap,
  onJump,
}: {
  step: FlowStep;
  steps: FlowStep[];
  entry?: WiretapEntry;
  wiretap: WiretapEntry[];
  onJump: (index: number) => void;
}) {
  const internal = step.from === step.to;
  const toRight = step.to === "server";
  const byAttacker = step.from === "attacker";
  const sealed =
    step.protection === "handshake-encrypted" || step.protection === "application-encrypted";
  const failed = step.status === "failed";

  const wireTone = byAttacker
    ? "text-alarm"
    : internal
      ? "text-line"
      : sealed
        ? "text-safe"
        : "text-open";

  return (
    <div className="mt-2.5 flex flex-col rounded-xl border-[1.5px] border-line-soft bg-paper p-3">
      <div className="grid grid-cols-[3.75rem_1fr_3.75rem] items-center gap-2 sm:grid-cols-[5.5rem_1fr_5.5rem] sm:gap-3">
        <Node
          icon={<IconBrowser size={26} />}
          label="クライアント"
          sub="ブラウザ"
          active={step.from === "client" || step.to === "client"}
          working={internal && step.from === "client"}
        />

        <div className="relative h-24">
          <div
            className={`absolute top-1/2 h-[3px] w-full -translate-y-1/2 ${wireTone} ${
              internal ? "opacity-40" : toRight ? "wire-flow" : "wire-flow wire-flow-back"
            }`}
            style={internal ? { background: "currentColor" } : undefined}
          />

          {internal ? (
            <p className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full border-[1.5px] border-line-soft bg-card px-2.5 py-1 text-[10px] font-semibold text-ink-faint">
              経路には何も流れない
            </p>
          ) : (
            // 手が変わるたびに作り直して、動きを最初から見せる。
            <div
              key={step.index}
              className={`absolute top-1/2 ${toRight ? "packet-right" : "packet-left"}`}
            >
              <Packet
                title={STEP_COPY[step.id].title}
                sealed={sealed}
                byAttacker={byAttacker}
                failed={failed}
              />
            </div>
          )}
        </div>

        <Node
          icon={<IconServer size={26} />}
          label="サーバー"
          sub="bank.example.com"
          active={step.from === "server" || step.to === "server"}
          working={internal && step.from === "server"}
        />
      </div>

      <Eavesdrop entry={entry} internal={internal} sealed={sealed} />
      <OnTheWire steps={steps} current={step} wiretap={wiretap} onJump={onJump} />
      <Inventory steps={steps} current={step} />
    </div>
  );
}

/**
 * 経路に出たものの一覧。
 *
 * 「平文なのは最初の 2 通だけ」というこのデモの核心は、1 手ずつ見ているだけでは
 * 掴みにくい。全部を並べて封の有無で塗り分けると、境目が一目で分かる。
 * 押すとその手に飛ぶ。
 */
function OnTheWire({
  steps,
  current,
  wiretap,
  onJump,
}: {
  steps: FlowStep[];
  current: FlowStep;
  wiretap: WiretapEntry[];
  onJump: (index: number) => void;
}) {
  return (
    <div className="mt-2 flex items-center gap-2">
      <span className="flex shrink-0 items-center gap-1 rounded-lg border-[1.5px] border-line bg-card px-1.5 py-1 text-[10px] font-bold text-ink-faint">
        <IconEnvelope size={14} />
        <span className="hidden sm:inline">経路</span>
      </span>

      <ol className="flex min-w-0 flex-1 flex-wrap gap-1">
        {wiretap.map((item) => {
          const at = steps.find((s) => STEP_COPY[s.id].wiretapLabel === item.label);
          const isCurrent = at !== undefined && at.index === current.index;
          const reached = at !== undefined && at.index <= current.index;
          return (
            <li key={item.label}>
              <button
                type="button"
                disabled={at === undefined}
                onClick={() => at && onJump(at.index - 1)}
                title={item.note}
                className={`flex items-center gap-1 rounded-lg border-[1.5px] px-1.5 py-1 text-[10px] font-bold transition disabled:cursor-default ${
                  item.readable
                    ? "border-open/40 bg-open-soft text-open"
                    : "border-safe/40 bg-safe-soft text-safe"
                } ${isCurrent ? "outline-2 outline-offset-1 outline-accent" : ""} ${
                  reached ? "" : "opacity-45"
                }`}
              >
                {item.readable ? <IconLockOpen size={12} /> : <IconLock size={12} />}
                <span className="max-w-[8rem] truncate">{item.label}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

/**
 * ここまでに両者が手にしたもの。
 *
 * 数字や文章ではなく持ち物が増えていく形にしてあるのは、鍵が「いつ」生まれるのかが
 * ハンドシェイクのいちばん掴みにくいところだから。灰色から色が付く瞬間が答えになる。
 */
const INVENTORY: { id: StepId; label: string }[] = [
  { id: "client-hello", label: "使い捨て公開鍵" },
  { id: "ecdhe", label: "共有秘密 abG" },
  { id: "key-schedule", label: "handshake 鍵" },
  { id: "app-keys", label: "application 鍵" },
];

function Inventory({ steps, current }: { steps: FlowStep[]; current: FlowStep }) {
  return (
    <div className="mt-2 flex items-center gap-2">
      <span className="flex shrink-0 items-center gap-1 rounded-lg border-[1.5px] border-line bg-card px-1.5 py-1 text-[10px] font-bold text-ink-faint">
        <IconKey size={14} />
        <span className="hidden sm:inline">手持ち</span>
      </span>

      <ol className="flex min-w-0 flex-1 flex-wrap gap-1">
        {INVENTORY.map(({ id, label }) => {
          const at = steps.find((s) => s.id === id);
          const held = at !== undefined && at.index <= current.index;
          return (
            <li
              key={id}
              className={`flex items-center gap-1 rounded-lg border-[1.5px] px-1.5 py-1 text-[10px] font-bold transition ${
                held
                  ? "border-safe/40 bg-safe-soft text-safe"
                  : "border-line-soft bg-card text-ink-faint opacity-50"
              }`}
            >
              {held ? <IconLock size={12} /> : <IconLockOpen size={12} />}
              <span className="truncate">{label}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function Node({
  icon,
  label,
  sub,
  active,
  working,
}: {
  icon: React.ReactNode;
  label: string;
  sub: string;
  active: boolean;
  working: boolean;
}) {
  return (
    <div
      className={`rounded-xl border-[1.5px] px-1 py-3 text-center transition ${
        active
          ? "border-accent bg-card text-accent-deep shadow-[0_2px_0_var(--color-accent)]"
          : "border-line-soft bg-card text-ink-faint"
      }`}
    >
      <span className="flex justify-center">
        {working ? (
          <span className="cranking flex text-accent">
            <IconGear size={26} />
          </span>
        ) : (
          icon
        )}
      </span>
      <span className="mt-1 block truncate text-[11px] font-bold">{label}</span>
      <span className="mt-px block truncate font-mono text-[9px] text-ink-faint">{sub}</span>
    </div>
  );
}

/** 経路を渡っていく 1 通。封の有無が見た目で分かるようにする。 */
function Packet({
  title,
  sealed,
  byAttacker,
  failed,
}: {
  title: string;
  sealed: boolean;
  byAttacker: boolean;
  failed: boolean;
}) {
  const tone = byAttacker
    ? "border-alarm bg-alarm-soft text-alarm"
    : failed
      ? "border-alarm bg-card text-alarm"
      : sealed
        ? "border-safe bg-safe-soft text-safe"
        : "border-open border-dashed bg-open-soft text-open";

  return (
    <span
      className={`flex items-center gap-1.5 rounded-xl border-[1.5px] px-2 py-1.5 whitespace-nowrap shadow-sm ${tone}`}
    >
      {byAttacker ? (
        <IconMask size={15} />
      ) : sealed ? (
        <IconLock size={15} />
      ) : (
        <IconLockOpen size={15} />
      )}
      <span className="max-w-[9rem] truncate text-[11px] font-bold sm:max-w-none">{title}</span>
    </span>
  );
}

/** 経路をのぞいている第三者に、いまこの瞬間何が見えているか。 */
function Eavesdrop({
  entry,
  internal,
  sealed,
}: {
  entry?: WiretapEntry;
  internal: boolean;
  sealed: boolean;
}) {
  const readable = entry?.readable ?? false;

  return (
    <div className="mt-2 flex items-start gap-2">
      <span
        className={`mt-px flex shrink-0 items-center gap-1 rounded-lg border-[1.5px] px-1.5 py-1 text-[10px] font-bold ${
          readable
            ? "border-alarm/40 bg-alarm-soft text-alarm"
            : "border-line bg-card text-ink-faint"
        }`}
      >
        <IconEye size={14} />
        <span className="hidden sm:inline">盗聴者</span>
      </span>

      <div className="min-w-0 flex-1">
        {entry ? (
          <>
            <Wire tone={readable ? "alarm" : "safe"} clamp>
              {entry.visible}
            </Wire>
            <p className="mt-0.5 truncate text-[10px] text-ink-faint">{entry.note}</p>
          </>
        ) : (
          <Wire tone="muted" clamp>
            {internal
              ? "— 手元の計算なので、経路には何も出ない"
              : sealed
                ? "— 暗号文が流れただけ。長さと時刻しか分からない"
                : "—"}
          </Wire>
        )}
      </div>

      {entry && (readable ? <Pill tone="alarm">読める</Pill> : <Pill tone="safe">読めない</Pill>)}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 現在地と説明
// ---------------------------------------------------------------------------

/** 全手順のつまみ。番号だけの丸を並べ、好きなところに飛べるようにする。 */
function StepDots({
  steps,
  index,
  onSelect,
}: {
  steps: FlowStep[];
  index: number;
  onSelect: (index: number) => void;
}) {
  return (
    <ol className="ml-auto flex flex-wrap gap-1">
      {steps.map((step, i) => {
        const current = i === index;
        const bad = step.status === "failed" || step.status === "danger";
        return (
          <li key={step.index}>
            <button
              type="button"
              onClick={() => onSelect(i)}
              aria-label={`${step.index}. ${STEP_COPY[step.id].title}`}
              aria-current={current}
              title={STEP_COPY[step.id].title}
              className={`grid size-6 place-items-center rounded-md border-[1.5px] font-mono text-[10px] font-bold transition ${
                current
                  ? "border-accent bg-accent text-white"
                  : bad
                    ? "border-alarm/40 bg-alarm-soft text-alarm"
                    : i < index
                      ? "border-accent/30 bg-accent-soft text-accent-deep"
                      : "border-line-soft bg-paper text-ink-faint hover:border-line"
              }`}
            >
              {step.index}
            </button>
          </li>
        );
      })}
    </ol>
  );
}

/** いまの手の説明。見出し + 1 文だけを常に出し、残りは折りたたむ。 */
function Caption({ step }: { step: FlowStep }) {
  const copy = STEP_COPY[step.id];
  const pill = STATUS_PILL[step.status];
  const skipped = step.status === "skipped";

  return (
    <div key={step.index} className="rise-in mt-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="grid size-6 shrink-0 place-items-center rounded-md bg-ink font-mono text-[11px] font-bold text-white">
          {step.index}
        </span>
        <h3 className="text-base font-bold">{copy.title}</h3>
        <Pill tone={pill.tone}>{pill.text}</Pill>
        <span className="text-[11px] text-ink-faint">{PHASE_LABELS[step.phase]}</span>
      </div>

      <p className="mt-1.5 text-sm leading-relaxed text-ink-soft">
        {skipped && copy.whenSkipped ? copy.whenSkipped : copy.line}
      </p>

      <div className="mt-2">
        <More summary="くわしく / 実際に計算された値">
          <div className="rounded-xl border-[1.5px] border-line-soft bg-paper px-3 py-2.5">
            <p className="text-xs leading-relaxed text-ink-soft">{copy.more}</p>
            <p className="mt-2 border-t border-line-soft pt-2 font-mono text-[11px] text-ink-faint">
              {step.title}
            </p>
            <p className="mt-1 text-[11px] leading-relaxed text-ink-faint">{step.detail}</p>
            {step.data && <DataList data={step.data} />}
          </div>
        </More>
      </div>
    </div>
  );
}
