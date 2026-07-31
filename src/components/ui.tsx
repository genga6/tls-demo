/** デモ画面で使い回す小さな表示部品。 */

import type { ReactNode } from "react";
import { PHASE_LABELS, type Phase } from "../lib/types";

type Tone = "ok" | "warn" | "danger" | "muted" | "info";

const TONE_CLASSES: Record<Tone, string> = {
  ok: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/30",
  warn: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  danger: "bg-rose-500/10 text-rose-300 ring-rose-500/30",
  muted: "bg-slate-500/10 text-slate-400 ring-slate-500/30",
  info: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
};

export function Badge({ tone = "muted", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${TONE_CLASSES[tone]}`}
    >
      {children}
    </span>
  );
}

const PHASE_TONES: Record<Phase, string> = {
  handshake: "bg-violet-500/10 text-violet-300 ring-violet-500/30",
  certificate: "bg-sky-500/10 text-sky-300 ring-sky-500/30",
  "key-exchange": "bg-teal-500/10 text-teal-300 ring-teal-500/30",
  encryption: "bg-amber-500/10 text-amber-300 ring-amber-500/30",
  https: "bg-fuchsia-500/10 text-fuchsia-300 ring-fuchsia-500/30",
};

export function PhaseBadge({ phase }: { phase: Phase }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded px-1.5 py-0.5 font-mono text-[11px] ring-1 ring-inset ${PHASE_TONES[phase]}`}
    >
      {PHASE_LABELS[phase]}
    </span>
  );
}

export function Panel({
  title,
  subtitle,
  actions,
  children,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/40">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 px-5 py-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
          {subtitle && <p className="mt-1 max-w-2xl text-sm text-slate-400">{subtitle}</p>}
        </div>
        {actions}
      </header>
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}

/** ON/OFF トグル 1 個。OFF のときは「危険な状態」として見た目を変える。 */
export function Toggle({
  checked,
  onChange,
  label,
  description,
  attack,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  description: string;
  attack: string;
}) {
  return (
    <label
      className={`flex cursor-pointer gap-3 rounded-lg border p-3 transition ${
        checked
          ? "border-slate-800 bg-slate-900/60 hover:border-slate-700"
          : "border-rose-900/60 bg-rose-950/20 hover:border-rose-800"
      }`}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-1 size-4 shrink-0 accent-emerald-500"
      />
      <span className="min-w-0">
        <span className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-slate-200">{label}</span>
          {!checked && <Badge tone="danger">OFF</Badge>}
        </span>
        <span className="mt-1 block text-xs leading-relaxed text-slate-400">{description}</span>
        {!checked && (
          <span className="mt-1.5 block text-xs leading-relaxed text-rose-300">
            → {attack} が成立する
          </span>
        )}
      </span>
    </label>
  );
}

/** キーと値を並べる表。値は等幅で、長ければ折り返す。 */
export function DataList({ data }: { data: Record<string, string> }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return null;
  return (
    <dl className="mt-3 grid gap-x-4 gap-y-1.5 sm:grid-cols-[minmax(0,14rem)_minmax(0,1fr)]">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-xs text-slate-500">{key}</dt>
          <dd className="break-all font-mono text-xs text-slate-300">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** 等幅の枠付きテキスト（平文・暗号文の表示用）。 */
export function Mono({ tone = "muted", children }: { tone?: Tone; children: ReactNode }) {
  const border =
    tone === "danger"
      ? "border-rose-900/60 bg-rose-950/20 text-rose-200"
      : tone === "ok"
        ? "border-emerald-900/60 bg-emerald-950/20 text-emerald-200"
        : "border-slate-800 bg-slate-950/60 text-slate-300";
  return (
    <pre
      className={`mt-2 overflow-x-auto rounded-md border px-3 py-2 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all ${border}`}
    >
      {children}
    </pre>
  );
}

/** 通信の向きを示す矢印。 */
export function Arrow({ from, to }: { from: string; to: string }) {
  if (from === to) {
    return <span className="font-mono text-xs text-slate-500">{from} 内部処理</span>;
  }
  return (
    <span className="font-mono text-xs text-slate-400">
      {from} <span className="text-slate-600">──▶</span> {to}
    </span>
  );
}
