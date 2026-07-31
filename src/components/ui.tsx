/** 盤面で使い回す小さな部品。見た目の定義は index.css の .panel / .btn / .pill に置いてある。 */

import type { ReactNode } from "react";

type Tone = "safe" | "open" | "alarm" | "muted" | "accent";

const PILL_TONES: Record<Tone, string> = {
  safe: "bg-safe-soft text-safe border-safe/40",
  open: "bg-open-soft text-open border-open/40",
  alarm: "bg-alarm-soft text-alarm border-alarm/40",
  muted: "bg-paper text-ink-soft border-line",
  accent: "bg-accent-soft text-accent-deep border-accent/40",
};

/** 状態を一目で出す札。 */
export function Pill({ tone = "muted", children }: { tone?: Tone; children: ReactNode }) {
  return <span className={`pill ${PILL_TONES[tone]}`}>{children}</span>;
}

/** 盤面に置く板。 */
export function Panel({
  title,
  hint,
  actions,
  children,
  className = "",
}: {
  title?: string;
  hint?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  // min-w-0 が要る。中に折り返せない等幅の 1 行があるため、これがないと
  // グリッドの列が中身の幅まで広がり、画面ごと横スクロールしてしまう。
  return (
    <section className={`panel flex min-w-0 flex-col ${className}`}>
      {title && (
        <header className="flex flex-wrap items-center justify-between gap-2 border-b border-line-soft px-3.5 py-2.5">
          <div className="flex min-w-0 items-baseline gap-2">
            <h2 className="text-sm font-bold tracking-wide">{title}</h2>
            {hint && <p className="text-xs text-ink-faint">{hint}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className="flex flex-1 flex-col p-3.5">{children}</div>
    </section>
  );
}

/** 押せるもの。 */
export function Button({
  onClick,
  tone = "neutral",
  disabled,
  label,
  title,
  children,
}: {
  onClick: () => void;
  tone?: "neutral" | "accent" | "alarm";
  disabled?: boolean;
  /** アイコンだけのボタンに付ける読み上げ用の名前。 */
  label?: string;
  title?: string;
  children: ReactNode;
}) {
  const toneClass = { neutral: "", accent: "btn-accent", alarm: "btn-alarm" }[tone];
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={label}
      title={title ?? label}
      className={`btn ${toneClass}`}
    >
      {children}
    </button>
  );
}

/**
 * ON / OFF のスイッチ。
 *
 * checkbox のまま見た目だけ差し替えている（キーボード操作と読み上げをそのまま活かすため）。
 */
export function Switch({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  /** 読み上げ用の名前。画面には出さない。 */
  label: string;
}) {
  return (
    <span className="relative inline-flex size-9 shrink-0 items-center justify-center">
      <input
        type="checkbox"
        aria-label={label}
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="peer absolute inset-0 cursor-pointer appearance-none rounded-lg opacity-0"
      />
      <span
        aria-hidden
        className={`pointer-events-none h-5 w-9 rounded-full border-[1.5px] transition-colors peer-focus-visible:outline-2 peer-focus-visible:outline-accent peer-focus-visible:outline-offset-2 ${
          checked ? "border-safe bg-safe" : "border-line bg-paper"
        }`}
      >
        <span
          className={`absolute top-1/2 size-3.5 -translate-y-1/2 rounded-full bg-card shadow-sm transition-all ${
            checked ? "left-[1.15rem]" : "left-[0.15rem]"
          }`}
        />
      </span>
    </span>
  );
}

/** 等幅の 1 行。平文や 16 進をそのまま見せる。 */
export function Wire({
  tone = "muted",
  clamp = false,
  children,
}: {
  tone?: "muted" | "open" | "alarm" | "safe";
  /** 1 行に収めて溢れは省略する（盤面用）。 */
  clamp?: boolean;
  children: ReactNode;
}) {
  const tones = {
    muted: "border-line-soft bg-paper text-ink-soft",
    open: "border-open/30 bg-open-soft text-open",
    alarm: "border-alarm/30 bg-alarm-soft text-alarm",
    safe: "border-safe/30 bg-safe-soft text-safe",
  };
  return (
    <pre
      className={`rounded-lg border px-2.5 py-1.5 font-mono text-[11px] leading-relaxed ${tones[tone]} ${
        clamp ? "overflow-hidden text-ellipsis whitespace-nowrap" : "whitespace-pre-wrap break-all"
      }`}
    >
      {children}
    </pre>
  );
}

/** キーと値を並べる表。実際に計算された値の表示用。 */
export function DataList({ data }: { data: Record<string, string> }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return null;
  return (
    <dl className="mt-2 grid gap-x-3 gap-y-1 sm:grid-cols-[minmax(0,13rem)_minmax(0,1fr)]">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-[11px] text-ink-faint">{key}</dt>
          <dd className="mb-1 font-mono text-[11px] break-all text-ink-soft sm:mb-0">{value}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * 開くと補足が出る小さな折りたたみ。閉じているときは 1 行しか占めない。
 *
 * 見た目を小さなボタンにしてあるのは、ただの文字だと押せることに気づかれないため。
 */
export function More({
  summary,
  children,
  popover = false,
}: {
  summary: string;
  children: ReactNode;
  /**
   * 開いた中身を浮かせる。
   *
   * 並びの中に置いた折りたたみは、開くと周りを押しのけてボタン自体が動いてしまう。
   * 位置を動かしたくない場所ではこちらを使う。
   */
  popover?: boolean;
}) {
  return (
    <details className={`group ${popover ? "relative" : ""}`}>
      <summary className="inline-flex list-none items-center gap-1 rounded-lg border-[1.5px] border-line-soft bg-paper px-2 py-1 text-[11px] font-bold text-accent-deep transition-colors hover:border-accent/50 hover:text-accent [&::-webkit-details-marker]:hidden">
        <svg
          viewBox="0 0 24 24"
          width="11"
          height="11"
          fill="none"
          stroke="currentColor"
          strokeWidth={3}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
          className="transition-transform group-open:rotate-90"
        >
          <path d="M9 5l7 7-7 7" />
        </svg>
        {summary}
      </summary>
      <div
        className={
          popover ? "absolute right-0 z-20 mt-1.5 w-[min(24rem,calc(100vw-2rem))]" : "mt-1.5"
        }
      >
        {children}
      </div>
    </details>
  );
}
