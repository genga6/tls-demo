/**
 * 攻撃スロット。
 *
 * 8 つの攻撃を、いまの守りの設定で実際に走らせた結果を枠で並べる。文章を 8 つ積み上げると
 * 読めなくなるので、**選んだ 1 つだけ**を下の欄に出す。守りを外すと、そのとき通った攻撃が
 * 自動で選ばれる。
 *
 * どの攻撃も対応する守り 1 つだけで結果が決まる（`attacks.ts` の `isolate`）。
 * だから「外した → 通った」の因果が 1 対 1 で読める。
 */

import { useEffect, useRef, useState } from "react";
import { type AttackId, type AttackResult, lootPreview } from "../lib/attacks";
import { ATTACK_COPY, DEFENSE_COPY } from "../lib/plain";
import { DEFENSE_INFO, type DefenseKey, type Defenses, PHASE_LABELS } from "../lib/types";
import { IconMask, IconShield, IconShieldBroken } from "./icons";
import { Button, More, Panel, Pill, Wire } from "./ui";

export function AttackBoard({
  attacks,
  defenses,
  onToggleDefense,
}: {
  attacks: AttackResult[];
  defenses: Defenses;
  onToggleDefense: (key: DefenseKey, next: boolean) => void;
}) {
  const [selected, setSelected] = useState<AttackId>("mitm");
  const previouslyOpen = useRef<Set<AttackId>>(new Set());

  // 守りを外した結果として新しく通った攻撃があれば、それを選んで見せる。
  useEffect(() => {
    const open = new Set(attacks.filter((a) => a.succeeded).map((a) => a.id));
    const fresh = [...open].find((id) => !previouslyOpen.current.has(id));
    previouslyOpen.current = open;
    if (fresh) setSelected(fresh);
  }, [attacks]);

  const current = attacks.find((a) => a.id === selected);

  return (
    <Panel title="攻撃" hint="8 通りを同時に実行中">
      <ul className="grid grid-cols-2 gap-1.5 sm:grid-cols-4">
        {attacks.map((attack) => (
          <li key={attack.id}>
            <Slot
              attack={attack}
              selected={attack.id === selected}
              onSelect={() => setSelected(attack.id)}
            />
          </li>
        ))}
      </ul>

      {current && (
        <Detail
          key={current.id}
          attack={current}
          defenseOn={defenses[current.defense]}
          onToggleDefense={onToggleDefense}
        />
      )}
    </Panel>
  );
}

/** 攻撃 1 つの枠。通ったかどうかだけが分かる大きさにする。 */
function Slot({
  attack,
  selected,
  onSelect,
}: {
  attack: AttackResult;
  selected: boolean;
  onSelect: () => void;
}) {
  const open = attack.succeeded;

  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={`flex w-full items-start gap-1.5 rounded-xl border-[1.5px] px-2 py-2 text-left transition ${
        open
          ? `alarm-flash border-alarm bg-alarm-soft ${selected ? "outline-2 outline-offset-1 outline-alarm" : ""}`
          : selected
            ? "border-accent bg-accent-soft"
            : "border-line-soft bg-card hover:border-line"
      }`}
    >
      <span className={`mt-px shrink-0 ${open ? "text-alarm" : "text-safe"}`}>
        {open ? <IconMask size={16} /> : <IconShield size={16} />}
      </span>
      <span className="min-w-0">
        <span className="block text-[11px] leading-snug font-bold break-words">
          {ATTACK_COPY[attack.id].short}
        </span>
        <span
          className={`mt-0.5 block text-[10px] font-bold ${open ? "text-alarm" : "text-ink-faint"}`}
        >
          {open ? "通った" : "防げた"}
        </span>
      </span>
    </button>
  );
}

/** 選んだ 1 つの中身。ここだけが文章を持つ。 */
function Detail({
  attack,
  defenseOn,
  onToggleDefense,
}: {
  attack: AttackResult;
  defenseOn: boolean;
  onToggleDefense: (key: DefenseKey, next: boolean) => void;
}) {
  const copy = ATTACK_COPY[attack.id];
  const defense = DEFENSE_COPY[attack.defense];

  return (
    <div
      className={`rise-in mt-3 rounded-xl border-[1.5px] p-3 ${
        attack.succeeded ? "border-alarm/50 bg-alarm-soft" : "border-line-soft bg-paper"
      }`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-bold">{copy.short}</h3>
        {attack.succeeded ? <Pill tone="alarm">通った</Pill> : <Pill tone="safe">防げた</Pill>}
        <span className="text-[11px] text-ink-faint">{PHASE_LABELS[attack.phase]}</span>
      </div>

      <p className="mt-1.5 text-xs leading-relaxed text-ink-soft">{copy.story}</p>

      <div className="mt-2.5 flex flex-wrap items-center gap-2">
        <span
          className={`flex items-center gap-1.5 rounded-lg border-[1.5px] bg-card px-2 py-1 text-[11px] font-bold ${
            defenseOn ? "border-safe/40 text-safe" : "border-alarm/40 text-alarm"
          }`}
        >
          {defenseOn ? <IconShield size={14} /> : <IconShieldBroken size={14} />}
          {defense.short}
          <span className="font-normal text-ink-faint">{defenseOn ? "ON" : "OFF"}</span>
        </span>

        {defenseOn ? (
          <Button tone="alarm" onClick={() => onToggleDefense(attack.defense, false)}>
            この守りを外して試す
          </Button>
        ) : (
          <Button tone="accent" onClick={() => onToggleDefense(attack.defense, true)}>
            守りを戻す
          </Button>
        )}
      </div>

      <p
        className={`mt-2.5 text-xs leading-relaxed ${
          attack.succeeded ? "font-semibold text-alarm" : "text-safe"
        }`}
      >
        {attack.outcome}
      </p>

      {attack.succeeded && attack.loot && (
        <div className="mt-2">
          <p className="text-[10px] font-bold tracking-wider text-alarm uppercase">
            攻撃者が手にしたもの
          </p>
          <div className="mt-1">
            <Wire tone="alarm">{lootPreview(attack.loot)}</Wire>
          </div>
        </div>
      )}

      <div className="mt-2.5 border-t border-line-soft pt-2">
        <More summary="TLS での呼び方">
          <p className="text-[11px] font-semibold">{attack.name}</p>
          <p className="mt-0.5 text-[11px] leading-relaxed text-ink-soft">{attack.premise}</p>
          <p className="mt-1 font-mono text-[11px] text-ink-faint">
            決め手: {DEFENSE_INFO[attack.defense].label}
          </p>
        </More>
      </div>
    </div>
  );
}
