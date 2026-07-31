/**
 * 守りのラック。
 *
 * TLS が実際にやっている確認を 7 つに分け、1 つずつ外せるようにしてある。
 * 盤面の隣に置いてあるので、外した瞬間に手順が変わり、攻撃スロットの結果が変わる。
 *
 * 説明はスイッチの脇に 1 行だけ出し、残りはラックの下に 1 つだけ折りたたんで置く。
 */

import { useMemo } from "react";
import { DEFENSE_COPY } from "../lib/plain";
import {
  ALL_DEFENSES_ON,
  DEFENSE_INFO,
  DEFENSE_KEYS,
  type DefenseKey,
  type Defenses,
  PHASE_LABELS,
  type Phase,
} from "../lib/types";
import { IconShield, IconShieldBroken } from "./icons";
import { Button, More, Panel, Pill, Switch } from "./ui";

const PHASE_ORDER: Phase[] = ["handshake", "certificate", "key-exchange", "encryption", "https"];

export function DefenseRack({
  defenses,
  onChange,
}: {
  defenses: Defenses;
  onChange: (next: Defenses) => void;
}) {
  const byPhase = useMemo(() => {
    const map = new Map<Phase, DefenseKey[]>();
    for (const key of DEFENSE_KEYS) {
      const phase = DEFENSE_INFO[key].phase;
      map.set(phase, [...(map.get(phase) ?? []), key]);
    }
    return map;
  }, []);

  const onCount = DEFENSE_KEYS.filter((key) => defenses[key]).length;

  return (
    <Panel
      title="守り"
      hint="外すと攻撃が 1 つ通る"
      actions={
        <Button
          onClick={() => onChange(ALL_DEFENSES_ON)}
          disabled={onCount === DEFENSE_KEYS.length}
        >
          全部 ON
        </Button>
      }
    >
      <div className="space-y-2">
        {PHASE_ORDER.map((phase) => {
          const keys = byPhase.get(phase) ?? [];
          return (
            <div key={phase}>
              <p className="text-[10px] font-bold tracking-wider text-ink-faint uppercase">
                {PHASE_LABELS[phase]}
              </p>

              {keys.length > 0 ? (
                <ul className="mt-1 space-y-1">
                  {keys.map((key) => (
                    <li key={key}>
                      <Row
                        defenseKey={key}
                        checked={defenses[key]}
                        onChange={(next) => onChange({ ...defenses, [key]: next })}
                      />
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 rounded-lg border-[1.5px] border-dashed border-line-soft px-2.5 py-1 text-[11px] text-ink-faint">
                  固有の守りはない（下の 4 層がそのまま決める）
                </p>
              )}
            </div>
          );
        })}
      </div>

      <div className="mt-3 border-t border-line-soft pt-2.5">
        <More summary="それぞれ何を確かめているのか">
          <dl className="space-y-2">
            {DEFENSE_KEYS.map((key) => (
              <div key={key}>
                <dt className="font-mono text-[11px] font-semibold">{DEFENSE_INFO[key].label}</dt>
                <dd className="text-[11px] leading-relaxed text-ink-soft">
                  {DEFENSE_COPY[key].analogy}
                  <span className="mt-0.5 block text-ink-faint">{DEFENSE_INFO[key].what}</span>
                </dd>
              </div>
            ))}
          </dl>
        </More>
      </div>
    </Panel>
  );
}

function Row({
  defenseKey,
  checked,
  onChange,
}: {
  defenseKey: DefenseKey;
  checked: boolean;
  onChange: (next: boolean) => void;
}) {
  const copy = DEFENSE_COPY[defenseKey];

  return (
    <div
      className={`rounded-xl border-[1.5px] px-2 py-1.5 transition ${
        checked ? "border-line-soft bg-card" : "border-alarm/50 bg-alarm-soft"
      }`}
    >
      <div className="flex items-center gap-2">
        <span className={checked ? "text-safe" : "text-alarm"}>
          {checked ? <IconShield size={18} /> : <IconShieldBroken size={18} />}
        </span>
        <span className="min-w-0 flex-1 truncate text-xs font-bold">{copy.short}</span>
        <Switch checked={checked} onChange={onChange} label={DEFENSE_INFO[defenseKey].label} />
      </div>

      {!checked && (
        <p className="mt-1 flex items-start gap-1.5 text-[11px] leading-relaxed text-alarm">
          <Pill tone="alarm">OFF</Pill>
          <span className="min-w-0">{copy.ifOff}</span>
        </p>
      )}
    </div>
  );
}
