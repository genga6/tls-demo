import { TlsDemo } from "./components/TlsDemo";
import { IconLock } from "./components/icons";
import { More } from "./components/ui";

export function App() {
  return (
    <div className="mx-auto max-w-6xl px-3 py-5 sm:px-5 sm:py-7">
      <header className="mb-3 flex flex-wrap items-end justify-between gap-x-4 gap-y-2">
        <div>
          <h1 className="flex items-center gap-1.5 text-xl font-bold tracking-tight sm:text-2xl">
            <span className="text-accent">
              <IconLock size={22} />
            </span>
            TLS 1.3 の中身を動かして見る
          </h1>
          <p className="mt-1 text-xs text-ink-soft sm:text-sm">
            https で銀行サイトに繋いだ瞬間の十数手を再生し、守りを 1
            つ外すと攻撃が本当に通る。すべてこのタブの中で計算している。
          </p>
        </div>

        <div className="text-[11px] leading-relaxed text-ink-faint">
          <More summary="このデモの前提" popover>
            <div className="space-y-1.5 rounded-xl border-[1.5px] border-line bg-card p-3 shadow-lg">
              <p>
                鍵・ハッシュ・署名・暗号文はすべて実際に計算した値。ECDHE P-256 / ECDSA P-256 /
                AES-128-GCM / HKDF はブラウザの Web Crypto をそのまま使い、鍵導出と署名対象は RFC
                8446 の定義どおり。実在のサーバーには接続せず、鍵はこのタブから外に出ない。
              </p>
              <p>
                ただし教材専用。攻撃の成立条件を見やすくするため、ハンドシェイクは TLS
                のバイナリではなく JSON、証明書も X.509 DER ではない。本番の TLS
                実装として使ってはならない。
              </p>
            </div>
          </More>
        </div>
      </header>

      <main>
        <TlsDemo />
      </main>
    </div>
  );
}
