import { TlsDemo, TlsTree } from "./components/TlsDemo";

export function App() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-4xl px-5 py-10">
        <header className="mb-8">
          <h1 className="text-3xl font-bold tracking-tight">TLS ハンドシェイクと HTTPS のデモ</h1>
          <p className="mt-3 max-w-2xl text-slate-400">
            ブラウザに繋いだ瞬間に何が起きているのかを、モックサーバーと Web Crypto
            で最初から最後まで再現する。証明書チェーン・ホスト名照合・CertificateVerify・Finished・前方秘匿性・
            レコード暗号化の各防御をトグルで OFF にすると、対応する攻撃が成立する様子を確認できる。
          </p>

          <div className="mt-5">
            <TlsTree />
          </div>

          <p className="mt-4 max-w-2xl text-sm leading-relaxed text-slate-500">
            HTTPS はこの順で動く: TLS ハンドシェイク → 証明書の検証 → 鍵交換 → 共通鍵で暗号化 →
            その上で HTTP 通信。鍵導出 (HKDF-Expand-Label / Derive-Secret)、鍵交換 (ECDHE P-256)、
            署名 (ECDSA P-256)、AEAD (AES-128-GCM) はいずれも RFC 8446 の定義どおりに実装してあり、
            実在のサーバーには接続しない。鍵はこのタブから外に出ない。
          </p>
        </header>

        <main>
          <TlsDemo />
        </main>

        <footer className="mt-12 border-t border-slate-800 pt-6 text-sm leading-relaxed text-slate-500">
          このモックサーバーは教材専用であり、本番の TLS 実装として使ってはならない。
          攻撃の成立条件を見やすくすることを優先しており、ハンドシェイクメッセージのバイト表現や
          証明書の符号化 (X.509 DER) は本物とは異なる。
        </footer>
      </div>
    </div>
  );
}
