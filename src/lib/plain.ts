/**
 * 画面に出す言葉。
 *
 * 用語は TLS のものをそのまま使う（ClientHello は ClientHello と呼ぶ）。読みやすさは
 * 言葉を easy にすることではなく、**一度に出す量**で作る。だから 1 項目につき
 *
 *   title … TLS での呼び名（見出し）
 *   line  … 何が起きたかを 1 文（常に見える）
 *   more  … もう少し詳しい話（開いたときだけ）
 *
 * の 3 段に分け、盤面には title と line しか出さない。
 */

import type { AttackId } from "./attacks";
import type { DefenseKey, Phase, StepId } from "./types";

// ---------------------------------------------------------------------------
// 5 つの層
// ---------------------------------------------------------------------------

/** 進行トラックに出す、層ごとの短い添え書き。呼び名は PHASE_LABELS をそのまま使う。 */
export const PHASE_NOTE: Record<Phase, string> = {
  handshake: "話し方を決める",
  certificate: "相手を確かめる",
  "key-exchange": "共通鍵を作る",
  encryption: "封をする",
  https: "HTTP を運ぶ",
};

// ---------------------------------------------------------------------------
// 各手順
// ---------------------------------------------------------------------------

export interface StepCopy {
  /** TLS でのメッセージ名・処理名。 */
  title: string;
  /** 何が起きたかを 1 文で。常に見える唯一の説明。 */
  line: string;
  /** 開いたときだけ出す補足。 */
  more: string;
  /** 対応する守りを外して省略された場合の 1 文。 */
  whenSkipped?: string;
  /** 経路上の記録（盗聴者ビュー）のどの行に対応するか。 */
  wiretapLabel?: string;
}

export const STEP_COPY: Record<StepId, StepCopy> = {
  "client-hello": {
    title: "ClientHello",
    line: "使える暗号スイートの一覧と、鍵交換用の公開鍵をまとめて送る。",
    more: "TLS 1.3 が 1 往復でハンドシェイクを終えられるのは、最初の 1 通に鍵交換の材料 (key_share) を相乗りさせているから。ここはまだ鍵がないので平文で流れる。",
    wiretapLabel: "ClientHello",
  },
  "hello-tampered": {
    title: "ClientHello の改ざん",
    line: "平文なので、経路上の攻撃者が暗号スイートの一覧を削れる。",
    more: "強いスイートを消してしまえば、サーバーは残った弱いものを選ぶしかない。書き換えそのものは成功する。TLS 1.3 は改ざんを防ぐのではなく、必ず後で破綻するようにしてある。",
  },
  "server-hello": {
    title: "ServerHello",
    line: "サーバーが暗号スイートを 1 つ選び、自分の公開鍵を返す。平文はここまで。",
    more: "この 2 通だけで両者は共通鍵を計算する材料をそろえる。経路に出たのは公開鍵 2 つだけで、そこから共有秘密を求めるのは離散対数問題そのもの。",
    wiretapLabel: "ServerHello",
  },
  ecdhe: {
    title: "ECDHE — 共有秘密",
    line: "相手の公開点と自分の秘密鍵から、両者が同じ値 abG にたどりつく。",
    more: "aB = bA = abG。やり取りを全部見られていても共通鍵は作れる。ただし ECDHE が保証するのは「誰かと安全な通信路ができた」ことだけで、その誰かが銀行かどうかは何も言わない。",
  },
  "key-schedule": {
    title: "HKDF — 鍵スケジュール",
    line: "共有秘密をそのまま鍵にせず、用途ごとのラベルで別々の鍵へ枝分かれさせる。",
    more: "Early → Handshake → Master と段を踏み、各段で「ここまでのハンドシェイク全文のハッシュ」を混ぜ込む。用途ごとにラベルが違うので、1 本漏れても他は導出できない。",
  },
  "transcript-mismatch": {
    title: "transcript hash の食い違い",
    line: "両者の会話の記録が違うので、導出された鍵が別物になった。",
    more: "鍵導出の入力に transcript hash が入っているため、1 バイトの書き換えで鍵が変わる。改ざんを検出するより前に、通信そのものが成立しなくなる。",
  },
  "flight-locked": {
    title: "復号できない",
    line: "鍵が一致しないので封を開けられない。ブラウザは接続を中止する。",
    more: "実際のブラウザで出る「この接続は安全ではありません」は、この行き止まりの画面。通信を続けずに止めるところまでが TLS の仕事。",
  },
  certificate: {
    title: "Certificate",
    line: "サーバーが自分の証明書と中間 CA の証明書を送る。",
    more: "ルート CA の証明書は送らない。クライアントが信頼ストアに持っているはずのものだから。TLS 1.3 ではこの証明書もすでに handshake 鍵で暗号化された中を通る。",
    wiretapLabel: "サーバーの証明書フライト",
  },
  "chain-verify": {
    title: "証明書の検証",
    line: "署名を発行元へたどって信頼ストアに届くか、SAN と有効期限も確かめる。",
    more: "鍵交換が成立したことは相手が本物であることを意味しない。中間者とも鍵交換は問題なく成功する。相手が誰かは、信頼ストアという外部の根拠だけが教えてくれる。",
  },
  "cert-verify": {
    title: "CertificateVerify",
    line: "ハンドシェイク全文への署名で、証明書の秘密鍵を持つ本人かを確かめる。",
    more: "証明書は公開情報で、正規サーバーに繋げば誰でも取得できる。だから提示だけでは何も証明しない。公開鍵と対になる秘密鍵で署名できることが、持ち主本人の証拠になる。",
    whenSkipped: "署名を確かめないので、証明書を拾ってきて提示しただけの相手でも通る。",
  },
  "finished-locked": {
    title: "復号できない",
    line: "締めくくりの Finished も開けられない。ここで終わり。",
    more: "ハンドシェイク鍵が食い違ったままなので、この先どのレコードも復号できない。",
  },
  "server-finished": {
    title: "Finished（サーバー）",
    line: "ここまでの全メッセージのハッシュに MAC を付けて送り、改ざんの有無を照合する。",
    more: "鍵交換に成功したことと、見ていたやり取りの中身が同一であることを 1 通で同時に証明する。ダウングレード攻撃が TLS 1.3 で通らないのはこの仕組みのため。",
    whenSkipped: "全文を突き合わせないので、経路上でスイートを落とされていても気づけない。",
  },
  "client-finished": {
    title: "Finished（クライアント）",
    line: "同じ照合を逆向きにも行い、双方向で改ざんがないことを確かめる。",
    more: "これでハンドシェイクは完了。ここから先は application 鍵での通信になる。",
  },
  "app-keys": {
    title: "application 鍵へ切り替え",
    line: "Master Secret から、方向ごとに別のアプリ用 AEAD 鍵と IV を導出する。",
    more: "レコードごとの連番を nonce に混ぜるので、同じ nonce が二度使われることが構造的に起こらない。handshake 鍵はここで役目を終える。",
  },
  "http-request": {
    title: "HTTP リクエスト",
    line: "ふつうの HTTP のバイト列を、そのままレコード層に流し込む。",
    more: "HTTPS は独立したプロトコルではない。やっているのはこれだけ。Cookie も Authorization も AEAD の中に入り、経路に漏れるのは長さと送信タイミングだけになる。",
    wiretapLabel: "HTTP リクエスト",
  },
  "http-response": {
    title: "HTTP レスポンス",
    line: "復号と同時に認証タグを検証する。1 ビットでも触られていれば開かない。",
    more: "「開けられた」こと自体が「誰も改ざんしていない」の証明になっている。AEAD が暗号化と改ざん検知を同時にやっているため。",
    wiretapLabel: "HTTP レスポンス",
  },
};

// ---------------------------------------------------------------------------
// 守り（防御トグル）
// ---------------------------------------------------------------------------

export interface DefenseCopy {
  /** ラックに出す短い名前。 */
  short: string;
  /** 身近なことへの言い換え。開いたときだけ出す。 */
  analogy: string;
  /** 外すと何が起きるか。OFF のときだけ出す。 */
  ifOff: string;
}

export const DEFENSE_COPY: Record<DefenseKey, DefenseCopy> = {
  certificateChain: {
    short: "チェーン検証",
    analogy: "その社員証、どこの会社が発行したもの？ 知らない会社のものは信じない。",
    ifOff: "誰でも自分で CA を名乗れる。偽 CA の証明書が通る。",
  },
  hostnameCheck: {
    short: "ホスト名 (SAN) 照合",
    analogy: "身分証が本物でも、書かれた名前が違えば別人。",
    ifOff: "攻撃者が自分の正規証明書で他人になりすませる。",
  },
  validityCheck: {
    short: "有効期限・失効",
    analogy: "期限切れの身分証、紛失届が出ている身分証は受け取らない。",
    ifOff: "漏れた鍵を無効化する手段が働かなくなる。",
  },
  certificateVerify: {
    short: "CertificateVerify",
    analogy: "身分証はコピーできる。持ち主だけが書けるサインで本人を確かめる。",
    ifOff: "証明書を拾ってきただけの相手が本物として通る。",
  },
  finishedVerify: {
    short: "Finished 照合",
    analogy: "最後に「さっきこう言ったよね」と互いに読み上げる。",
    ifOff: "ハンドシェイクを書き換えられても気づけない。",
  },
  forwardSecrecy: {
    short: "前方秘匿性 (ECDHE)",
    analogy: "話し終えたら鍵は捨てる。後で金庫を破られても昔の手紙は開かない。",
    ifOff: "録っておいた暗号文が、後から長期鍵で全部読める。",
  },
  recordEncryption: {
    short: "レコード暗号化",
    analogy: "はがきをやめて封筒で出す。",
    ifOff: "Cookie もトークンも経路にいる誰にでも読める。",
  },
};

// ---------------------------------------------------------------------------
// 攻撃
// ---------------------------------------------------------------------------

export interface AttackCopy {
  /** スロットに出す短い名前。 */
  short: string;
  /** 攻撃者が何をするか。選んだときだけ出す。 */
  story: string;
}

export const ATTACK_COPY: Record<AttackId, AttackCopy> = {
  mitm: {
    short: "偽 CA でなりすまし",
    story:
      "攻撃者が自前の CA『Totally Legit CA』を立て、bank.example.com の証明書を自分に発行する。署名は整合していて名前も期限も正しい。唯一の欠陥は、その CA が信頼ストアに入っていないこと。",
  },
  "wrong-hostname": {
    short: "別ドメインの正規証明書",
    story:
      "攻撃者は evil.example.net を本当に所有し、正規 CA から正規の証明書を得ている。チェーンも期限も完璧で、違うのは SAN に書かれた名前だけ。",
  },
  "expired-cert": {
    short: "期限切れ証明書",
    story:
      "30 日前に期限が切れた証明書を提示する。署名もホスト名も正しいので、notBefore / notAfter を見なければ気づけない。",
  },
  "revoked-cert": {
    short: "失効済み証明書",
    story:
      "秘密鍵の漏洩により CA が失効させた証明書。期限内なので、CRL / OCSP を引かない限り有効に見えてしまう。",
  },
  "cert-copy": {
    short: "証明書のコピペ",
    story:
      "正規サーバーの証明書チェーンをそのままコピーして提示する。チェーンも SAN も期限も本物と完全に同一。持っていないのは対応する秘密鍵だけ。",
  },
  downgrade: {
    short: "暗号スイートの格下げ",
    story:
      "平文の ClientHello から強いスイートを削り、サーバーに弱いものを選ばせる。サーバーは「クライアントはこれしか対応していない」と信じるしかない。",
  },
  "retrospective-decrypt": {
    short: "あとから遡って復号",
    story:
      "攻撃者は今日の暗号文をすべて記録しておき、後日サーバーの長期秘密鍵を入手する。そして記録済みの通信を、鍵スケジュールごと再現して復号しようとする。",
  },
  eavesdrop: {
    short: "のぞき見",
    story: "攻撃者は能動的な細工を一切しない。同じ Wi-Fi や経路上の機器からパケットを眺めるだけ。",
  },
};
