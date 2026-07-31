/**
 * デモ全体で共有する型。
 *
 * TLS を 5 つの層に分けて理解する:
 *
 *   TLS
 *   ├── Handshake      接続時に何をしているか
 *   ├── Certificate    サーバーが本物か確認
 *   ├── Key Exchange   共通鍵を安全に共有
 *   ├── Encryption     以降の通信を暗号化
 *   └── HTTPS          HTTP を TLS で保護したもの
 *
 * それぞれの層に「これを外すと何が起きるか」を示す防御トグルを割り当ててある。
 */

/** ツリーのどの層の話かを示す区分。フロー可視化のグルーピングにも使う。 */
export type Phase = "handshake" | "certificate" | "key-exchange" | "encryption" | "https";

export const PHASE_LABELS: Record<Phase, string> = {
  handshake: "Handshake",
  certificate: "Certificate",
  "key-exchange": "Key Exchange",
  encryption: "Encryption",
  https: "HTTPS",
};

export const PHASE_SUMMARIES: Record<Phase, string> = {
  handshake: "接続時に何をしているか",
  certificate: "サーバーが本物か確認",
  "key-exchange": "共通鍵を安全に共有",
  encryption: "以降の通信を暗号化",
  https: "HTTP を TLS で保護したもの",
};

// ---------------------------------------------------------------------------
// 防御トグル
// ---------------------------------------------------------------------------

/**
 * 各防御の ON/OFF。すべて ON が現実の TLS 1.3 の姿で、
 * 1 つ OFF にすると対応する攻撃がちょうど 1 つ成立する。
 */
export interface Defenses {
  /** 証明書チェーンを信頼済みルート CA まで辿って署名を検証する。 */
  certificateChain: boolean;
  /** 証明書の SAN が接続先ホスト名と一致するか照合する。 */
  hostnameCheck: boolean;
  /** 証明書の有効期間内か、失効していないかを確認する。 */
  validityCheck: boolean;
  /** CertificateVerify で、相手が証明書の秘密鍵を実際に持つことを確認する。 */
  certificateVerify: boolean;
  /** Finished でハンドシェイク全文のハッシュを突き合わせる。 */
  finishedVerify: boolean;
  /** 鍵交換に使い捨て鍵（ECDHE）を使い、前方秘匿性を確保する。 */
  forwardSecrecy: boolean;
  /** レコード層を AEAD で暗号化する（OFF なら実質ただの HTTP）。 */
  recordEncryption: boolean;
}

export const DEFENSE_KEYS = [
  "certificateChain",
  "hostnameCheck",
  "validityCheck",
  "certificateVerify",
  "finishedVerify",
  "forwardSecrecy",
  "recordEncryption",
] as const;

export type DefenseKey = (typeof DEFENSE_KEYS)[number];

/** すべての防御が有効な、正しい TLS 1.3 の設定。 */
export const ALL_DEFENSES_ON: Defenses = {
  certificateChain: true,
  hostnameCheck: true,
  validityCheck: true,
  certificateVerify: true,
  finishedVerify: true,
  forwardSecrecy: true,
  recordEncryption: true,
};

export interface DefenseInfo {
  key: DefenseKey;
  /** ツリーのどの層に属する防御か。 */
  phase: Phase;
  label: string;
  /** 何をしているか。 */
  what: string;
  /** OFF にすると成立する攻撃の名前。 */
  attack: string;
}

export const DEFENSE_INFO: Record<DefenseKey, DefenseInfo> = {
  certificateChain: {
    key: "certificateChain",
    phase: "certificate",
    label: "証明書チェーン検証",
    what: "受け取った証明書を中間 CA・ルート CA へ辿り、各段の署名と信頼ストアへの到達を確認する。",
    attack: "中間者攻撃（偽 CA の証明書を受理）",
  },
  hostnameCheck: {
    key: "hostnameCheck",
    phase: "certificate",
    label: "ホスト名（SAN）照合",
    what: "証明書の subjectAltName に接続先ホスト名が含まれるか照合する。",
    attack: "別ドメインの正規証明書による成りすまし",
  },
  validityCheck: {
    key: "validityCheck",
    phase: "certificate",
    label: "有効期限・失効確認",
    what: "notBefore / notAfter の範囲内であり、CA の失効リストに載っていないことを確認する。",
    attack: "期限切れ・失効済み証明書の受理",
  },
  certificateVerify: {
    key: "certificateVerify",
    phase: "certificate",
    label: "CertificateVerify 署名",
    what: "サーバーがハンドシェイク全文に署名し、証明書に対応する秘密鍵を持つことを証明する。",
    attack: "証明書コピペ（秘密鍵を持たない偽サーバー）",
  },
  finishedVerify: {
    key: "finishedVerify",
    phase: "handshake",
    label: "Finished / transcript hash 照合",
    what: "ここまでのハンドシェイク全文のハッシュに MAC を付けて交換し、改ざんがないことを確認する。",
    attack: "ダウングレード攻撃（暗号スイートの格下げ）",
  },
  forwardSecrecy: {
    key: "forwardSecrecy",
    phase: "key-exchange",
    label: "前方秘匿性（ECDHE）",
    what: "鍵交換に接続ごとの使い捨て鍵を使い、長期鍵が漏れても過去の通信を守る。",
    attack: "長期鍵の漏洩による過去通信の遡及復号",
  },
  recordEncryption: {
    key: "recordEncryption",
    phase: "encryption",
    label: "レコード層の暗号化（AEAD）",
    what: "以降の通信を AES-128-GCM で暗号化し、同時に改ざん検知の認証タグを付ける。",
    attack: "盗聴・改ざん（保護のない HTTP と同じ状態）",
  },
};

// ---------------------------------------------------------------------------
// フロー可視化
// ---------------------------------------------------------------------------

/** 通信路に登場する主体。 */
export type Actor = "client" | "server" | "attacker" | "ca";

export const ACTOR_LABELS: Record<Actor, string> = {
  client: "クライアント",
  server: "サーバー",
  attacker: "攻撃者",
  ca: "認証局 (CA)",
};

/** ステップの結果。UI のバッジ色に対応する。 */
export type StepStatus = "ok" | "skipped" | "failed" | "danger";

/**
 * ステップの識別子。
 *
 * 画面側がやさしい日本語の解説を引き当てるための鍵。表示文言を変えても
 * 対応関係が崩れないよう、タイトルではなくこの ID で引く。
 */
export type StepId =
  | "client-hello"
  | "hello-tampered"
  | "server-hello"
  | "ecdhe"
  | "key-schedule"
  | "transcript-mismatch"
  | "flight-locked"
  | "certificate"
  | "chain-verify"
  | "cert-verify"
  | "finished-locked"
  | "server-finished"
  | "client-finished"
  | "app-keys"
  | "http-request"
  | "http-response";

/**
 * ハンドシェイクの 1 ステップ。
 *
 * 通信（from → to）と、その場での検証・計算の両方をこの型で表す。
 * `from === to` なら「その主体が内部で行った処理」を意味する。
 */
export interface FlowStep {
  /** 表示順に振られる 1 始まりの番号。 */
  index: number;
  /** どの手順かを示す識別子。画面側の解説文と対応する。 */
  id: StepId;
  phase: Phase;
  from: Actor;
  to: Actor;
  /** その時点で通信路が暗号化されているか。平文区間の可視化に使う。 */
  protection: "plaintext" | "handshake-encrypted" | "application-encrypted" | "internal";
  title: string;
  detail: string;
  status: StepStatus;
  /** 実際に計算された値（鍵・ハッシュ・ハンドシェイクの中身）。 */
  data?: Record<string, string>;
}

/** ハンドシェイク 1 回分の結果。 */
export interface HandshakeResult {
  steps: FlowStep[];
  /** ハンドシェイクが最後まで通ったか。 */
  established: boolean;
  /** 中断した場合の理由。 */
  abortReason?: string;
  /** 交渉された暗号スイート。 */
  cipherSuite: string;
  /** 鍵交換方式の表示名。 */
  keyExchange: string;
  /** 合意した鍵素材（表示用の 16 進文字列）。 */
  secrets: Record<string, string>;
}
