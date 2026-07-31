/**
 * ハンドシェイクメッセージと transcript（ここまでのやり取り全文）。
 *
 * TLS ツリーの「Handshake（接続時に何をしているか）」層の骨格。
 *
 * 本物の TLS 1.3 はこれらを厳密なバイナリ構造で送るが、ここでは中身が読める
 * JSON で表現し、`canonicalJson` で決定的なバイト列に落とす。
 * 重要なのは形式ではなく、**送受信した全メッセージのハッシュ（transcript hash）が
 * 鍵導出と Finished の両方に効いている**という構造のほうなので、そこは忠実に再現する。
 */

import { type Bytes, canonicalJson, concat, utf8 } from "./bytes";
import { sha256 } from "./crypto";
import type { Certificate } from "./pki";

/** クライアントが対応を表明する暗号スイート（先頭ほど優先度が高い）。 */
export const CIPHER_SUITES = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256",
  "TLS_RSA_WITH_RC4_128_SHA", // 古い脆弱なスイート。ダウングレード攻撃の標的。
] as const;

export type CipherSuite = (typeof CIPHER_SUITES)[number];

/** このデモが実際に実装している唯一のスイート。 */
export const NEGOTIATED_SUITE: CipherSuite = "TLS_AES_128_GCM_SHA256";

export interface ClientHello {
  type: "ClientHello";
  /** 互換のため TLS 1.2 を名乗る（本物の TLS 1.3 も同じことをしている）。 */
  legacyVersion: "TLS 1.2";
  /** 32 バイトの乱数（hex）。 */
  random: string;
  /** SNI。どのホストに繋ぎたいかを平文で伝える。 */
  serverName: string;
  supportedVersions: string[];
  cipherSuites: string[];
  supportedGroups: string[];
  /** 使い捨て（または静的）鍵の公開点（hex）。TLS 1.3 は Hello に鍵共有を相乗りさせる。 */
  keyShare: { group: string; publicKey: string };
}

export interface ServerHello {
  type: "ServerHello";
  legacyVersion: "TLS 1.2";
  random: string;
  selectedVersion: string;
  /** サーバーが選んだ暗号スイート。ここを書き換えるのがダウングレード攻撃。 */
  cipherSuite: string;
  keyShare: { group: string; publicKey: string };
}

export interface EncryptedExtensions {
  type: "EncryptedExtensions";
  alpn: string;
}

export interface CertificateMessage {
  type: "Certificate";
  /** [0] がサーバー証明書、以降が中間 CA。ルートは送らない。 */
  chain: Certificate[];
}

export interface CertificateVerifyMessage {
  type: "CertificateVerify";
  algorithm: "ecdsa_secp256r1_sha256";
  /** ハンドシェイク全文に対する署名（Base64）。 */
  signature: string;
}

export interface FinishedMessage {
  type: "Finished";
  /** transcript hash への HMAC（hex）。 */
  verifyData: string;
}

export type HandshakeMessage =
  | ClientHello
  | ServerHello
  | EncryptedExtensions
  | CertificateMessage
  | CertificateVerifyMessage
  | FinishedMessage;

/** 1 メッセージを決定的なバイト列に直列化する。 */
export function encodeMessage(message: HandshakeMessage): Bytes {
  return utf8(canonicalJson(message));
}

/**
 * transcript — ここまでに送受信したハンドシェイクメッセージの並び。
 *
 * TLS 1.3 の要は、鍵導出（Derive-Secret の context）と改ざん検知（Finished）の
 * 両方がこの transcript のハッシュを見ている点にある。途中の 1 バイトでも
 * 食い違えば、両者が導出する鍵が変わり、Finished の照合も通らない。
 */
export class Transcript {
  private readonly messages: HandshakeMessage[] = [];

  append(message: HandshakeMessage): void {
    this.messages.push(message);
  }

  /** 現時点までのメッセージの一覧（読み取り専用）。 */
  list(): readonly HandshakeMessage[] {
    return this.messages;
  }

  /** 全メッセージを連結したバイト列。 */
  bytes(): Bytes {
    return concat(...this.messages.map(encodeMessage));
  }

  /** Transcript-Hash(messages)。 */
  async hash(): Promise<Bytes> {
    return sha256(this.bytes());
  }

  /** 同じ内容の独立したコピー（攻撃者が別の transcript を持つ状況の再現に使う）。 */
  clone(): Transcript {
    const copy = new Transcript();
    for (const m of this.messages) copy.append(m);
    return copy;
  }
}

/**
 * CertificateVerify の署名対象（RFC 8446 §4.4.3）。
 *
 *   0x20 を 64 個 || コンテキスト文字列 || 0x00 || Transcript-Hash(Certificate まで)
 *
 * 先頭のパディングとコンテキスト文字列は、この署名が他の用途（証明書への署名や
 * クライアント側の CertificateVerify）の署名として流用されるのを防ぐためにある。
 */
export function certificateVerifyContent(
  transcriptHash: Bytes,
  side: "server" | "client" = "server",
): Bytes {
  return concat(
    new Uint8Array(64).fill(0x20),
    utf8(`TLS 1.3, ${side} CertificateVerify`),
    new Uint8Array([0x00]),
    transcriptHash,
  );
}
