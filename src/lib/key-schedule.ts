/**
 * TLS 1.3 の鍵スケジュール（RFC 8446 §7.1）。
 *
 * TLS ツリーの「Key Exchange（共通鍵を安全に共有）」層の後半。ECDHE で得た
 * 32 バイトの共有秘密を、用途ごとに分かれた大量の鍵へ機械的に展開する部分。
 *
 *              0
 *              |
 *              v
 *    PSK ->  HKDF-Extract = Early Secret
 *              |
 *              v
 *        Derive-Secret(., "derived", "")
 *              |
 *              v
 *  (EC)DHE ->  HKDF-Extract = Handshake Secret
 *              |
 *              +--> Derive-Secret(., "c hs traffic", ClientHello..ServerHello)
 *              +--> Derive-Secret(., "s hs traffic", ClientHello..ServerHello)
 *              |
 *              v
 *        Derive-Secret(., "derived", "")
 *              |
 *              v
 *      0 ->  HKDF-Extract = Master Secret
 *              |
 *              +--> Derive-Secret(., "c ap traffic", ClientHello..server Finished)
 *              +--> Derive-Secret(., "s ap traffic", ClientHello..server Finished)
 *
 * 設計の要点は 2 つ:
 *   1. 用途ごとにラベルを変えるので、ある鍵が漏れても他の鍵は導出できない。
 *   2. traffic secret は transcript hash から派生するので、
 *      ハンドシェイクの内容が 1 バイトでも違えば鍵が一致しない。
 */

import { type Bytes, hexPreview, zeros } from "./bytes";
import {
  HASH_LEN,
  IV_LEN,
  KEY_LEN,
  deriveSecret,
  hkdfExpandLabel,
  hkdfExtract,
  hmacSha256,
  importAeadKey,
  sha256,
} from "./crypto";

/** ある方向・ある段階の通信を守る鍵一式。 */
export interface TrafficKeys {
  /** 派生元の traffic secret。 */
  secret: Bytes;
  keyBytes: Bytes;
  key: CryptoKey;
  iv: Bytes;
}

/**
 * traffic secret から実際の AEAD 鍵と IV を導出する。
 *
 *   key = HKDF-Expand-Label(secret, "key", "", 16)
 *   iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
 */
export async function deriveTrafficKeys(secret: Bytes): Promise<TrafficKeys> {
  const keyBytes = await hkdfExpandLabel(secret, "key", new Uint8Array(0), KEY_LEN);
  const iv = await hkdfExpandLabel(secret, "iv", new Uint8Array(0), IV_LEN);
  return { secret, keyBytes, key: await importAeadKey(keyBytes), iv };
}

/** ハンドシェイク段階の鍵。ServerHello の直後から使い始める。 */
export interface HandshakeSecrets {
  handshakeSecret: Bytes;
  clientSecret: Bytes;
  serverSecret: Bytes;
  client: TrafficKeys;
  server: TrafficKeys;
}

/** アプリケーションデータ段階の鍵。Finished 以降の HTTP 通信を守る。 */
export interface ApplicationSecrets {
  masterSecret: Bytes;
  clientSecret: Bytes;
  serverSecret: Bytes;
  client: TrafficKeys;
  server: TrafficKeys;
}

/**
 * Early Secret。
 *
 * PSK（事前共有鍵）を使わない通常のハンドシェイクでは、salt も ikm も
 * すべてゼロ。つまり定数だが、PSK 再開と同じ手順に揃えるために必ず通る。
 */
export async function computeEarlySecret(psk?: Bytes): Promise<Bytes> {
  return hkdfExtract(zeros(HASH_LEN), psk ?? zeros(HASH_LEN));
}

/**
 * Handshake Secret。ECDHE の共有秘密がここで初めて混ざる。
 *
 * 直前に Derive-Secret(., "derived", "") を挟むのは、Early Secret を
 * そのまま salt に使わず一段噛ませることで、段どうしの独立性を保つため。
 */
export async function computeHandshakeSecret(
  earlySecret: Bytes,
  sharedSecret: Bytes,
): Promise<Bytes> {
  const derived = await deriveSecret(earlySecret, "derived", await sha256(new Uint8Array(0)));
  return hkdfExtract(derived, sharedSecret);
}

/** ClientHello..ServerHello の transcript からハンドシェイク用の鍵を導く。 */
export async function computeHandshakeSecrets(
  handshakeSecret: Bytes,
  transcriptHash: Bytes,
): Promise<HandshakeSecrets> {
  const clientSecret = await deriveSecret(handshakeSecret, "c hs traffic", transcriptHash);
  const serverSecret = await deriveSecret(handshakeSecret, "s hs traffic", transcriptHash);
  return {
    handshakeSecret,
    clientSecret,
    serverSecret,
    client: await deriveTrafficKeys(clientSecret),
    server: await deriveTrafficKeys(serverSecret),
  };
}

/** Master Secret。ここも ikm はゼロで、材料は Handshake Secret だけ。 */
export async function computeMasterSecret(handshakeSecret: Bytes): Promise<Bytes> {
  const derived = await deriveSecret(handshakeSecret, "derived", await sha256(new Uint8Array(0)));
  return hkdfExtract(derived, zeros(HASH_LEN));
}

/** ClientHello..server Finished の transcript からアプリ用の鍵を導く。 */
export async function computeApplicationSecrets(
  masterSecret: Bytes,
  transcriptHash: Bytes,
): Promise<ApplicationSecrets> {
  const clientSecret = await deriveSecret(masterSecret, "c ap traffic", transcriptHash);
  const serverSecret = await deriveSecret(masterSecret, "s ap traffic", transcriptHash);
  return {
    masterSecret,
    clientSecret,
    serverSecret,
    client: await deriveTrafficKeys(clientSecret),
    server: await deriveTrafficKeys(serverSecret),
  };
}

/**
 * Finished メッセージの verify_data。
 *
 *   finished_key = HKDF-Expand-Label(base_key, "finished", "", 32)
 *   verify_data  = HMAC(finished_key, Transcript-Hash(ここまでの全メッセージ))
 *
 * 「ハンドシェイク鍵を導出できた」ことと「見たハンドシェイクの中身が同一である」
 * ことを一度に証明する。前者は鍵交換が成立した証拠、後者は改ざんがない証拠。
 */
export async function finishedVerifyData(baseKey: Bytes, transcriptHash: Bytes): Promise<Bytes> {
  const finishedKey = await hkdfExpandLabel(baseKey, "finished", new Uint8Array(0), HASH_LEN);
  return hmacSha256(finishedKey, transcriptHash);
}

/** 導出された鍵素材を UI 表示用の 16 進プレビューにまとめる。 */
export function describeSecrets(
  handshake: HandshakeSecrets,
  application: ApplicationSecrets,
  sharedSecret: Bytes,
): Record<string, string> {
  return {
    "ECDHE 共有秘密": hexPreview(sharedSecret),
    "Handshake Secret": hexPreview(handshake.handshakeSecret),
    "client handshake traffic": hexPreview(handshake.clientSecret),
    "server handshake traffic": hexPreview(handshake.serverSecret),
    "Master Secret": hexPreview(application.masterSecret),
    "client application traffic": hexPreview(application.clientSecret),
    "server application traffic": hexPreview(application.serverSecret),
    "AEAD 鍵 (client→server)": hexPreview(application.client.keyBytes),
    "AEAD 鍵 (server→client)": hexPreview(application.server.keyBytes),
  };
}
