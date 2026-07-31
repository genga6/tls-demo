/**
 * TLS 1.3 が使う暗号プリミティブを Web Crypto の上に薄く並べたもの。
 *
 * ここは「本物」の部分で、鍵導出（HKDF-Expand-Label / Derive-Secret）、
 * 鍵交換（ECDHE P-256）、署名（ECDSA P-256）、AEAD（AES-128-GCM）はいずれも
 * RFC 8446 に沿った定義そのままを実装している。
 * 実装をごまかしているのはハンドシェイクメッセージのバイト表現だけで、
 * それは `transcript.ts` に隔離してある。
 *
 * 暗号スイート相当: TLS_AES_128_GCM_SHA256
 */

import { type Bytes, concat, uint16, utf8, withUint8Length, zeros } from "./bytes";

const subtle = crypto.subtle;

/** SHA-256 の出力長。TLS 1.3 では「Hash.length」としてあちこちに現れる。 */
export const HASH_LEN = 32;
/** AES-128 の鍵長。 */
export const KEY_LEN = 16;
/** AEAD の nonce 長（GCM の 96 ビット）。 */
export const IV_LEN = 12;

// ---------------------------------------------------------------------------
// ハッシュと HMAC
// ---------------------------------------------------------------------------

/** SHA-256。 */
export async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

/** HMAC-SHA256。鍵は生バイト列で受け取る。 */
export async function hmacSha256(key: Bytes, data: Bytes): Promise<Bytes> {
  const cryptoKey = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return new Uint8Array(await subtle.sign("HMAC", cryptoKey, data));
}

// ---------------------------------------------------------------------------
// HKDF（RFC 5869）と TLS 1.3 のラベル付き派生（RFC 8446 §7.1）
// ---------------------------------------------------------------------------

/**
 * HKDF-Extract: 入力鍵素材（ikm）を固定長の擬似乱数鍵（PRK）に「濃縮」する。
 *
 * 実体は HMAC(salt を鍵として, ikm) で、ECDHE の共有秘密のように
 * 分布が一様でない値を、そのまま鍵として使える形に整えるのが目的。
 */
export async function hkdfExtract(salt: Bytes, ikm: Bytes): Promise<Bytes> {
  return hmacSha256(salt, ikm);
}

/**
 * HKDF-Expand: PRK から任意長の鍵素材を「伸長」する。
 *
 * T(i) = HMAC(PRK, T(i-1) | info | i) を必要な長さになるまで繰り返し連結する。
 */
export async function hkdfExpand(prk: Bytes, info: Bytes, length: number): Promise<Bytes> {
  const blocks: Bytes[] = [];
  let previous = new Uint8Array(0);
  for (let counter = 1; blocks.reduce((n, b) => n + b.length, 0) < length; counter++) {
    previous = await hmacSha256(prk, concat(previous, info, new Uint8Array([counter])));
    blocks.push(previous);
  }
  return concat(...blocks).slice(0, length);
}

/**
 * HKDF-Expand-Label（RFC 8446 §7.1）。
 *
 * ラベルを構造体に詰めてから HKDF-Expand に渡すことで、
 * 同じ秘密から派生した別用途の鍵どうしが絶対に一致しないようにしている。
 *
 *   struct {
 *     uint16 length;
 *     opaque label<7..255>  = "tls13 " + Label;
 *     opaque context<0..255>;
 *   } HkdfLabel;
 */
export async function hkdfExpandLabel(
  secret: Bytes,
  label: string,
  context: Bytes,
  length: number,
): Promise<Bytes> {
  const hkdfLabel = concat(
    uint16(length),
    withUint8Length(utf8(`tls13 ${label}`)),
    withUint8Length(context),
  );
  return hkdfExpand(secret, hkdfLabel, length);
}

/**
 * Derive-Secret（RFC 8446 §7.1）。
 *
 * HKDF-Expand-Label の context に「ここまでのハンドシェイク全文のハッシュ」を
 * 入れる形。これにより、導出される鍵がやり取りの内容そのものに縛られ、
 * 途中でメッセージを改ざんされると両者の鍵が一致しなくなる。
 */
export async function deriveSecret(
  secret: Bytes,
  label: string,
  transcriptHash: Bytes,
): Promise<Bytes> {
  return hkdfExpandLabel(secret, label, transcriptHash, HASH_LEN);
}

// ---------------------------------------------------------------------------
// ECDHE（P-256）— 鍵交換
// ---------------------------------------------------------------------------

export interface EcdhKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** 非圧縮形式の公開点（65 バイト）。ハンドシェイクで相手に送る値。 */
  publicKeyRaw: Bytes;
}

/** P-256 の鍵ペアを生成する（ECDHE のたびに新しく作れば前方秘匿性が得られる）。 */
export async function generateEcdhKeyPair(): Promise<EcdhKeyPair> {
  const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const publicKeyRaw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicKeyRaw };
}

/**
 * ECDH 共有秘密の計算。
 *
 * 自分の秘密鍵 a と相手の公開点 B から aB を計算する。相手も bA を計算し、
 * aB = bA = abG となって同じ値に辿り着く。盗聴者は A と B しか見えず、
 * そこから abG を求めるのは離散対数問題そのもので現実的に解けない。
 */
export async function ecdhSharedSecret(
  privateKey: CryptoKey,
  peerPublicKeyRaw: Bytes,
): Promise<Bytes> {
  const peerKey = await subtle.importKey(
    "raw",
    peerPublicKeyRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  return new Uint8Array(
    await subtle.deriveBits({ name: "ECDH", public: peerKey }, privateKey, 256),
  );
}

// ---------------------------------------------------------------------------
// ECDSA（P-256）— 署名（証明書の署名と CertificateVerify）
// ---------------------------------------------------------------------------

export interface SigningKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  /** 証明書に載せる公開鍵（JWK 形式で中身が読める）。 */
  publicKeyJwk: JsonWebKey;
}

/** ECDSA P-256 の署名鍵ペアを生成する。 */
export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const publicKeyJwk = await subtle.exportKey("jwk", pair.publicKey);
  return { privateKey: pair.privateKey, publicKey: pair.publicKey, publicKeyJwk };
}

/** ECDSA-SHA256 で署名する。 */
export async function sign(privateKey: CryptoKey, data: Bytes): Promise<Bytes> {
  const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, data);
  return new Uint8Array(sig);
}

/** ECDSA-SHA256 の署名を検証する。 */
export async function verify(
  publicKey: CryptoKey,
  signature: Bytes,
  data: Bytes,
): Promise<boolean> {
  return subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, data);
}

/** JWK 形式の公開鍵を検証用の CryptoKey に戻す。 */
export async function importVerifyKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

// ---------------------------------------------------------------------------
// AES-128-GCM — レコード層の AEAD
// ---------------------------------------------------------------------------

/** 生の 16 バイトを AES-GCM 鍵として取り込む。 */
export async function importAeadKey(keyBytes: Bytes): Promise<CryptoKey> {
  return subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/**
 * AEAD による封印（暗号化 + 認証タグ付与）。
 *
 * additionalData は暗号化されないが認証の対象にはなる。TLS ではレコードヘッダが
 * ここに入り、ヘッダを書き換えると復号が必ず失敗するようになっている。
 */
export async function aeadSeal(
  key: CryptoKey,
  nonce: Bytes,
  plaintext: Bytes,
  additionalData: Bytes,
): Promise<Bytes> {
  const sealed = await subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
    key,
    plaintext,
  );
  return new Uint8Array(sealed);
}

/**
 * AEAD による開封（復号 + 認証タグ検証）。
 *
 * 1 ビットでも改ざんされていれば復号は例外になる。ここでは呼び出し側が
 * 扱いやすいよう null を返す。
 */
export async function aeadOpen(
  key: CryptoKey,
  nonce: Bytes,
  ciphertext: Bytes,
  additionalData: Bytes,
): Promise<Bytes | null> {
  try {
    const opened = await subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData, tagLength: 128 },
      key,
      ciphertext,
    );
    return new Uint8Array(opened);
  } catch {
    return null;
  }
}

/**
 * レコードごとの nonce を作る（RFC 8446 §5.3）。
 *
 * 固定の write_iv とレコード連番の XOR。レコードごとに必ず違う nonce になり、
 * GCM で致命的な nonce 再利用を構造的に防いでいる。
 */
export function recordNonce(writeIv: Bytes, sequenceNumber: number): Bytes {
  const seq = zeros(IV_LEN);
  // 連番を右詰めのビッグエンディアンで置く（本来 64 ビット、ここでは下位 32 ビットで十分）。
  new DataView(seq.buffer).setUint32(IV_LEN - 4, sequenceNumber);
  const nonce = new Uint8Array(IV_LEN);
  for (let i = 0; i < IV_LEN; i++) nonce[i] = writeIv[i] ^ seq[i];
  return nonce;
}
