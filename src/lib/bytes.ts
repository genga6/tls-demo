/**
 * バイト列ユーティリティ。
 *
 * TLS はバイト列を「連結してハッシュ」「連結して署名」する操作の塊なので、
 * Buffer 非依存（ブラウザでもそのまま動く）の最小限のヘルパをここに集約する。
 */

/**
 * このデモで扱うバイト列の型。
 *
 * TypeScript 5.7 以降、`Uint8Array` は基となるバッファを型引数に取り、既定は
 * `SharedArrayBuffer` も含む `ArrayBufferLike` になる。Web Crypto は共有バッファを
 * 受け付けないため、専有バッファに固定した別名を用意してプロジェクト全体で使う。
 */
export type Bytes = Uint8Array<ArrayBuffer>;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** UTF-8 文字列 → バイト列。 */
export function utf8(text: string): Bytes {
  return textEncoder.encode(text);
}

/** バイト列 → UTF-8 文字列。 */
export function fromUtf8(bytes: Bytes): string {
  return textDecoder.decode(bytes);
}

/** バイト列 → 小文字 16 進文字列。 */
export function hex(bytes: Bytes): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** 16 進文字列 → バイト列。 */
export function fromHex(text: string): Bytes {
  const clean = text.replace(/\s+/g, "");
  if (clean.length % 2 !== 0) throw new Error("16 進文字列の長さが奇数");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** バイト列 → Base64（証明書やトークンの表示用）。 */
export function base64(bytes: Bytes): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Base64 → バイト列。 */
export function fromBase64(text: string): Bytes {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** 複数のバイト列を連結する。 */
export function concat(...parts: Bytes[]): Bytes {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** n バイトのゼロ列（HKDF の salt / ikm に使う）。 */
export function zeros(n: number): Bytes {
  return new Uint8Array(n);
}

/**
 * 長さを一致させたうえで全バイトを走査する比較。
 *
 * 早期 return しないのは、比較にかかる時間から正解バイト数が漏れる
 * タイミング攻撃を避けるため（Finished や MAC の照合で使う）。
 */
export function timingSafeEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** uint16 を 2 バイト（ビッグエンディアン）に。 */
export function uint16(value: number): Bytes {
  return new Uint8Array([(value >> 8) & 0xff, value & 0xff]);
}

/** 1 バイトの長さ接頭辞つきバイト列（TLS の `opaque x<0..255>` 相当）。 */
export function withUint8Length(bytes: Bytes): Bytes {
  if (bytes.length > 255) throw new Error("255 バイトを超える値には 1 バイト長は使えない");
  return concat(new Uint8Array([bytes.length]), bytes);
}

/** 表示用に先頭 n バイトだけを 16 進化し、続きがあれば省略記号を付ける。 */
export function hexPreview(bytes: Bytes, n = 16): string {
  const head = hex(bytes.slice(0, n));
  return bytes.length > n ? `${head}…（全 ${bytes.length} バイト）` : head;
}

/**
 * キーを再帰的にソートした決定的な JSON 直列化。
 *
 * 証明書の署名対象やハンドシェイクの transcript hash は「同じ内容なら必ず
 * 同じバイト列」でなければ成立しない。本物の TLS/X.509 が DER という厳密な
 * バイナリ表現を使っているのと同じ理由で、ここでも正規形を定義しておく。
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}
