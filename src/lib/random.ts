/**
 * 乱数生成。
 *
 * ClientHello / ServerHello の 32 バイト random、証明書のシリアル番号、
 * ECDHE の鍵ペアなどはすべて予測不能である必要があるため、
 * `Math.random()` ではなく CSPRNG（Web Crypto）を使う。
 */

import type { Bytes } from "./bytes";

/** 暗号学的に安全な n バイトの乱数。 */
export function randomBytes(n: number): Bytes {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** 16 進文字列の乱数 ID（シリアル番号などの表示用）。 */
export function randomId(byteLength = 8): string {
  let out = "";
  for (const b of randomBytes(byteLength)) out += b.toString(16).padStart(2, "0");
  return out;
}
