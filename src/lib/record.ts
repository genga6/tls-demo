/**
 * レコード層。TLS ツリーの「Encryption（以降の通信を暗号化）」層。
 *
 * ハンドシェイクで鍵が決まったあと、実際のデータはすべてこの層を通る。
 * 1 レコードごとに AEAD（AES-128-GCM）で封をし、同時に改ざん検知の
 * 認証タグを付ける。「暗号化」と「改ざん検知」が別物ではなく、
 * AEAD という 1 つの操作で同時に達成されているのがポイント。
 */

import { type Bytes, concat, hex, uint16 } from "./bytes";
import { aeadOpen, aeadSeal, recordNonce } from "./crypto";
import type { TrafficKeys } from "./key-schedule";

export type ContentType = "handshake" | "application_data" | "alert";

const CONTENT_TYPE_BYTE: Record<ContentType, number> = {
  alert: 21,
  handshake: 22,
  application_data: 23,
};

const BYTE_CONTENT_TYPE: Record<number, ContentType> = {
  21: "alert",
  22: "handshake",
  23: "application_data",
};

/** ネットワーク上を流れる 1 レコード。 */
export interface TlsRecord {
  sequenceNumber: number;
  /**
   * 外側のヘッダに書かれる型。暗号化時は本当の型を隠すため常に
   * application_data になる（本当の型は暗号文の中に入る）。
   */
  outerType: ContentType;
  /** レコードヘッダ。暗号化されないが AEAD の追加認証データとして守られる。 */
  header: Bytes;
  /** 暗号文（暗号化 OFF なら平文がそのまま入る）。 */
  payload: Bytes;
  encrypted: boolean;
}

/** 開封の結果。 */
export type OpenResult =
  | { ok: true; contentType: ContentType; plaintext: Bytes }
  | { ok: false; reason: string };

/**
 * 片方向のレコード保護。
 *
 * TLS は方向ごとに別の鍵と別の連番を持つ。連番は暗号化されず送信もされない
 * （両者が数えているだけ）が、nonce に混ぜられるので、順序が狂ったり
 * レコードが差し替えられたりすると復号が失敗する。
 */
export class RecordLayer {
  private sequenceNumber = 0;

  constructor(
    private readonly keys: TrafficKeys,
    /** false のとき暗号化せず平文のまま流す（保護のない HTTP と同じ状態）。 */
    private readonly encryptionEnabled: boolean,
  ) {}

  get seq(): number {
    return this.sequenceNumber;
  }

  /** 平文を 1 レコードに封じる。 */
  async protect(contentType: ContentType, plaintext: Bytes): Promise<TlsRecord> {
    const sequenceNumber = this.sequenceNumber++;

    if (!this.encryptionEnabled) {
      return {
        sequenceNumber,
        outerType: contentType,
        header: makeHeader(contentType, plaintext.length),
        payload: plaintext,
        encrypted: false,
      };
    }

    // TLS 1.3 の TLSInnerPlaintext: 本当の中身の末尾に本当の型を 1 バイト付ける。
    const inner = concat(plaintext, new Uint8Array([CONTENT_TYPE_BYTE[contentType]]));
    // 外側は常に application_data を名乗り、長さは認証タグ 16 バイトを含む。
    const header = makeHeader("application_data", inner.length + 16);
    const nonce = recordNonce(this.keys.iv, sequenceNumber);
    const payload = await aeadSeal(this.keys.key, nonce, inner, header);

    return { sequenceNumber, outerType: "application_data", header, payload, encrypted: true };
  }

  /** レコードを開封する。改ざんされていれば必ず失敗する。 */
  async open(record: TlsRecord): Promise<OpenResult> {
    const sequenceNumber = this.sequenceNumber++;

    if (!record.encrypted) {
      return { ok: true, contentType: record.outerType, plaintext: record.payload };
    }

    const nonce = recordNonce(this.keys.iv, sequenceNumber);
    const inner = await aeadOpen(this.keys.key, nonce, record.payload, record.header);
    if (!inner) {
      return {
        ok: false,
        reason: "AEAD の認証タグ検証に失敗（改ざん・鍵不一致・順序の食い違いのいずれか）",
      };
    }

    const typeByte = inner[inner.length - 1];
    const contentType = BYTE_CONTENT_TYPE[typeByte];
    if (!contentType) return { ok: false, reason: `未知の content type: ${typeByte}` };

    return { ok: true, contentType, plaintext: inner.slice(0, inner.length - 1) };
  }
}

/**
 * レコードヘッダ（TLSCiphertext）。
 *
 *   opaque_type(1) || legacy_record_version(2) || length(2)
 *
 * 暗号化されないので盗聴者にも「TLS レコードが何バイト流れたか」は見える。
 * ただし AEAD の追加認証データに含まれるため、長さを書き換えると復号が失敗する。
 */
function makeHeader(contentType: ContentType, length: number): Bytes {
  return concat(
    new Uint8Array([CONTENT_TYPE_BYTE[contentType]]),
    new Uint8Array([0x03, 0x03]), // legacy_record_version = TLS 1.2 固定
    uint16(length),
  );
}

/** 盗聴者から見たレコードの姿（16 進ダンプ）。 */
export function recordOnTheWire(record: TlsRecord): string {
  return `${hex(record.header)} | ${hex(record.payload)}`;
}
