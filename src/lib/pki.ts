/**
 * PKI — 証明書と認証局。TLS ツリーの「Certificate（サーバーが本物か確認）」層。
 *
 * 鍵交換だけでは「誰かと安全な通信路ができた」ことしか分からない。相手が
 * 意図した相手であることは、第三者（CA）の署名という外部の根拠に頼るしかない。
 * ここではその信頼の連鎖を最小構成で再現する。
 *
 * 現実との差分: 証明書は X.509 の DER ではなく、中身が読める JSON で表現する。
 * 署名の対象・検証手順・チェーンの辿り方は本物と同じ考え方をとる。
 */

import { type Bytes, base64, canonicalJson, fromBase64, utf8 } from "./bytes";
import {
  type SigningKeyPair,
  generateSigningKeyPair,
  importVerifyKey,
  sign,
  verify,
} from "./crypto";
import { randomId } from "./random";

// ---------------------------------------------------------------------------
// 証明書
// ---------------------------------------------------------------------------

/** 証明書の署名対象になる本体（X.509 の tbsCertificate 相当）。 */
export interface CertificateBody {
  serialNumber: string;
  /** 証明書の持ち主。 */
  subject: string;
  /** この証明書が有効なホスト名（X.509 の subjectAltName）。 */
  subjectAltNames: string[];
  /** この証明書に署名した CA の名前。 */
  issuer: string;
  notBefore: string;
  notAfter: string;
  /** 持ち主の公開鍵。TLS ではこの鍵で CertificateVerify を検証する。 */
  publicKeyJwk: JsonWebKey;
  /** 他の証明書に署名できる CA 証明書か（X.509 の basicConstraints）。 */
  isCa: boolean;
}

/** 本体 + 発行者による署名。 */
export interface Certificate {
  body: CertificateBody;
  signatureAlgorithm: "ecdsa-with-SHA256";
  /** issuer の秘密鍵による body への署名（Base64）。 */
  signature: string;
}

/**
 * 署名対象のバイト列を作る。
 *
 * キーの順序が変わると別のバイト列になり署名が壊れるため、
 * 再帰的にキーをソートした正規形にしてから直列化する。
 */
export function certificateTbsBytes(body: CertificateBody): Bytes {
  return utf8(canonicalJson(body));
}

// ---------------------------------------------------------------------------
// 認証局
// ---------------------------------------------------------------------------

export interface CertificateAuthority {
  name: string;
  keyPair: SigningKeyPair;
  /** この CA 自身の証明書（ルートなら自己署名）。 */
  certificate: Certificate;
  /** 失効させたシリアル番号（CRL / OCSP 相当）。 */
  revokedSerials: Set<string>;
}

const YEAR_MS = 365 * 24 * 60 * 60 * 1000;

/**
 * ルート CA を作る。
 *
 * ルート証明書は自分の秘密鍵で自分に署名した「自己署名証明書」で、
 * 署名としては何も証明していない。信頼の根拠は署名ではなく、
 * OS やブラウザの信頼ストアにあらかじめ入っているという一点にある。
 */
export async function createRootCa(
  name: string,
  now: Date = new Date(),
): Promise<CertificateAuthority> {
  const keyPair = await generateSigningKeyPair();
  const body: CertificateBody = {
    serialNumber: randomId(),
    subject: name,
    subjectAltNames: [],
    issuer: name, // 自己署名: subject と issuer が同一
    notBefore: new Date(now.getTime() - YEAR_MS).toISOString(),
    notAfter: new Date(now.getTime() + 10 * YEAR_MS).toISOString(),
    publicKeyJwk: keyPair.publicKeyJwk,
    isCa: true,
  };
  const signature = base64(await sign(keyPair.privateKey, certificateTbsBytes(body)));
  return {
    name,
    keyPair,
    certificate: { body, signatureAlgorithm: "ecdsa-with-SHA256", signature },
    revokedSerials: new Set(),
  };
}

export interface IssueOptions {
  subject: string;
  subjectAltNames?: string[];
  /** 発行先の公開鍵。省略すると新しい鍵ペアを作って返す。 */
  publicKeyJwk?: JsonWebKey;
  isCa?: boolean;
  notBefore?: Date;
  notAfter?: Date;
}

/** CA が証明書を発行する（＝発行対象の本体に CA の秘密鍵で署名する）。 */
export async function issueCertificate(
  issuer: CertificateAuthority,
  options: IssueOptions,
  now: Date = new Date(),
): Promise<{ certificate: Certificate; keyPair?: SigningKeyPair }> {
  const keyPair = options.publicKeyJwk ? undefined : await generateSigningKeyPair();
  const publicKeyJwk = options.publicKeyJwk ?? keyPair?.publicKeyJwk;
  if (!publicKeyJwk) throw new Error("公開鍵を用意できなかった");

  const body: CertificateBody = {
    serialNumber: randomId(),
    subject: options.subject,
    subjectAltNames: options.subjectAltNames ?? [],
    issuer: issuer.name,
    notBefore: (options.notBefore ?? new Date(now.getTime() - 24 * 60 * 60 * 1000)).toISOString(),
    notAfter: (options.notAfter ?? new Date(now.getTime() + YEAR_MS)).toISOString(),
    publicKeyJwk,
    isCa: options.isCa ?? false,
  };
  const signature = base64(await sign(issuer.keyPair.privateKey, certificateTbsBytes(body)));
  return {
    certificate: { body, signatureAlgorithm: "ecdsa-with-SHA256", signature },
    keyPair,
  };
}

/** 発行済み CA 証明書から中間 CA を組み立てる。 */
export async function createIntermediateCa(
  root: CertificateAuthority,
  name: string,
  now: Date = new Date(),
): Promise<CertificateAuthority> {
  const { certificate, keyPair } = await issueCertificate(root, { subject: name, isCa: true }, now);
  if (!keyPair) throw new Error("中間 CA の鍵ペアが生成されなかった");
  return { name, keyPair, certificate, revokedSerials: new Set() };
}

// ---------------------------------------------------------------------------
// 検証
// ---------------------------------------------------------------------------

/** 個々のチェック結果。UI にそのまま並べられる粒度にしてある。 */
export interface CertCheck {
  name: string;
  status: "pass" | "fail" | "skipped";
  detail: string;
}

export interface ChainVerificationResult {
  ok: boolean;
  checks: CertCheck[];
  /** 失敗した場合の一行説明。 */
  reason?: string;
}

export interface VerifyChainOptions {
  /** 信頼ストア。ここに入っているルート証明書だけが信頼の起点になれる。 */
  trustedRoots: Certificate[];
  /** 接続先ホスト名（SAN 照合の対象）。 */
  hostname: string;
  now: Date;
  /** 失効情報（CA 名 → 失効シリアル）。 */
  revokedSerials?: Set<string>;
  /** どの検証を実施するか。false のものは "skipped" になる。 */
  enable: {
    chain: boolean;
    hostname: boolean;
    validity: boolean;
  };
}

/**
 * 証明書チェーンを検証する。
 *
 * chain[0] がサーバー証明書（リーフ）、以降が中間 CA。ルートは送られてこず、
 * クライアントの信頼ストアから探す。各段で「発行者の公開鍵で署名が検証できるか」
 * を確かめ、最後に信頼ストアへ到達できれば信頼の連鎖が完成する。
 */
export async function verifyCertificateChain(
  chain: Certificate[],
  options: VerifyChainOptions,
): Promise<ChainVerificationResult> {
  const checks: CertCheck[] = [];
  let reason: string | undefined;

  if (chain.length === 0) {
    return {
      ok: false,
      checks: [{ name: "証明書の受信", status: "fail", detail: "証明書が 1 枚も届いていない" }],
      reason: "証明書が提示されなかった",
    };
  }

  const leaf = chain[0];

  // --- ホスト名照合 ------------------------------------------------------
  if (options.enable.hostname) {
    const names = leaf.body.subjectAltNames;
    const matched = names.some((n) => matchesHostname(n, options.hostname));
    checks.push({
      name: "ホスト名照合 (SAN)",
      status: matched ? "pass" : "fail",
      detail: matched
        ? `${options.hostname} は SAN [${names.join(", ")}] に含まれる`
        : `${options.hostname} は SAN [${names.join(", ")}] のいずれにも一致しない`,
    });
    if (!matched) reason ??= `証明書のホスト名不一致（提示: ${names.join(", ")}）`;
  } else {
    checks.push({
      name: "ホスト名照合 (SAN)",
      status: "skipped",
      detail: `照合を省略。SAN は [${leaf.body.subjectAltNames.join(", ")}]`,
    });
  }

  // --- 有効期限と失効 ----------------------------------------------------
  if (options.enable.validity) {
    const notBefore = new Date(leaf.body.notBefore);
    const notAfter = new Date(leaf.body.notAfter);
    const inRange = options.now >= notBefore && options.now <= notAfter;
    checks.push({
      name: "有効期限",
      status: inRange ? "pass" : "fail",
      detail: inRange
        ? `有効期間内（${fmt(notBefore)} 〜 ${fmt(notAfter)}）`
        : `有効期間外（${fmt(notBefore)} 〜 ${fmt(notAfter)} / 現在 ${fmt(options.now)}）`,
    });
    if (!inRange) reason ??= options.now > notAfter ? "証明書の期限切れ" : "証明書がまだ有効でない";

    const revoked = options.revokedSerials?.has(leaf.body.serialNumber) ?? false;
    checks.push({
      name: "失効確認 (CRL/OCSP)",
      status: revoked ? "fail" : "pass",
      detail: revoked
        ? `シリアル ${leaf.body.serialNumber} は失効リストに載っている`
        : `シリアル ${leaf.body.serialNumber} は失効していない`,
    });
    if (revoked) reason ??= "証明書が失効済み";
  } else {
    checks.push({
      name: "有効期限・失効確認",
      status: "skipped",
      detail: `確認を省略。notAfter は ${fmt(new Date(leaf.body.notAfter))}`,
    });
  }

  // --- チェーンの署名検証 ------------------------------------------------
  if (options.enable.chain) {
    const chainResult = await verifySignatureChain(chain, options.trustedRoots);
    checks.push(...chainResult.checks);
    if (!chainResult.ok) reason ??= chainResult.reason;
  } else {
    checks.push({
      name: "チェーン署名検証",
      status: "skipped",
      detail: `検証を省略。発行者は "${leaf.body.issuer}" と自称しているが誰も確かめていない`,
    });
  }

  const ok = checks.every((c) => c.status !== "fail");
  return { ok, checks, reason: ok ? undefined : reason };
}

/** チェーンを 1 段ずつ辿り、最後に信頼ストアへ到達できるかを確かめる。 */
async function verifySignatureChain(
  chain: Certificate[],
  trustedRoots: Certificate[],
): Promise<ChainVerificationResult> {
  const checks: CertCheck[] = [];

  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    const next = chain[i + 1];
    // 発行者は「チェーンの次の証明書」か、なければ信頼ストアのルート。
    const issuerCert = next ?? trustedRoots.find((r) => r.body.subject === cert.body.issuer);

    if (!issuerCert) {
      checks.push({
        name: `信頼の起点 (${cert.body.issuer})`,
        status: "fail",
        detail: `発行者 "${cert.body.issuer}" が信頼ストアに存在しない。誰でも名乗れる自称 CA。`,
      });
      return {
        ok: false,
        checks,
        reason: `信頼されていない発行者 "${cert.body.issuer}"`,
      };
    }

    if (issuerCert.body.subject !== cert.body.issuer) {
      checks.push({
        name: `発行者の一致 (${cert.body.subject})`,
        status: "fail",
        detail: `issuer "${cert.body.issuer}" と次の証明書の subject "${issuerCert.body.subject}" が食い違う`,
      });
      return { ok: false, checks, reason: "チェーンが繋がっていない" };
    }

    if (!issuerCert.body.isCa) {
      checks.push({
        name: `CA 権限 (${issuerCert.body.subject})`,
        status: "fail",
        detail: "発行者が CA 証明書ではない（basicConstraints CA:FALSE）",
      });
      return { ok: false, checks, reason: "CA でない証明書が発行者になっている" };
    }

    const issuerKey = await importVerifyKey(issuerCert.body.publicKeyJwk);
    const valid = await verify(
      issuerKey,
      fromBase64(cert.signature),
      certificateTbsBytes(cert.body),
    );
    checks.push({
      name: `署名検証 ${cert.body.subject} ← ${issuerCert.body.subject}`,
      status: valid ? "pass" : "fail",
      detail: valid
        ? `"${issuerCert.body.subject}" の公開鍵で署名を検証できた`
        : `"${issuerCert.body.subject}" の公開鍵では署名を検証できない（改ざんまたは別の鍵で署名）`,
    });
    if (!valid) return { ok: false, checks, reason: "証明書の署名が不正" };

    // 信頼ストアのルートに到達したらそこで連鎖は完成。
    if (!next) {
      checks.push({
        name: "信頼ストアへの到達",
        status: "pass",
        detail: `ルート "${issuerCert.body.subject}" は信頼ストアに登録済み`,
      });
    }
  }

  return { ok: true, checks };
}

/**
 * ホスト名照合。
 *
 * ワイルドカードは最も左のラベル 1 つだけに使え、ラベルを跨がない。
 * `*.example.com` は `api.example.com` に一致するが、`example.com` にも
 * `a.b.example.com` にも一致しない。
 */
export function matchesHostname(pattern: string, hostname: string): boolean {
  const p = pattern.toLowerCase();
  const h = hostname.toLowerCase();
  if (!p.startsWith("*.")) return p === h;

  const suffix = p.slice(1); // ".example.com"
  if (!h.endsWith(suffix)) return false;
  const label = h.slice(0, h.length - suffix.length);
  return label.length > 0 && !label.includes(".");
}

function fmt(date: Date): string {
  return date.toISOString().slice(0, 10);
}
