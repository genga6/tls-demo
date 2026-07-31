/**
 * サーバー役と、デモが使う PKI の「世界」の組み立て。
 *
 * 正規サーバーのほか、各攻撃で使う偽サーバーもここで用意する。攻撃ごとに
 * **たった 1 つの防御だけ**が結果を左右するよう、他の条件はすべて正規サーバーと
 * 同じに揃えてある（例: 期限切れサーバーは、期限以外は完全に正しい）。
 */

import { type EcdhKeyPair, generateEcdhKeyPair, generateSigningKeyPair } from "./crypto";
import { CIPHER_SUITES, NEGOTIATED_SUITE } from "./messages";
import {
  type Certificate,
  type CertificateAuthority,
  createIntermediateCa,
  createRootCa,
  issueCertificate,
} from "./pki";

/** TLS サーバー 1 台。 */
export interface TlsServer {
  id: string;
  label: string;
  /** 提示する証明書チェーン（[0] がリーフ、以降が中間 CA）。 */
  certificateChain: Certificate[];
  /**
   * CertificateVerify の署名に使う秘密鍵。
   * 証明書の公開鍵と対応しているとは限らない（証明書コピペ攻撃の再現）。
   */
  signingKey: CryptoKey;
  /**
   * 長期の静的 ECDH 鍵。前方秘匿性を切ったときの鍵交換に使う。
   * この鍵が漏れると、過去に記録された通信をすべて復号できてしまう。
   */
  staticEcdh: EcdhKeyPair;
}

/** サーバーが暗号スイートを選ぶ。クライアントの提示順を尊重する。 */
export function selectCipherSuite(offered: string[]): string {
  // このデモが実装しているのは AES-128-GCM のみ。それが提示されていれば選ぶ。
  if (offered.includes(NEGOTIATED_SUITE)) return NEGOTIATED_SUITE;
  // 残っているものから先頭を選ぶ（ダウングレード攻撃で弱いものだけが残る場面）。
  return offered[0] ?? NEGOTIATED_SUITE;
}

/** 弱いとみなす（＝ダウングレードの成果とみなす）スイート。 */
export function isWeakSuite(suite: string): boolean {
  return suite !== "TLS_AES_128_GCM_SHA256" && suite !== "TLS_AES_256_GCM_SHA384";
}

/** クライアントが最初に提示するスイート一覧。 */
export function offeredCipherSuites(): string[] {
  return [...CIPHER_SUITES];
}

// ---------------------------------------------------------------------------
// デモの世界
// ---------------------------------------------------------------------------

export const LEGIT_HOSTNAME = "bank.example.com";
export const ATTACKER_HOSTNAME = "evil.example.net";

export interface DemoWorld {
  now: Date;
  /** ブラウザ／OS にプリインストールされている想定のルート CA。 */
  rootCa: CertificateAuthority;
  /** ルート CA が発行した中間 CA。実際のサーバー証明書はここが発行する。 */
  intermediateCa: CertificateAuthority;
  /** クライアントの信頼ストア。ここにあるルートだけが信頼の起点。 */
  trustedRoots: Certificate[];
  /** 攻撃者が自分で立てた CA。誰でも作れるが、信頼ストアには入っていない。 */
  rogueCa: CertificateAuthority;
  /** 失効済みシリアル番号（CRL / OCSP 相当）。 */
  revokedSerials: Set<string>;

  legitServer: TlsServer;
  /** 攻撃者の偽 CA が発行した bank.example.com 証明書を出すサーバー。 */
  mitmServer: TlsServer;
  /** 攻撃者が正規に取得した evil.example.net の証明書を出すサーバー。 */
  wrongHostnameServer: TlsServer;
  /** 期限切れ証明書を出すサーバー。 */
  expiredServer: TlsServer;
  /** 失効済み証明書を出すサーバー。 */
  revokedServer: TlsServer;
  /** 正規の証明書をコピーして出すが、対応する秘密鍵を持たないサーバー。 */
  certCopyServer: TlsServer;
}

const DAY_MS = 24 * 60 * 60 * 1000;
const YEAR_MS = 365 * DAY_MS;

/**
 * デモの世界を一度だけ構築する。
 *
 * 鍵生成が何度も走るので、UI 側では結果をキャッシュして使い回す。
 */
export async function buildWorld(now: Date = new Date()): Promise<DemoWorld> {
  const rootCa = await createRootCa("Example Root CA", now);
  const intermediateCa = await createIntermediateCa(rootCa, "Example TLS CA G2", now);
  const rogueCa = await createRootCa("Totally Legit CA", now);
  const revokedSerials = new Set<string>();

  // --- 正規サーバー ------------------------------------------------------
  const legitKeys = await generateSigningKeyPair();
  const legit = await issueCertificate(
    intermediateCa,
    {
      subject: LEGIT_HOSTNAME,
      subjectAltNames: [LEGIT_HOSTNAME, `*.${LEGIT_HOSTNAME}`],
      publicKeyJwk: legitKeys.publicKeyJwk,
    },
    now,
  );
  const legitServer: TlsServer = {
    id: "legit",
    label: "正規サーバー",
    certificateChain: [legit.certificate, intermediateCa.certificate],
    signingKey: legitKeys.privateKey,
    staticEcdh: await generateEcdhKeyPair(),
  };

  // --- 中間者: 偽 CA が発行した、正しいホスト名の証明書 -------------------
  // 署名も期限もホスト名も「一見すると正しい」。唯一の欠陥は、
  // 発行元 CA が信頼ストアに存在しないこと。
  const mitmKeys = await generateSigningKeyPair();
  const mitm = await issueCertificate(
    rogueCa,
    {
      subject: LEGIT_HOSTNAME,
      subjectAltNames: [LEGIT_HOSTNAME],
      publicKeyJwk: mitmKeys.publicKeyJwk,
    },
    now,
  );
  const mitmServer: TlsServer = {
    id: "mitm",
    label: "中間者（偽 CA 発行の証明書）",
    certificateChain: [mitm.certificate, rogueCa.certificate],
    signingKey: mitmKeys.privateKey,
    staticEcdh: await generateEcdhKeyPair(),
  };

  // --- ホスト名不一致: 攻撃者が正規に取得した別ドメインの証明書 -----------
  // チェーンも期限も完璧に正しい。攻撃者が本当に evil.example.net を
  // 所有していれば CA は正規に発行する。問題は繋ぎ先が違うことだけ。
  const wrongHostKeys = await generateSigningKeyPair();
  const wrongHost = await issueCertificate(
    intermediateCa,
    {
      subject: ATTACKER_HOSTNAME,
      subjectAltNames: [ATTACKER_HOSTNAME],
      publicKeyJwk: wrongHostKeys.publicKeyJwk,
    },
    now,
  );
  const wrongHostnameServer: TlsServer = {
    id: "wrong-hostname",
    label: "成りすまし（別ドメインの正規証明書）",
    certificateChain: [wrongHost.certificate, intermediateCa.certificate],
    signingKey: wrongHostKeys.privateKey,
    staticEcdh: await generateEcdhKeyPair(),
  };

  // --- 期限切れ ----------------------------------------------------------
  const expiredKeys = await generateSigningKeyPair();
  const expired = await issueCertificate(
    intermediateCa,
    {
      subject: LEGIT_HOSTNAME,
      subjectAltNames: [LEGIT_HOSTNAME],
      publicKeyJwk: expiredKeys.publicKeyJwk,
      notBefore: new Date(now.getTime() - 2 * YEAR_MS),
      notAfter: new Date(now.getTime() - 30 * DAY_MS),
    },
    now,
  );
  const expiredServer: TlsServer = {
    id: "expired",
    label: "期限切れ証明書のサーバー",
    certificateChain: [expired.certificate, intermediateCa.certificate],
    signingKey: expiredKeys.privateKey,
    staticEcdh: await generateEcdhKeyPair(),
  };

  // --- 失効済み ----------------------------------------------------------
  // 秘密鍵が漏れたので CA が失効させた、という想定。期限内なので
  // 失効リストを引かない限り見抜けない。
  const revokedKeys = await generateSigningKeyPair();
  const revoked = await issueCertificate(
    intermediateCa,
    {
      subject: LEGIT_HOSTNAME,
      subjectAltNames: [LEGIT_HOSTNAME],
      publicKeyJwk: revokedKeys.publicKeyJwk,
    },
    now,
  );
  revokedSerials.add(revoked.certificate.body.serialNumber);
  intermediateCa.revokedSerials.add(revoked.certificate.body.serialNumber);
  const revokedServer: TlsServer = {
    id: "revoked",
    label: "失効済み証明書のサーバー",
    certificateChain: [revoked.certificate, intermediateCa.certificate],
    signingKey: revokedKeys.privateKey,
    staticEcdh: await generateEcdhKeyPair(),
  };

  // --- 証明書コピペ ------------------------------------------------------
  // 証明書は公開情報なので、誰でも取得してそのまま提示できる。
  // ただし対応する秘密鍵は手元にないので、別の鍵で署名するしかない。
  const impostorKeys = await generateSigningKeyPair();
  const certCopyServer: TlsServer = {
    id: "cert-copy",
    label: "証明書コピペ（秘密鍵なし）",
    certificateChain: legitServer.certificateChain,
    signingKey: impostorKeys.privateKey,
    staticEcdh: await generateEcdhKeyPair(),
  };

  return {
    now,
    rootCa,
    intermediateCa,
    rogueCa,
    trustedRoots: [rootCa.certificate],
    revokedSerials,
    legitServer,
    mitmServer,
    wrongHostnameServer,
    expiredServer,
    revokedServer,
    certCopyServer,
  };
}
