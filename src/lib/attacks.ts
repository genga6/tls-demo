/**
 * 攻撃シミュレーション。
 *
 * 各攻撃は、対応する防御 **1 つだけ** で結果が決まるように構成してある。
 * そのために、攻撃ごとに「その防御は UI のトグルの値、それ以外はすべて ON」
 * という設定でセッションを走らせる（`isolate` を参照）。
 * 他の防御を切っても結果が変わらないので、因果関係が 1 対 1 で読める。
 */

import { type Bytes, fromUtf8 } from "./bytes";
import { aeadOpen, ecdhSharedSecret, recordNonce } from "./crypto";
import {
  computeApplicationSecrets,
  computeEarlySecret,
  computeHandshakeSecret,
  computeHandshakeSecrets,
  computeMasterSecret,
} from "./key-schedule";
import type { ClientHello } from "./messages";
import { type DemoWorld, LEGIT_HOSTNAME } from "./server";
import type { RecordedRecord, SessionResult, SessionTrace } from "./session";
import { runSession } from "./session";
import { ALL_DEFENSES_ON, DEFENSE_INFO, type DefenseKey, type Defenses, type Phase } from "./types";

export type AttackId =
  | "mitm"
  | "wrong-hostname"
  | "expired-cert"
  | "revoked-cert"
  | "cert-copy"
  | "downgrade"
  | "retrospective-decrypt"
  | "eavesdrop";

export interface AttackResult {
  id: AttackId;
  name: string;
  /** この攻撃の成否を決める唯一の防御。 */
  defense: DefenseKey;
  phase: Phase;
  /** 攻撃者が何をするか。 */
  premise: string;
  /** 攻撃が成立したか。 */
  succeeded: boolean;
  /** 結果の一行説明。 */
  outcome: string;
  /** 成立時に攻撃者が得たもの。 */
  loot?: string;
  session?: SessionResult;
}

/**
 * 対象の防御だけ UI の値を使い、残りはすべて ON にする。
 *
 * これにより「この攻撃が通ったのは、この防御を切ったからだ」が一意に定まる。
 */
function isolate(defenses: Defenses, key: DefenseKey): Defenses {
  return { ...ALL_DEFENSES_ON, [key]: defenses[key] };
}

/** すべての攻撃を現在の防御設定で実行する。 */
export async function runAllAttacks(world: DemoWorld, defenses: Defenses): Promise<AttackResult[]> {
  return Promise.all([
    attackMitm(world, defenses),
    attackWrongHostname(world, defenses),
    attackExpiredCertificate(world, defenses),
    attackRevokedCertificate(world, defenses),
    attackCertificateCopy(world, defenses),
    attackDowngrade(world, defenses),
    attackRetrospectiveDecryption(world, defenses),
    attackEavesdrop(world, defenses),
  ]);
}

// ---------------------------------------------------------------------------
// Certificate 層の攻撃
// ---------------------------------------------------------------------------

/**
 * 中間者攻撃。
 *
 * 攻撃者は自分で CA を立て、bank.example.com 用の証明書を自分に発行する。
 * 署名としては完全に整合しており、ホスト名も期限も正しい。唯一の欠陥は、
 * その CA が信頼ストアに入っていないこと。チェーン検証はまさにそこを見ている。
 */
async function attackMitm(world: DemoWorld, defenses: Defenses): Promise<AttackResult> {
  const session = await runSession({
    defenses: isolate(defenses, "certificateChain"),
    hostname: LEGIT_HOSTNAME,
    server: world.mitmServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: world.now,
  });

  return {
    id: "mitm",
    name: "中間者攻撃（偽 CA の証明書）",
    defense: "certificateChain",
    phase: "certificate",
    premise:
      "攻撃者が自前の CA『Totally Legit CA』を立て、bank.example.com 用の証明書を自分に発行して提示する。",
    succeeded: session.established,
    outcome: session.established
      ? "クライアントは攻撃者と TLS を確立した。以降の通信はすべて攻撃者が復号できる。"
      : `チェーン検証で阻止: ${session.abortReason}`,
    loot: session.established ? session.httpRequest : undefined,
    session,
  };
}

/**
 * ホスト名不一致による成りすまし。
 *
 * 攻撃者は evil.example.net を本当に所有しており、正規の CA から正規の
 * 証明書を受け取っている。チェーンも期限も完璧。SAN を見なければ通ってしまう。
 */
async function attackWrongHostname(world: DemoWorld, defenses: Defenses): Promise<AttackResult> {
  const session = await runSession({
    defenses: isolate(defenses, "hostnameCheck"),
    hostname: LEGIT_HOSTNAME,
    server: world.wrongHostnameServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: world.now,
  });

  return {
    id: "wrong-hostname",
    name: "別ドメインの正規証明書による成りすまし",
    defense: "hostnameCheck",
    phase: "certificate",
    premise:
      "攻撃者が自分で所有する evil.example.net の正規証明書を、bank.example.com への接続に対して提示する。",
    succeeded: session.established,
    outcome: session.established
      ? "信頼された CA の署名があるという理由だけで、まったく別のサーバーを本物として受け入れた。"
      : `SAN 照合で阻止: ${session.abortReason}`,
    loot: session.established ? session.httpRequest : undefined,
    session,
  };
}

/** 期限切れ証明書の受理。 */
async function attackExpiredCertificate(
  world: DemoWorld,
  defenses: Defenses,
): Promise<AttackResult> {
  const session = await runSession({
    defenses: isolate(defenses, "validityCheck"),
    hostname: LEGIT_HOSTNAME,
    server: world.expiredServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: world.now,
  });

  return {
    id: "expired-cert",
    name: "期限切れ証明書の受理",
    defense: "validityCheck",
    phase: "certificate",
    premise:
      "30 日前に期限が切れた証明書を提示する。署名もホスト名も正しいので、日付を見なければ気づけない。",
    succeeded: session.established,
    outcome: session.established
      ? "期限切れの証明書を受け入れた。鍵の使用期間を区切るという前提が崩れる。"
      : `有効期限の確認で阻止: ${session.abortReason}`,
    loot: session.established ? session.httpRequest : undefined,
    session,
  };
}

/**
 * 失効済み証明書の受理。
 *
 * 秘密鍵が漏れた証明書は CA が失効させるが、証明書そのものは期限内のまま
 * 有効に見える。失効リストを引かない限り、漏れた鍵を持つ攻撃者を止められない。
 */
async function attackRevokedCertificate(
  world: DemoWorld,
  defenses: Defenses,
): Promise<AttackResult> {
  const session = await runSession({
    defenses: isolate(defenses, "validityCheck"),
    hostname: LEGIT_HOSTNAME,
    server: world.revokedServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: world.now,
  });

  return {
    id: "revoked-cert",
    name: "失効済み証明書の受理",
    defense: "validityCheck",
    phase: "certificate",
    premise:
      "秘密鍵の漏洩により CA が失効させた証明書を提示する。期限内なので、失効リストを引かなければ有効に見える。",
    succeeded: session.established,
    outcome: session.established
      ? "失効済みの証明書を受け入れた。漏れた鍵を無効化する手段が機能していない。"
      : `失効確認 (CRL/OCSP) で阻止: ${session.abortReason}`,
    loot: session.established ? session.httpRequest : undefined,
    session,
  };
}

/**
 * 証明書コピペ。
 *
 * 証明書は公開情報なので、正規サーバーに繋いで取得すれば誰でも手に入る。
 * だが対応する秘密鍵は手に入らない。CertificateVerify はそこだけを突く。
 */
async function attackCertificateCopy(world: DemoWorld, defenses: Defenses): Promise<AttackResult> {
  const session = await runSession({
    defenses: isolate(defenses, "certificateVerify"),
    hostname: LEGIT_HOSTNAME,
    server: world.certCopyServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: world.now,
  });

  return {
    id: "cert-copy",
    name: "証明書コピペ（秘密鍵を持たない偽サーバー）",
    defense: "certificateVerify",
    phase: "certificate",
    premise:
      "正規サーバーの証明書チェーンをそのままコピーして提示する。チェーンも SAN も期限も本物と完全に同一。",
    succeeded: session.established,
    outcome: session.established
      ? "証明書を持っているだけの相手を本物と認めた。証明書は公開情報なので、これでは何も証明していない。"
      : `CertificateVerify の署名検証で阻止: ${session.abortReason}`,
    loot: session.established ? session.httpRequest : undefined,
    session,
  };
}

// ---------------------------------------------------------------------------
// Handshake 層の攻撃
// ---------------------------------------------------------------------------

/**
 * ダウングレード攻撃。
 *
 * ClientHello は平文なので、経路上の攻撃者が暗号スイート一覧を書き換えられる。
 * 強いものを削れば、サーバーは残った弱いものを選ばざるを得ない。
 *
 * TLS 1.3 がこれを防げるのは、ハンドシェイク全文のハッシュが鍵導出と Finished の
 * 両方に効いているから。書き換えれば両者の記録が食い違い、そこで破綻する。
 */
async function attackDowngrade(world: DemoWorld, defenses: Defenses): Promise<AttackResult> {
  const session = await runSession({
    defenses: isolate(defenses, "finishedVerify"),
    hostname: LEGIT_HOSTNAME,
    server: world.legitServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: world.now,
    tamperClientHello: (hello: ClientHello) => ({
      ...hello,
      // 現代的な AEAD スイートを削り、古い RC4 のスイートだけを残す。
      cipherSuites: hello.cipherSuites.filter((s) => s.includes("RC4")),
    }),
  });

  const succeeded = session.established && session.downgraded;
  return {
    id: "downgrade",
    name: "ダウングレード攻撃（暗号スイートの格下げ）",
    defense: "finishedVerify",
    phase: "handshake",
    premise:
      "経路上で ClientHello から強い暗号スイートを削除し、サーバーに弱いスイートを選ばせる。",
    succeeded,
    outcome: succeeded
      ? `弱いスイート ${session.cipherSuite} に落とされたまま通信が成立した。`
      : `transcript hash / Finished の照合で阻止: ${session.abortReason ?? "改ざんを検出"}`,
    loot: succeeded ? `交渉結果: ${session.cipherSuite}` : undefined,
    session,
  };
}

// ---------------------------------------------------------------------------
// Key Exchange / Encryption 層の攻撃
// ---------------------------------------------------------------------------

/**
 * 長期鍵の漏洩による遡及復号。
 *
 * 攻撃者は今日の暗号文をひたすら記録しておき、後日サーバーの長期鍵を
 * 手に入れる（差し押さえ・侵入・内部犯行など）。鍵交換に長期鍵を使っていた場合、
 * 記録済みの通信をすべて遡って復号できてしまう。
 *
 * ECDHE なら、鍵交換に使った秘密鍵は接続終了時に捨てられている。長期鍵は
 * 署名（CertificateVerify）にしか使っておらず、漏れても過去の通信は守られる。
 */
async function attackRetrospectiveDecryption(
  world: DemoWorld,
  defenses: Defenses,
): Promise<AttackResult> {
  const session = await runSession({
    defenses: isolate(defenses, "forwardSecrecy"),
    hostname: LEGIT_HOSTNAME,
    server: world.legitServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: world.now,
  });

  const recovered = session.trace
    ? await attemptRetrospectiveDecryption(session.trace, world.legitServer.staticEcdh.privateKey)
    : null;

  const succeeded = recovered !== null;
  return {
    id: "retrospective-decrypt",
    name: "長期鍵の漏洩による過去通信の遡及復号",
    defense: "forwardSecrecy",
    phase: "key-exchange",
    premise:
      "攻撃者は暗号文をすべて記録しておき、後日サーバーの長期秘密鍵を入手して、記録済みの通信の復号を試みる。",
    succeeded,
    outcome: succeeded
      ? "記録しておいた暗号文を、長期鍵から鍵スケジュールを再現して復号できた。過去に遡ってすべて読める。"
      : "長期鍵を手に入れても復号できない。鍵交換に使った使い捨て鍵は接続終了時に捨てられており、どこにも残っていない。",
    loot: recovered ?? undefined,
    session,
  };
}

/**
 * 記録済みの通信を、サーバーの長期 ECDH 秘密鍵から復号し直す。
 *
 * 攻撃者が持っているのは「平文で流れた ClientHello の公開鍵」と「記録した暗号文」、
 * そして後から入手した長期秘密鍵だけ。この 3 つから鍵スケジュールをそっくり
 * 再現できてしまうかどうかを実際に試す。
 *
 * @returns 復号できた HTTP 平文。復号できなければ null。
 */
export async function attemptRetrospectiveDecryption(
  trace: SessionTrace,
  serverStaticPrivateKey: CryptoKey,
): Promise<string | null> {
  // ① 長期鍵とクライアントの公開鍵から共有秘密を再計算する。
  //    セッションが使い捨て鍵を使っていた場合、ここで別の値が出て以降すべて外れる。
  const shared = await ecdhSharedSecret(serverStaticPrivateKey, trace.clientKeyShareRaw);

  // ② 鍵スケジュールをそのまま再現する。手順は公開仕様なので誰でも辿れる。
  const handshakeSecret = await computeHandshakeSecret(await computeEarlySecret(), shared);
  const handshake = await computeHandshakeSecrets(handshakeSecret, trace.helloTranscriptHash);

  // ③ まずハンドシェイクレコードを復号できるか確かめる。
  //    ここが通れば、攻撃者は Certificate 以降を読んで transcript を再構成できる。
  const handshakeRecord = trace.records.find((r) => r.label.startsWith("EncryptedExtensions"));
  if (handshakeRecord && !(await tryDecrypt(handshake.server, handshakeRecord))) return null;

  // ④ アプリケーション鍵まで進み、記録した HTTP レコードを復号する。
  const application = await computeApplicationSecrets(
    await computeMasterSecret(handshakeSecret),
    trace.applicationTranscriptHash,
  );

  const request = trace.records.find((r) => r.label === "HTTP リクエスト");
  if (!request) return null;
  const plaintext = await tryDecrypt(application.client, request);
  return plaintext;
}

/** 記録した 1 レコードを、与えた鍵で復号してみる。 */
async function tryDecrypt(
  keys: { key: CryptoKey; iv: Bytes },
  recorded: RecordedRecord,
): Promise<string | null> {
  const { record } = recorded;
  if (!record.encrypted) return fromUtf8(record.payload);

  const nonce = recordNonce(keys.iv, record.sequenceNumber);
  const opened = await aeadOpen(keys.key, nonce, record.payload, record.header);
  if (!opened) return null;
  // 末尾 1 バイトは TLSInnerPlaintext の content type。
  return fromUtf8(opened.slice(0, opened.length - 1));
}

/**
 * 盗聴。
 *
 * 攻撃者は何もせず経路上でパケットを眺めるだけ。レコード層が暗号化されていれば
 * 暗号文しか見えないが、そうでなければ Cookie も認証トークンもそのまま読める。
 */
async function attackEavesdrop(world: DemoWorld, defenses: Defenses): Promise<AttackResult> {
  const session = await runSession({
    defenses: isolate(defenses, "recordEncryption"),
    hostname: LEGIT_HOSTNAME,
    server: world.legitServer,
    trustedRoots: world.trustedRoots,
    revokedSerials: world.revokedSerials,
    now: world.now,
  });

  const readableAppData = session.wiretap.find(
    (entry) => entry.readable && entry.label.startsWith("HTTP"),
  );

  return {
    id: "eavesdrop",
    name: "盗聴（経路上での読み取り）",
    defense: "recordEncryption",
    phase: "encryption",
    premise:
      "攻撃者は同じ Wi-Fi や経路上の機器からパケットを眺めるだけ。能動的な細工は一切しない。",
    succeeded: Boolean(readableAppData),
    outcome: readableAppData
      ? "HTTP の中身がそのまま読めた。Cookie と Authorization ヘッダを回収できる。"
      : "暗号文しか見えない。分かるのはレコード長と通信のタイミングだけ。",
    loot: readableAppData?.visible,
    session,
  };
}

/** 攻撃結果を、対応する防御の説明と一緒に並べるための補助。 */
export function attackDefenseLabel(result: AttackResult): string {
  return DEFENSE_INFO[result.defense].label;
}

/** 復号できたバイト列のプレビュー（UI 表示用）。 */
export function lootPreview(loot: string | undefined, max = 240): string {
  if (!loot) return "";
  const flat = loot.replace(/\r\n/g, " ⏎ ");
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}
