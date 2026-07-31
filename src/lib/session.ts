/**
 * TLS セッション 1 回分の実行。ツリーの 5 層をこの順で通る。
 *
 *   Handshake → Certificate → Key Exchange → Encryption → HTTPS
 *
 * クライアントとサーバーを同じプロセス内の 2 つの状態として動かし、
 * それぞれが「自分が実際に送受信したもの」だけを見て計算する。
 * 中間者が途中で書き換えれば両者の transcript は自然に食い違い、
 * 特別な細工なしに TLS の防御が発動する。
 */

import {
  type Bytes,
  base64,
  fromBase64,
  fromHex,
  fromUtf8,
  hex,
  hexPreview,
  timingSafeEqual,
  utf8,
} from "./bytes";
import {
  type EcdhKeyPair,
  ecdhSharedSecret,
  generateEcdhKeyPair,
  importVerifyKey,
  sign,
  verify,
} from "./crypto";
import { demoRequest, demoResponse, serializeRequest, serializeResponse } from "./http";
import {
  type HandshakeSecrets,
  computeApplicationSecrets,
  computeEarlySecret,
  computeHandshakeSecret,
  computeHandshakeSecrets,
  computeMasterSecret,
  describeSecrets,
  finishedVerifyData,
} from "./key-schedule";
import {
  type ClientHello,
  type ServerHello,
  Transcript,
  certificateVerifyContent,
} from "./messages";
import { type Certificate, verifyCertificateChain } from "./pki";
import { randomBytes } from "./random";
import { RecordLayer, type TlsRecord } from "./record";
import { type TlsServer, isWeakSuite, offeredCipherSuites, selectCipherSuite } from "./server";
import type { Defenses, FlowStep } from "./types";

// ---------------------------------------------------------------------------
// 入出力の型
// ---------------------------------------------------------------------------

/** 盗聴者（経路上の第三者）に見えたもの 1 件。 */
export interface WiretapEntry {
  label: string;
  /** 実際に目に映る中身。 */
  visible: string;
  /** 中身が読めてしまっているか。 */
  readable: boolean;
  note: string;
}

export interface RecordedRecord {
  direction: "client→server" | "server→client";
  label: string;
  record: TlsRecord;
}

/** 遡及復号の検証に必要な、セッションの生データ。 */
export interface SessionTrace {
  /** 平文の ClientHello に載っていたクライアントの公開鍵。誰にでも見えている。 */
  clientKeyShareRaw: Bytes;
  serverKeyShareRaw: Bytes;
  /** サーバーが使い捨て鍵を使ったか（false なら長期鍵の漏洩で全滅する）。 */
  serverUsedEphemeralKey: boolean;
  /**
   * ClientHello..ServerHello の transcript hash。
   * どちらも平文で流れるので、盗聴者も自分で計算できる値。
   */
  helloTranscriptHash: Bytes;
  /**
   * ClientHello..server Finished の transcript hash（アプリ鍵の導出に必要）。
   * 暗号化されたメッセージを含むが、共有秘密を手に入れた攻撃者は
   * ハンドシェイクレコードを復号して自力で再構成できる。
   */
  applicationTranscriptHash: Bytes;
  records: RecordedRecord[];
}

export interface SessionScenario {
  defenses: Defenses;
  /** クライアントが繋ぎたいホスト名。 */
  hostname: string;
  server: TlsServer;
  trustedRoots: Certificate[];
  revokedSerials?: Set<string>;
  now?: Date;
  /**
   * 中間者による ClientHello の書き換え。
   * サーバーは書き換え後を受け取り、クライアントは自分が送った original を覚えている。
   */
  tamperClientHello?: (hello: ClientHello) => ClientHello;
}

export interface SessionResult {
  steps: FlowStep[];
  established: boolean;
  abortReason?: string;
  /** 最終的に使われた暗号スイート。 */
  cipherSuite: string;
  /** ダウングレードされて弱いスイートになったか。 */
  downgraded: boolean;
  keyExchange: string;
  secrets: Record<string, string>;
  wiretap: WiretapEntry[];
  trace?: SessionTrace;
  httpRequest?: string;
  httpResponse?: string;
}

// ---------------------------------------------------------------------------
// ステップ記録
// ---------------------------------------------------------------------------

class StepLog {
  private readonly steps: FlowStep[] = [];

  add(step: Omit<FlowStep, "index">): void {
    this.steps.push({ ...step, index: this.steps.length + 1 });
  }

  all(): FlowStep[] {
    return this.steps;
  }
}

// ---------------------------------------------------------------------------
// セッション実行
// ---------------------------------------------------------------------------

export async function runSession(scenario: SessionScenario): Promise<SessionResult> {
  const { defenses, hostname, server, trustedRoots } = scenario;
  const now = scenario.now ?? new Date();
  const encrypt = defenses.recordEncryption;
  const log = new StepLog();
  const wiretap: WiretapEntry[] = [];
  const records: RecordedRecord[] = [];

  // =========================================================================
  // Handshake — ClientHello
  // =========================================================================

  const clientEcdh = await generateEcdhKeyPair();
  const sentClientHello: ClientHello = {
    type: "ClientHello",
    legacyVersion: "TLS 1.2",
    random: hex(randomBytes(32)),
    serverName: hostname,
    supportedVersions: ["TLS 1.3"],
    cipherSuites: offeredCipherSuites(),
    supportedGroups: ["x25519", "secp256r1"],
    keyShare: { group: "secp256r1", publicKey: hex(clientEcdh.publicKeyRaw) },
  };

  // 中間者が経路上で書き換える場合、サーバーが受け取るのはこちら。
  const receivedClientHello = scenario.tamperClientHello
    ? scenario.tamperClientHello(sentClientHello)
    : sentClientHello;
  const helloTampered = receivedClientHello !== sentClientHello;

  log.add({
    phase: "handshake",
    from: "client",
    to: "server",
    protection: "plaintext",
    title: "① ClientHello",
    detail:
      "対応する TLS バージョン・暗号スイート・鍵交換グループを提示し、同時に ECDHE の公開鍵 (key_share) まで送ってしまう。" +
      "TLS 1.3 が 1 往復でハンドシェイクを終えられるのは、最初の一言に鍵共有を相乗りさせているから。",
    status: "ok",
    data: {
      "接続先 (SNI)": sentClientHello.serverName,
      random: `${sentClientHello.random.slice(0, 32)}…`,
      提示した暗号スイート: sentClientHello.cipherSuites.join(", "),
      "key_share (公開鍵)": hexPreview(clientEcdh.publicKeyRaw),
    },
  });

  wiretap.push({
    label: "ClientHello",
    visible: `SNI: ${sentClientHello.serverName} / suites: ${sentClientHello.cipherSuites.join(", ")}`,
    readable: true,
    note: "ハンドシェイクの最初は必ず平文。どのサイトに繋いだか (SNI) は TLS でも隠れない。",
  });

  if (helloTampered) {
    log.add({
      phase: "handshake",
      from: "attacker",
      to: "server",
      protection: "plaintext",
      title: "⚠ 中間者が ClientHello を書き換え",
      detail:
        "平文で流れる ClientHello から強い暗号スイートを削り、弱いものだけを残してサーバーへ転送する。" +
        "サーバーは「クライアントはこれしか対応していない」と信じて弱いスイートを選ぶ。",
      status: "danger",
      data: {
        書き換え前: sentClientHello.cipherSuites.join(", "),
        書き換え後: receivedClientHello.cipherSuites.join(", "),
      },
    });
  }

  // =========================================================================
  // Handshake — ServerHello
  // =========================================================================

  const selectedSuite = selectCipherSuite(receivedClientHello.cipherSuites);
  const downgraded = isWeakSuite(selectedSuite);

  // 前方秘匿性 ON なら接続ごとの使い捨て鍵、OFF なら長期の静的鍵を使う。
  const serverEcdh: EcdhKeyPair = defenses.forwardSecrecy
    ? await generateEcdhKeyPair()
    : server.staticEcdh;

  const serverHello: ServerHello = {
    type: "ServerHello",
    legacyVersion: "TLS 1.2",
    random: hex(randomBytes(32)),
    selectedVersion: "TLS 1.3",
    cipherSuite: selectedSuite,
    keyShare: { group: "secp256r1", publicKey: hex(serverEcdh.publicKeyRaw) },
  };

  const abort = (reason: string): SessionResult => ({
    steps: log.all(),
    established: false,
    abortReason: reason,
    cipherSuite: selectedSuite,
    downgraded,
    keyExchange: keyExchangeLabel(defenses.forwardSecrecy),
    secrets: {},
    wiretap,
  });

  log.add({
    phase: "handshake",
    from: "server",
    to: "client",
    protection: "plaintext",
    title: "② ServerHello",
    detail:
      "サーバーが暗号スイートを 1 つ選び、自分の key_share を返す。ここまでが平文で、" +
      "この 2 通のやり取りだけで両者は共通鍵を計算する材料を揃える。",
    status: "ok",
    data: {
      選ばれた暗号スイート: selectedSuite,
      鍵交換: keyExchangeLabel(defenses.forwardSecrecy),
      "key_share (公開鍵)": hexPreview(serverEcdh.publicKeyRaw),
    },
  });

  wiretap.push({
    label: "ServerHello",
    visible: `cipher: ${selectedSuite} / key_share: ${hexPreview(serverEcdh.publicKeyRaw, 8)}`,
    readable: true,
    note: "公開鍵は見えてよい。見えても共有秘密は計算できない、というのが公開鍵暗号の前提。",
  });

  // --- transcript の分岐 --------------------------------------------------
  // クライアントは「自分が送った」ClientHello を、サーバーは「自分が受け取った」
  // ClientHello を transcript に積む。中間者が書き換えていれば両者の記録が
  // 食い違い、以降のすべての鍵が別物になる。
  //
  // finishedVerify を OFF にした状態は「ハンドシェイク全文を鍵と MAC に縛らない」
  // 古い設計の模擬。クライアントは自分が何を送ったかを覚えておらず、
  // 経路上で書き換えられた内容をそのまま自分の記録として受け入れてしまう。
  const clientTranscript = new Transcript();
  clientTranscript.append(defenses.finishedVerify ? sentClientHello : receivedClientHello);
  clientTranscript.append(serverHello);

  const serverTranscript = new Transcript();
  serverTranscript.append(receivedClientHello);
  serverTranscript.append(serverHello);

  // =========================================================================
  // Key Exchange
  // =========================================================================

  const clientShared = await ecdhSharedSecret(clientEcdh.privateKey, serverEcdh.publicKeyRaw);
  const serverShared = await ecdhSharedSecret(
    serverEcdh.privateKey,
    fromHex(receivedClientHello.keyShare.publicKey),
  );

  const ephemeralNote = defenses.forwardSecrecy
    ? "使い捨て鍵なので、接続が終われば秘密鍵は捨てられ、後から誰にも再現できない。"
    : "長期鍵を使い回しているため、その鍵が将来漏れれば同じ計算を誰でも再現できてしまう。";

  log.add({
    phase: "key-exchange",
    from: "client",
    to: "client",
    protection: "internal",
    title: "③ ECDHE で共有秘密を計算",
    detail: [
      "自分の秘密鍵 a と相手の公開点 B から aB を求める。サーバーも bA を求め、aB = bA = abG で同じ値に辿り着く。",
      "経路上には A と B しか流れておらず、そこから abG を求めるのは離散対数問題そのもので現実的に解けない。",
      ephemeralNote,
    ].join(""),
    status: defenses.forwardSecrecy ? "ok" : "danger",
    data: {
      "共有秘密 (client 側)": hexPreview(clientShared),
      "共有秘密 (server 側)": hexPreview(serverShared),
      一致: timingSafeEqual(clientShared, serverShared) ? "はい" : "いいえ",
    },
  });

  const clientHelloHash = await clientTranscript.hash();
  const serverHelloHash = await serverTranscript.hash();
  const clientHs = await deriveHandshake(clientShared, clientHelloHash);
  const serverHs = await deriveHandshake(serverShared, serverHelloHash);

  log.add({
    phase: "key-exchange",
    from: "client",
    to: "client",
    protection: "internal",
    title: "④ 鍵スケジュール (HKDF)",
    detail:
      "共有秘密をそのまま鍵にはしない。Early Secret → Handshake Secret → Master Secret と段を踏み、" +
      "各段で「ここまでのハンドシェイク全文のハッシュ」を混ぜ込む。用途ごとにラベルが違うので、" +
      "ある鍵が漏れても他の鍵は導出できない。",
    status: "ok",
    data: {
      "transcript hash (CH..SH)": hexPreview(clientHelloHash),
      "Handshake Secret": hexPreview(clientHs.handshakeSecret),
      "client handshake traffic": hexPreview(clientHs.clientSecret),
      "server handshake traffic": hexPreview(clientHs.serverSecret),
    },
  });

  if (!timingSafeEqual(clientHelloHash, serverHelloHash)) {
    log.add({
      phase: "handshake",
      from: "client",
      to: "client",
      protection: "internal",
      title: "⑤ transcript hash の食い違い",
      detail:
        "クライアントが「自分が送った ClientHello」から計算したハッシュと、サーバーが「受け取った ClientHello」から" +
        "計算したハッシュが一致しない。両者の鍵はこの時点で別物になり、以降のレコードは復号できず、" +
        "Finished の照合も必ず失敗する。これがダウングレード攻撃を潰す仕組み。",
      status: "ok",
      data: {
        クライアントのハッシュ: hexPreview(clientHelloHash),
        サーバーのハッシュ: hexPreview(serverHelloHash),
      },
    });
  }

  const serverHsOut = new RecordLayer(serverHs.server, encrypt);
  const clientHsIn = new RecordLayer(clientHs.server, encrypt);

  // =========================================================================
  // Certificate
  // =========================================================================

  const encryptedExtensions = { type: "EncryptedExtensions", alpn: "http/1.1" } as const;
  const certificateMessage = { type: "Certificate", chain: server.certificateChain } as const;

  serverTranscript.append(encryptedExtensions);
  serverTranscript.append(certificateMessage);

  // CertificateVerify は「Certificate まで」の transcript に署名する。
  const serverCertVerifyHash = await serverTranscript.hash();
  const certificateVerifyMessage = {
    type: "CertificateVerify",
    algorithm: "ecdsa_secp256r1_sha256",
    signature: base64(
      await sign(server.signingKey, certificateVerifyContent(serverCertVerifyHash)),
    ),
  } as const;
  serverTranscript.append(certificateVerifyMessage);

  // サーバーの第 1 フライトをまとめて 1 レコードで送る。
  const serverFlight = utf8(
    JSON.stringify([encryptedExtensions, certificateMessage, certificateVerifyMessage]),
  );
  const flightRecord = await serverHsOut.protect("handshake", serverFlight);
  records.push({
    direction: "server→client",
    label: "EncryptedExtensions / Certificate / CertificateVerify",
    record: flightRecord,
  });
  wiretap.push({
    label: "サーバーの証明書フライト",
    visible: encrypt
      ? hexPreview(flightRecord.payload, 24)
      : `${fromUtf8(flightRecord.payload).slice(0, 160)}…`,
    readable: !encrypt,
    note: encrypt
      ? "TLS 1.3 では証明書も暗号化される。誰に繋いだかが経路上から見えにくくなる。"
      : "暗号化 OFF。証明書の中身がそのまま見えている（TLS 1.2 まではこれが通常だった）。",
  });

  const opened = await clientHsIn.open(flightRecord);
  if (!opened.ok) {
    log.add({
      phase: "handshake",
      from: "server",
      to: "client",
      protection: "handshake-encrypted",
      title: "⑤ サーバーの証明書フライトを復号できない",
      detail: `${opened.reason}。ハンドシェイクの内容が経路上で書き換えられたため、両者の鍵が食い違っている。`,
      status: "failed",
    });
    return abort("transcript hash の不一致によりハンドシェイク鍵が一致しない（改ざん検出）");
  }

  clientTranscript.append(encryptedExtensions);
  clientTranscript.append(certificateMessage);

  const leaf = server.certificateChain[0];
  log.add({
    phase: "certificate",
    from: "server",
    to: "client",
    protection: encrypt ? "handshake-encrypted" : "plaintext",
    title: "⑥ Certificate — サーバー証明書の提示",
    detail:
      "サーバーが自分の証明書と中間 CA の証明書を送る。ルート CA の証明書は送らない。" +
      "クライアントが自分の信頼ストアに持っているはずのものだから。",
    status: "ok",
    data: {
      subject: leaf.body.subject,
      SAN: leaf.body.subjectAltNames.join(", ") || "（なし）",
      issuer: leaf.body.issuer,
      有効期間: `${leaf.body.notBefore.slice(0, 10)} 〜 ${leaf.body.notAfter.slice(0, 10)}`,
      チェーン: server.certificateChain.map((c) => c.body.subject).join(" ← "),
    },
  });

  const chainResult = await verifyCertificateChain(server.certificateChain, {
    trustedRoots,
    hostname,
    now,
    revokedSerials: scenario.revokedSerials,
    enable: {
      chain: defenses.certificateChain,
      hostname: defenses.hostnameCheck,
      validity: defenses.validityCheck,
    },
  });

  log.add({
    phase: "certificate",
    from: "client",
    to: "client",
    protection: "internal",
    title: "⑦ 証明書の検証",
    detail:
      "「鍵交換が成立した」ことは「相手が本物」を意味しない。中間者とも問題なく鍵交換はできてしまう。" +
      "相手が意図した相手かどうかは、信頼ストアのルート CA まで署名を辿れるか、という外部の根拠に頼るしかない。",
    status: chainResult.ok ? "ok" : "failed",
    data: Object.fromEntries(
      chainResult.checks.map((c) => [`${statusMark(c.status)} ${c.name}`, c.detail]),
    ),
  });

  if (!chainResult.ok) return abort(chainResult.reason ?? "証明書の検証に失敗");

  // --- CertificateVerify -------------------------------------------------
  const clientCertVerifyHash = await clientTranscript.hash();
  clientTranscript.append(certificateVerifyMessage);

  if (defenses.certificateVerify) {
    const leafKey = await importVerifyKey(leaf.body.publicKeyJwk);
    const signatureValid = await verify(
      leafKey,
      fromBase64(certificateVerifyMessage.signature),
      certificateVerifyContent(clientCertVerifyHash),
    );

    log.add({
      phase: "certificate",
      from: "client",
      to: "client",
      protection: "internal",
      title: "⑧ CertificateVerify — 秘密鍵の所持証明",
      detail:
        "証明書は公開情報なので、コピーして提示するだけなら誰にでもできる。そこでサーバーはここまでの" +
        "ハンドシェイク全文に、証明書の公開鍵と対になる秘密鍵で署名する。この署名を検証できて初めて" +
        "「証明書の持ち主本人」だと分かる。",
      status: signatureValid ? "ok" : "failed",
      data: {
        署名対象: '0x20×64 || "TLS 1.3, server CertificateVerify" || 0x00 || transcript hash',
        "transcript hash": hexPreview(clientCertVerifyHash),
        検証結果: signatureValid
          ? "証明書の公開鍵で署名を検証できた"
          : "証明書の公開鍵では署名を検証できない（対応する秘密鍵を持っていない）",
      },
    });

    if (!signatureValid) return abort("CertificateVerify の署名が証明書の公開鍵と一致しない");
  } else {
    log.add({
      phase: "certificate",
      from: "client",
      to: "client",
      protection: "internal",
      title: "⑧ CertificateVerify — 検証を省略",
      detail:
        "署名を確かめないので、証明書をどこかから拾ってきて提示しただけの相手でも通ってしまう。",
      status: "skipped",
    });
  }

  // =========================================================================
  // Handshake — Finished
  // =========================================================================

  // server Finished は「CertificateVerify まで」の transcript に対する MAC。
  const preFinishedHashServer = await serverTranscript.hash();
  const finishedMessage = {
    type: "Finished",
    verifyData: hex(await finishedVerifyData(serverHs.serverSecret, preFinishedHashServer)),
  } as const;
  serverTranscript.append(finishedMessage);

  const finishedRecord = await serverHsOut.protect(
    "handshake",
    utf8(JSON.stringify(finishedMessage)),
  );
  records.push({ direction: "server→client", label: "Finished", record: finishedRecord });

  const finishedOpened = await clientHsIn.open(finishedRecord);
  if (!finishedOpened.ok) {
    log.add({
      phase: "handshake",
      from: "server",
      to: "client",
      protection: "handshake-encrypted",
      title: "⑨ Finished を復号できない",
      detail: finishedOpened.reason,
      status: "failed",
    });
    return abort("Finished レコードの復号に失敗");
  }

  const preFinishedHashClient = await clientTranscript.hash();
  const expectedVerifyData = await finishedVerifyData(clientHs.serverSecret, preFinishedHashClient);
  const finishedMatches = timingSafeEqual(fromHex(finishedMessage.verifyData), expectedVerifyData);

  if (defenses.finishedVerify) {
    log.add({
      phase: "handshake",
      from: "server",
      to: "client",
      protection: "handshake-encrypted",
      title: "⑨ Finished — ハンドシェイク全文の照合",
      detail:
        "ここまでに交換した全メッセージのハッシュに、ハンドシェイク鍵から作った MAC を付けて送る。" +
        "「鍵交換に成功した」ことと「見たやり取りの中身が同一である」ことを 1 通で同時に証明する。" +
        "途中で 1 バイトでも書き換えられていれば、この値は一致しない。",
      status: finishedMatches ? "ok" : "failed",
      data: {
        "受信した verify_data": hexPreview(fromHex(finishedMessage.verifyData)),
        "期待した verify_data": hexPreview(expectedVerifyData),
      },
    });

    if (!finishedMatches) {
      return abort("Finished の verify_data が一致しない（ハンドシェイク改ざんを検出）");
    }
  } else {
    log.add({
      phase: "handshake",
      from: "server",
      to: "client",
      protection: "handshake-encrypted",
      title: "⑨ Finished — 照合を省略",
      detail:
        "ハンドシェイク全文を突き合わせないので、経路上で ClientHello の暗号スイート一覧を削られていても気づけない。" +
        "弱いスイートに落とされたまま通信が始まる。",
      status: "skipped",
    });
  }

  clientTranscript.append(finishedMessage);

  // =========================================================================
  // Encryption — アプリケーション鍵に切り替え
  // =========================================================================

  // アプリ用の鍵は「server Finished まで」の transcript から導く。
  const appHashClient = await clientTranscript.hash();
  const appHashServer = await serverTranscript.hash();

  const clientVerifyData = await finishedVerifyData(clientHs.clientSecret, appHashClient);
  log.add({
    phase: "handshake",
    from: "client",
    to: "server",
    protection: "handshake-encrypted",
    title: "⑩ クライアント Finished",
    detail: "同じ照合を逆方向にも行い、双方向で改ざんがないことを確認してハンドシェイクを終える。",
    status: "ok",
    data: { verify_data: hexPreview(clientVerifyData) },
  });

  const clientApp = await computeApplicationSecrets(
    await computeMasterSecret(clientHs.handshakeSecret),
    appHashClient,
  );
  const serverApp = await computeApplicationSecrets(
    await computeMasterSecret(serverHs.handshakeSecret),
    appHashServer,
  );

  log.add({
    phase: "encryption",
    from: "client",
    to: "client",
    protection: "internal",
    title: "⑪ アプリケーション鍵への切り替え",
    detail:
      "Master Secret から、ハンドシェイクとは別のアプリ用 traffic secret を導出し、そこから AEAD 鍵と IV を作る。" +
      "方向ごとに別の鍵を使い、レコード連番を nonce に混ぜるので、同じ nonce が二度使われることが構造的に起こらない。",
    status: encrypt ? "ok" : "danger",
    data: encrypt
      ? {
          "Master Secret": hexPreview(clientApp.masterSecret),
          "AEAD 鍵 (client→server)": hexPreview(clientApp.client.keyBytes),
          "AEAD 鍵 (server→client)": hexPreview(clientApp.server.keyBytes),
          "IV (client→server)": hexPreview(clientApp.client.iv),
          暗号スイート: selectedSuite,
        }
      : { 状態: "レコード暗号化が OFF。鍵は導出したが使わない。" },
  });

  // =========================================================================
  // HTTPS
  // =========================================================================

  const clientAppOut = new RecordLayer(clientApp.client, encrypt);
  const serverAppIn = new RecordLayer(serverApp.client, encrypt);
  const serverAppOut = new RecordLayer(serverApp.server, encrypt);
  const clientAppIn = new RecordLayer(clientApp.server, encrypt);

  const request = demoRequest(hostname);
  const requestText = serializeRequest(request);
  const requestRecord = await clientAppOut.protect("application_data", utf8(requestText));
  records.push({ direction: "client→server", label: "HTTP リクエスト", record: requestRecord });

  log.add({
    phase: "https",
    from: "client",
    to: "server",
    protection: encrypt ? "application-encrypted" : "plaintext",
    title: "⑫ HTTP リクエストを送る",
    detail: `HTTPS は独立したプロトコルではない。普通の HTTP のバイト列を、そのままレコード層に流し込むだけ。${
      encrypt
        ? "経路に出ていくのは、その平文を AEAD で封じた暗号文になる。"
        : "暗号化が OFF なので、この平文がそのまま経路に出ていく。"
    }`,
    status: encrypt ? "ok" : "danger",
    data: {
      "平文 (アプリが書いたもの)": requestText.replace(/\r\n/g, " ⏎ "),
      経路に出るもの: encrypt
        ? `${hex(requestRecord.header)} | ${hexPreview(requestRecord.payload, 28)}`
        : "（同じものが平文のまま）",
    },
  });

  wiretap.push({
    label: "HTTP リクエスト",
    visible: encrypt ? hexPreview(requestRecord.payload, 32) : requestText.replace(/\r\n/g, " ⏎ "),
    readable: !encrypt,
    note: encrypt
      ? "Cookie も Authorization も暗号文の中。漏れるのは長さと送信タイミングだけ。"
      : "Cookie と Authorization がそのまま読める。セッション乗っ取りに直結する。",
  });

  const receivedRequest = await serverAppIn.open(requestRecord);
  if (!receivedRequest.ok)
    return abort(`サーバーがリクエストを復号できない: ${receivedRequest.reason}`);

  const responseText = serializeResponse(demoResponse());
  const responseRecord = await serverAppOut.protect("application_data", utf8(responseText));
  records.push({ direction: "server→client", label: "HTTP レスポンス", record: responseRecord });

  const receivedResponse = await clientAppIn.open(responseRecord);
  if (!receivedResponse.ok) {
    return abort(`クライアントがレスポンスを復号できない: ${receivedResponse.reason}`);
  }

  log.add({
    phase: "https",
    from: "server",
    to: "client",
    protection: encrypt ? "application-encrypted" : "plaintext",
    title: "⑬ HTTP レスポンスを受け取る",
    detail:
      "レスポンスも同じレコード層を通る。復号と同時に認証タグを検証しているので、" +
      "1 ビットでも改ざんされていれば復号自体が失敗し、内容が使われることはない。",
    status: "ok",
    data: {
      復号後の平文: fromUtf8(receivedResponse.plaintext).replace(/\r\n/g, " ⏎ "),
      認証タグ: encrypt ? "検証済み（改ざんなし）" : "なし（改ざんを検知できない）",
    },
  });

  wiretap.push({
    label: "HTTP レスポンス",
    visible: encrypt
      ? hexPreview(responseRecord.payload, 32)
      : responseText.replace(/\r\n/g, " ⏎ "),
    readable: !encrypt,
    note: encrypt
      ? "Set-Cookie も暗号文の中。"
      : "Set-Cookie が読める。セッション ID をそのまま盗める。",
  });

  return {
    steps: log.all(),
    established: true,
    cipherSuite: selectedSuite,
    downgraded,
    keyExchange: keyExchangeLabel(defenses.forwardSecrecy),
    secrets: describeSecrets(clientHs, clientApp, clientShared),
    wiretap,
    trace: {
      clientKeyShareRaw: clientEcdh.publicKeyRaw,
      serverKeyShareRaw: serverEcdh.publicKeyRaw,
      serverUsedEphemeralKey: defenses.forwardSecrecy,
      helloTranscriptHash: clientHelloHash,
      applicationTranscriptHash: appHashClient,
      records,
    },
    httpRequest: requestText,
    httpResponse: fromUtf8(receivedResponse.plaintext),
  };
}

// ---------------------------------------------------------------------------
// 補助
// ---------------------------------------------------------------------------

async function deriveHandshake(
  sharedSecret: Bytes,
  transcriptHash: Bytes,
): Promise<HandshakeSecrets> {
  const early = await computeEarlySecret();
  const handshakeSecret = await computeHandshakeSecret(early, sharedSecret);
  return computeHandshakeSecrets(handshakeSecret, transcriptHash);
}

function keyExchangeLabel(forwardSecrecy: boolean): string {
  return forwardSecrecy
    ? "ECDHE (secp256r1) — 接続ごとの使い捨て鍵"
    : "静的 ECDH (secp256r1) — サーバーの長期鍵を再利用";
}

function statusMark(status: "pass" | "fail" | "skipped"): string {
  return status === "pass" ? "✓" : status === "fail" ? "✗" : "—";
}
