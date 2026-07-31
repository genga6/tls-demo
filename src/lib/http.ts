/**
 * HTTP。TLS ツリーの「HTTPS（HTTP を TLS で保護したもの）」層。
 *
 * HTTPS は独立したプロトコルではなく、「HTTP のバイト列をそのまま TLS の
 * レコード層に流し込んだもの」でしかない。ここで作る文字列が、そっくり
 * そのまま暗号化の対象になる。
 */

export interface HttpRequest {
  method: string;
  path: string;
  host: string;
  headers: Record<string, string>;
  body?: string;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
}

/**
 * デモで送るリクエスト。
 *
 * Cookie と Authorization をあえて載せてある。暗号化を切ったときに
 * 盗聴者の画面へ何が出てくるかを見るための素材。
 */
export function demoRequest(host: string): HttpRequest {
  return {
    method: "POST",
    path: "/api/transfer",
    host,
    headers: {
      Host: host,
      "Content-Type": "application/json",
      Cookie: "session=eyJ1aWQiOjQyfQ; theme=dark",
      Authorization: "Bearer sk_live_51H8xQ2eZvKYlo2C",
    },
    body: JSON.stringify({ to: "acct_9f2b", amount: 120000, currency: "JPY" }),
  };
}

export function demoResponse(): HttpResponse {
  return {
    status: 200,
    statusText: "OK",
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": "session=eyJ1aWQiOjQyfQ; Secure; HttpOnly; SameSite=Lax",
    },
    body: JSON.stringify({ ok: true, transferId: "tr_7c1d", balance: 384000 }),
  };
}

/** HTTP/1.1 のリクエストをそのままバイト列にできる文字列へ。 */
export function serializeRequest(request: HttpRequest): string {
  const lines = [`${request.method} ${request.path} HTTP/1.1`];
  for (const [name, value] of Object.entries(request.headers)) lines.push(`${name}: ${value}`);
  if (request.body !== undefined) {
    lines.push(`Content-Length: ${new TextEncoder().encode(request.body).length}`);
  }
  return `${lines.join("\r\n")}\r\n\r\n${request.body ?? ""}`;
}

/** HTTP/1.1 のレスポンスを文字列へ。 */
export function serializeResponse(response: HttpResponse): string {
  const lines = [`HTTP/1.1 ${response.status} ${response.statusText}`];
  for (const [name, value] of Object.entries(response.headers)) lines.push(`${name}: ${value}`);
  lines.push(`Content-Length: ${new TextEncoder().encode(response.body).length}`);
  return `${lines.join("\r\n")}\r\n\r\n${response.body}`;
}

/** リクエスト行だけを抜き出す（ログ表示用）。 */
export function requestLine(request: HttpRequest): string {
  return `${request.method} ${request.path} HTTP/1.1`;
}
