/**
 * @vitest-environment jsdom
 *
 * 盤面が描画され、操作が結果に繋がることの確認。
 *
 * 鍵生成 → ハンドシェイク → 全攻撃の実行までを実際に走らせるため、
 * ロジックとレンダリングを繋いだ状態での動作確認も兼ねている。
 */

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "../src/App";

// jsdom には Web Crypto が入っていないので、Node のものをそのまま使う。
if (!globalThis.crypto?.subtle) {
  const { webcrypto } = await import("node:crypto");
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}

const TIMEOUT = { timeout: 15_000 };

afterEach(() => {
  document.body.innerHTML = "";
});

/** 板を見出しから引く。同じ語はステータスバーにも出るので、見出しに限定して探す。 */
async function panel(name: string): Promise<HTMLElement> {
  const heading = await screen.findByRole("heading", { name }, TIMEOUT);
  const section = heading.closest("section");
  if (!section) throw new Error(`"${name}" の板が見つからない`);
  return section;
}

/** 守りのラックのスイッチを、TLS 側の名前で引く。 */
async function switchFor(label: string) {
  const rack = await panel("守り");
  return within(rack).getByRole("checkbox", { name: label });
}

/** 攻撃スロットを短い名前で引き、選ぶ。スロットは計算が終わってから現れる。 */
async function selectAttack(name: string) {
  const board = await panel("攻撃");
  const slot = await within(board).findByRole("button", { name: new RegExp(name) }, TIMEOUT);
  fireEvent.click(slot);
  return board;
}

/** 手順のつまみ（1..N の丸）を引く。同じ名前は経路の帯にも出るので、番号付きの名前で限定する。 */
function stepDot(stage: HTMLElement, title: string) {
  return within(stage).getByRole("button", { name: new RegExp(`^\\d+\\. ${title}$`) });
}

/** 盤面の再生を止める。以降の手動操作が自動再生に追い越されないように。 */
async function pause(stage: HTMLElement) {
  const button = within(stage).getByRole("button", { name: /一時停止|再生|もう一度/ });
  if (button.getAttribute("aria-label") === "一時停止") fireEvent.click(button);
}

describe("盤面の描画", () => {
  it("5 つの層を TLS の用語で示す", async () => {
    render(<App />);
    for (const label of ["Handshake", "Certificate", "Key Exchange", "Encryption", "HTTPS"]) {
      expect(await screen.findAllByText(new RegExp(label), undefined, TIMEOUT)).not.toHaveLength(0);
    }
  });

  it("鍵生成が終わると盤面・守り・攻撃がそろう", async () => {
    render(<App />);
    expect(await panel("ハンドシェイクの再生")).toBeDefined();
    expect(await panel("守り")).toBeDefined();
    expect(await panel("攻撃")).toBeDefined();
  });

  it("ステータスバーが接続と守りと突破を出す", async () => {
    render(<App />);
    expect(await screen.findByText("接続確立", undefined, TIMEOUT)).toBeDefined();
    expect(screen.getByText("7/7")).toBeDefined();
    expect(screen.getByText("0 / 8")).toBeDefined();
  });

  it("初期状態ではすべての攻撃が防がれる", async () => {
    render(<App />);
    const board = await panel("攻撃");
    await waitFor(() => expect(within(board).getAllByText("防げた")).toHaveLength(9), TIMEOUT);
    expect(within(board).queryByText("通った")).toBeNull();
  });

  it("守りは 7 つそろっていて、全部 ON で始まる", async () => {
    render(<App />);
    const rack = await panel("守り");
    expect(within(rack).getAllByRole("checkbox")).toHaveLength(7);
    for (const box of within(rack).getAllByRole("checkbox")) {
      expect((box as HTMLInputElement).checked).toBe(true);
    }
  });
});

describe("再生の操作", () => {
  it("1 手目から順に進み、12 手で終わる", async () => {
    render(<App />);
    const stage = await panel("ハンドシェイクの再生");
    await pause(stage);
    fireEvent.click(within(stage).getByRole("button", { name: "最初から" }));

    expect(within(stage).getByRole("heading", { name: "ClientHello" })).toBeDefined();
    // 最初の 1 通は平文。どのサイトに繋いだか (SNI) は暗号化しても隠れない。
    expect(within(stage).getAllByText(/SNI: bank\.example\.com/).length).toBeGreaterThan(0);

    fireEvent.click(within(stage).getByRole("button", { name: "次の手へ" }));
    expect(within(stage).getByRole("heading", { name: "ServerHello" })).toBeDefined();

    // つまみは 1 手につき 1 つ。正常フローは 12 手。
    expect(within(stage).getAllByRole("button", { name: /^\d+\. / })).toHaveLength(12);
  });

  it("つまみを押すと、その手に飛べる", async () => {
    render(<App />);
    const stage = await panel("ハンドシェイクの再生");
    await pause(stage);

    fireEvent.click(stepDot(stage, "HTTP リクエスト"));
    expect(within(stage).getByRole("heading", { name: "HTTP リクエスト" })).toBeDefined();
    // 暗号化が有効なら、この手でも盗聴者には読めない。
    expect(within(stage).getAllByText("読めない").length).toBeGreaterThan(0);
  });

  it("最後まで進むと接続確立の状態で終わる", async () => {
    render(<App />);
    const stage = await panel("ハンドシェイクの再生");
    await pause(stage);

    fireEvent.click(stepDot(stage, "HTTP レスポンス"));
    expect(within(stage).getByRole("heading", { name: "HTTP レスポンス" })).toBeDefined();
    expect(within(stage).queryByText(/接続中止/)).toBeNull();
  });
});

describe("守りを外す", () => {
  it("チェーン検証を外すと、偽 CA のなりすましが通る", async () => {
    render(<App />);
    const board = await panel("攻撃");
    await waitFor(() => expect(within(board).getAllByText("防げた")).toHaveLength(9), TIMEOUT);

    fireEvent.click(await switchFor("証明書チェーン検証"));

    // 通った攻撃は自動で選ばれ、攻撃者が手にした平文まで出る。
    await waitFor(() => expect(within(board).getAllByText("通った").length).toBe(2), TIMEOUT);
    expect(within(board).getByText(/Authorization: Bearer/)).toBeDefined();
  });

  it("外した守り 1 つにつき、通る攻撃も 1 つだけ", async () => {
    render(<App />);
    const board = await panel("攻撃");
    await waitFor(() => expect(within(board).getAllByText("防げた")).toHaveLength(9), TIMEOUT);

    fireEvent.click(await switchFor("証明書チェーン検証"));
    // スロット 8 枠のうち 1 枠 + 選択中の詳細欄で計 2 箇所。
    await waitFor(() => expect(within(board).getAllByText("通った")).toHaveLength(2), TIMEOUT);
    expect(within(board).getAllByText("防げた")).toHaveLength(7);
  });

  it("有効期限の確認を外すと、期限切れと失効の 2 件が通る", async () => {
    render(<App />);
    const board = await panel("攻撃");
    await waitFor(() => expect(within(board).getAllByText("防げた")).toHaveLength(9), TIMEOUT);

    fireEvent.click(await switchFor("有効期限・失効確認"));
    await waitFor(() => expect(within(board).getAllByText("通った")).toHaveLength(3), TIMEOUT);
  });

  it("レコード暗号化を外すと、盗聴者に HTTP がそのまま見える", async () => {
    render(<App />);
    const stage = await panel("ハンドシェイクの再生");
    await pause(stage);

    fireEvent.click(await switchFor("レコード層の暗号化（AEAD）"));

    await waitFor(() => {
      fireEvent.click(stepDot(stage, "HTTP リクエスト"));
      expect(within(stage).getAllByText(/Authorization: Bearer/).length).toBeGreaterThan(0);
    }, TIMEOUT);
  });

  it("Finished 照合を外すと、ダウングレードが通って手順に改ざんが現れる", async () => {
    render(<App />);
    const stage = await panel("ハンドシェイクの再生");
    const board = await panel("攻撃");

    fireEvent.click(await switchFor("Finished / transcript hash 照合"));

    await waitFor(() => expect(within(board).getAllByText("通った").length).toBe(2), TIMEOUT);
    // 正常フロー側は改ざんされていないので、そのまま繋がる。
    expect(stepDot(stage, "HTTP レスポンス")).toBeDefined();
  });
});

describe("攻撃スロットから守りを操作する", () => {
  it("スロットを選ぶと、その攻撃の説明が出る", async () => {
    render(<App />);
    const board = await selectAttack("のぞき見");
    expect(within(board).getAllByText(/パケットを眺めるだけ/).length).toBeGreaterThan(0);
  });

  it("詳細欄から守りを外し、そのまま戻せる", async () => {
    render(<App />);
    const board = await selectAttack("のぞき見");

    fireEvent.click(within(board).getByRole("button", { name: "この守りを外して試す" }));
    await waitFor(() => expect(within(board).getAllByText("通った").length).toBe(2), TIMEOUT);

    fireEvent.click(within(board).getByRole("button", { name: "守りを戻す" }));
    await waitFor(() => expect(within(board).getAllByText("防げた")).toHaveLength(9), TIMEOUT);
  });

  it("全部 ON に戻すボタンで初期状態に復帰する", async () => {
    render(<App />);
    const board = await panel("攻撃");
    await waitFor(() => expect(within(board).getAllByText("防げた")).toHaveLength(9), TIMEOUT);

    fireEvent.click(await switchFor("証明書チェーン検証"));
    await waitFor(() => expect(within(board).getAllByText("通った").length).toBe(2), TIMEOUT);

    fireEvent.click(screen.getByRole("button", { name: "全部 ON に戻す" }));
    await waitFor(() => expect(within(board).getAllByText("防げた")).toHaveLength(9), TIMEOUT);
  });
});

describe("守りを外すと手順そのものが変わる", () => {
  it("CertificateVerify を外すと、その手が『省略』になる", async () => {
    render(<App />);
    const stage = await panel("ハンドシェイクの再生");

    fireEvent.click(await switchFor("CertificateVerify 署名"));
    await pause(stage);

    await waitFor(() => {
      fireEvent.click(stepDot(stage, "CertificateVerify"));
      expect(within(stage).getByText("省略")).toBeDefined();
    }, TIMEOUT);
    expect(within(stage).getByText(/拾ってきて提示しただけの相手でも通る/)).toBeDefined();
  });
});
